package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static templates licenses
var assets embed.FS

var version = "development"

const retentionDays = 90

var articlePath = regexp.MustCompile(`^/articles/[a-z0-9]+(?:-[a-z0-9]+)*/$`)

type config struct {
	addr          string
	origin        string
	articleOrigin string
	dbPath        string
	clientID      string
	clientSecret  string
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func readConfig() (config, error) {
	cfg := config{
		addr:          env("METRIC_ADDR", "127.0.0.1:9841"),
		origin:        env("METRIC_ORIGIN", "http://127.0.0.1:9841"),
		articleOrigin: env("METRIC_ARTICLE_ORIGIN", "https://sec4.si"),
		dbPath:        env("METRIC_DATABASE", "data/metric.sqlite"),
		clientID:      os.Getenv("METRIC_GITHUB_CLIENT_ID"),
		clientSecret:  os.Getenv("METRIC_GITHUB_CLIENT_SECRET"),
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && cfg.clientSecret == "" {
		secret, err := os.ReadFile(filepath.Join(dir, "github-oauth"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return cfg, errors.New("could not read the OAuth credential")
		}
		cfg.clientSecret = strings.TrimSpace(string(secret))
	}
	for _, origin := range []string{cfg.origin, cfg.articleOrigin} {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || origin != u.Scheme+"://"+u.Host ||
			(u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "127.0.0.1")) {
			return cfg, errors.New("origins must be HTTPS URLs or loopback HTTP URLs, without a path")
		}
	}
	if (cfg.clientID == "") != (cfg.clientSecret == "") {
		return cfg, errors.New("the GitHub client ID and secret must be configured together")
	}
	return cfg, nil
}

type app struct {
	cfg       config
	store     *store
	github    githubClient
	templates *template.Template
	auth      authMemory
	rate      rateWindow
}

func newApp(cfg config, db *store, github githubClient) *app {
	return &app{
		cfg: cfg, store: db, github: github,
		templates: template.Must(template.ParseFS(assets, "templates/*.html")),
		auth:      authMemory{flows: make(map[string]oauthFlow), sessions: make(map[string]session)},
	}
}

func (a *app) handler() http.Handler {
	mux := http.NewServeMux()
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /privacy", a.privacy)
	mux.HandleFunc("GET /oauth/start", a.startOAuth)
	mux.HandleFunc("GET /oauth/callback", a.callback)
	mux.HandleFunc("GET /dashboard", a.dashboard)
	mux.HandleFunc("GET /access", a.access)
	mux.HandleFunc("POST /access", a.changeAccess)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /read", a.read)
	mux.HandleFunc("POST /read", a.record)
	mux.HandleFunc("OPTIONS /api/views", a.ingest)
	mux.HandleFunc("POST /api/views", a.ingest)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})
}

func (a *app) health(w http.ResponseWriter, r *http.Request) {
	if err := a.store.db.PingContext(r.Context()); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok", "version": version, "oauth_ready": a.cfg.clientID != "",
	})
}

func validArticle(path string) bool {
	return len(path) <= 160 && articlePath.MatchString(path)
}

func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if realIP := net.ParseIP(r.Header.Get("X-Real-IP")); realIP != nil {
			return realIP.String()
		}
	}
	return host
}

// A short, bounded in-memory counter protects inbound endpoints. Addresses never enter storage.
type rateWindow struct {
	mu     sync.Mutex
	minute int64
	counts map[string]int
}

func (limit *rateWindow) allow(key string, maximum int) bool {
	limit.mu.Lock()
	defer limit.mu.Unlock()
	minute := time.Now().Unix() / 60
	if limit.counts == nil || limit.minute != minute {
		limit.minute = minute
		limit.counts = make(map[string]int)
	}
	count := limit.counts[key]
	if count >= maximum || (count == 0 && len(limit.counts) >= 12000) {
		return false
	}
	limit.counts[key] = count + 1
	return true
}

func (a *app) ingest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Origin")
	if r.Header.Get("Origin") != a.cfg.articleOrigin {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", a.cfg.articleOrigin)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Header.Get("Sec-GPC") == "1" || r.Header.Get("DNT") == "1" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !a.rate.allow("view:"+clientIP(r), 90) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType != "application/json" {
		http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
		return
	}
	var input struct {
		Path string `json:"path"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil || !validArticle(input.Path) {
		http.Error(w, "invalid article path", http.StatusBadRequest)
		return
	}
	if d.Decode(new(any)) != io.EOF {
		http.Error(w, "expected one JSON object", http.StatusBadRequest)
		return
	}
	if err := a.store.countView(r.Context(), input.Path, day(time.Now())); err != nil {
		http.Error(w, "statistics unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func run() error {
	cfg, err := readConfig()
	if err != nil {
		return err
	}
	db, err := openStore(cfg.dbPath)
	if err != nil {
		return fmt.Errorf("open metric database: %w", err)
	}
	defer db.db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = db.prune(ctx, time.Now()); err != nil {
		return fmt.Errorf("prune metric database: %w", err)
	}
	a := newApp(cfg, db, newGitHub())
	go func() {
		retention := time.NewTicker(time.Hour)
		sessions := time.NewTicker(time.Minute)
		defer retention.Stop()
		defer sessions.Stop()
		for {
			select {
			case <-retention.C:
				if err := db.prune(ctx, time.Now()); err != nil && ctx.Err() == nil {
					log.Print("could not prune old reading statistics")
				}
			case now := <-sessions.C:
				a.auth.prune(now)
			case <-ctx.Done():
				return
			}
		}
	}()
	server := &http.Server{
		Addr: cfg.addr, Handler: a.handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16384,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("Metric listening on %s (GitHub OAuth configured: %t)", cfg.addr, cfg.clientID != "")
	if err = server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
