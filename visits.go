package main

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const visitIPRetention = 7 * 24 * time.Hour

var projectOrigins = []string{"https://benchmark.sec4.si", "https://lens.sec4.si", "https://infer.sec4.si"}
var referrerDomain = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

func (a *app) visitOriginAllowed(origin string) bool {
	return origin != "" && (origin == a.cfg.articleOrigin || slices.Contains(projectOrigins, origin))
}

func collectionRequest(w http.ResponseWriter, r *http.Request, origin string) bool {
	w.Header().Set("Vary", "Origin")
	if origin == "" || r.Header.Get("Origin") != origin {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	if r.Header.Get("Sec-GPC") == "1" || r.Header.Get("DNT") == "1" {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

func normalizedVisitPath(path string) string {
	if len(path) > 240 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#") {
		return ""
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || strings.ContainsAny(u.Path, "\x00\r\n\\") {
		return ""
	}
	escaped := u.EscapedPath()
	if strings.HasSuffix(escaped, "/index.html") {
		return strings.TrimSuffix(escaped, "index.html")
	}
	return escaped
}

func (a *app) ingestSiteVisit(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if !a.visitOriginAllowed(origin) {
		origin = ""
	}
	if !collectionRequest(w, r, origin) {
		return
	}
	ip := net.ParseIP(clientIP(r))
	if ip == nil {
		http.Error(w, "client address unavailable", http.StatusBadRequest)
		return
	}
	if !a.rate.allow("visit:"+ip.String(), 90) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType != "application/json" {
		http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
		return
	}
	var input struct {
		Path     string `json:"path"`
		Referrer string `json:"referrer"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "expected one visit record", http.StatusBadRequest)
		return
	}
	path := normalizedVisitPath(input.Path)
	if path == "" || (input.Referrer != "" && !referrerDomain.MatchString(input.Referrer)) {
		http.Error(w, "invalid visit record", http.StatusBadRequest)
		return
	}
	article := origin == a.cfg.articleOrigin && validArticle(path)
	if err := a.store.recordSiteVisit(r.Context(), origin, path, ip.String(), input.Referrer, time.Now(), article); err != nil {
		http.Error(w, "statistics unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *store) recordSiteVisit(ctx context.Context, site, path, ip, referrer string, now time.Time, article bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO site_visit_details (site, path, ip, referrer, visited_at)
		VALUES (?, ?, ?, ?, ?)`, site, path, ip, referrer, now.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO site_daily_views (site, path, day, views)
		VALUES (?, ?, ?, 1) ON CONFLICT (site, path, day) DO UPDATE SET views = views + 1`,
		site, path, now.In(reportingTimeZone).Format("2006-01-02")); err != nil {
		return err
	}
	if article {
		if _, err = tx.ExecContext(ctx, `INSERT INTO article_views (path, day, views) VALUES (?, ?, 1)
			ON CONFLICT (path, day) DO UPDATE SET views = views + 1`, path, day(now)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type siteOption struct {
	Origin string
	Name   string
}

type sitePageCount struct {
	Site  string
	Path  string
	Views int
}

type siteVisitDetail struct {
	Site     string
	Path     string
	IP       string
	Referrer string
	Seen     time.Time
}

type visitsPage struct {
	Site      string
	Sites     []siteOption
	Views     int
	SourceIPs int
	Pages     []sitePageCount
	Details   []siteVisitDetail
}

func (s *store) siteVisitTotals(ctx context.Context, site string, since time.Time, detailsSince time.Time) (views, ips int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT
		(SELECT coalesce(sum(views), 0) FROM site_daily_views WHERE day >= ?1 AND (?3 = '' OR site = ?3)),
		(SELECT count(DISTINCT ip) FROM site_visit_details WHERE visited_at >= ?2 AND (?3 = '' OR site = ?3))`,
		since.In(reportingTimeZone).Format("2006-01-02"), detailsSince.Unix(), site).Scan(&views, &ips)
	return
}

func (s *store) sitePageViews(ctx context.Context, site string, since time.Time) ([]sitePageCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT site, path, sum(views) AS total FROM site_daily_views
		WHERE day >= ? AND (? = '' OR site = ?) GROUP BY site, path ORDER BY total DESC, site, path LIMIT 50`,
		since.In(reportingTimeZone).Format("2006-01-02"), site, site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var counts []sitePageCount
	for rows.Next() {
		var count sitePageCount
		if err := rows.Scan(&count.Site, &count.Path, &count.Views); err != nil {
			return nil, err
		}
		count.Site = strings.TrimPrefix(count.Site, "https://")
		counts = append(counts, count)
	}
	return counts, rows.Err()
}

func (s *store) siteVisitDetails(ctx context.Context, site string, since time.Time, offset int) ([]siteVisitDetail, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT site, path, ip, referrer, visited_at FROM site_visit_details
		WHERE visited_at >= ? AND (? = '' OR site = ?) ORDER BY visited_at DESC, id DESC LIMIT 51 OFFSET ?`,
		since.Unix(), site, site, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var details []siteVisitDetail
	for rows.Next() {
		var detail siteVisitDetail
		var seen int64
		if err := rows.Scan(&detail.Site, &detail.Path, &detail.IP, &detail.Referrer, &seen); err != nil {
			return nil, err
		}
		detail.Site = strings.TrimPrefix(detail.Site, "https://")
		detail.Seen = time.Unix(seen, 0).In(reportingTimeZone)
		details = append(details, detail)
	}
	return details, rows.Err()
}

func visitsURL(period int, site string, page int) string {
	q := url.Values{"days": {strconv.Itoa(period)}}
	if site != "" {
		q.Set("site", site)
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	return "/visits?" + q.Encode()
}

func (a *app) visitsDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := a.admin(w, r, false)
	if !ok {
		return
	}
	q := r.URL.Query()
	period, _ := strconv.Atoi(q.Get("days"))
	if period != 7 && period != 30 && period != 90 {
		period = 30
	}
	site := q.Get("site")
	if !a.visitOriginAllowed(site) {
		site = ""
	}
	index, _ := strconv.Atoi(q.Get("page"))
	if index < 1 || index > 20000 {
		index = 1
	}
	now := time.Now()
	since := reportingSince(now, period)
	detailsSince := now.Add(-visitIPRetention)
	if detailsSince.Before(since) {
		detailsSince = since
	}
	ctx := r.Context()
	views, ips, err := a.store.siteVisitTotals(ctx, site, since, detailsSince)
	if err != nil {
		a.storeError(w)
		return
	}
	pages, err := a.store.sitePageViews(ctx, site, since)
	if err != nil {
		a.storeError(w)
		return
	}
	details, err := a.store.siteVisitDetails(ctx, site, detailsSince, (index-1)*50)
	if err != nil {
		a.storeError(w)
		return
	}
	origins := append([]string{a.cfg.articleOrigin}, projectOrigins...)
	options := make([]siteOption, 0, len(origins))
	for _, origin := range origins {
		options = append(options, siteOption{Origin: origin, Name: strings.TrimPrefix(origin, "https://")})
	}
	data := page{
		Title: "站点访问", User: user.user, Core: isCore(user.user.ID), CSRF: user.csrf, Period: period,
		Visits: visitsPage{Site: site, Sites: options, Views: views, SourceIPs: ips, Pages: pages, Details: details},
	}
	if index > 1 {
		data.Prev = visitsURL(period, site, index-1)
	}
	if len(details) > 50 {
		data.Visits.Details = details[:50]
		data.Next = visitsURL(period, site, index+1)
	}
	a.render(w, "visitsDashboard", http.StatusOK, data)
}
