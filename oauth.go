package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const org = "sec4si"

const (
	flowLifetime    = 10 * time.Minute
	sessionLifetime = 30 * time.Minute
	readerLifetime  = 10 * time.Minute
)

type identity struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

// Numeric GitHub account IDs keep privileges attached to the same accounts after a rename.
func isCore(id int64) bool {
	switch id {
	case 48591714, 13946521, 18380453: // ZacharyZcR, VillanCh, winmin
		return true
	default:
		return false
	}
}

var loginPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

type githubClient struct {
	web  string
	api  string
	http *http.Client
}

func newGitHub() githubClient {
	return githubClient{
		web: "https://github.com", api: "https://api.github.com",
		http: &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

type oauthFlow struct {
	verifier string
	article  string
	expires  time.Time
}

type session struct {
	user    identity
	token   string
	article string
	csrf    string
	expires time.Time
}

type authMemory struct {
	mu       sync.Mutex
	flows    map[string]oauthFlow
	sessions map[string]session
}

func (m *authMemory) addFlow(key string, f oauthFlow) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.flows) >= 2048 {
		return false
	}
	m.flows[key] = f
	return true
}

func (m *authMemory) takeFlow(key string) (oauthFlow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, found := m.flows[key]
	delete(m.flows, key)
	return f, found && f.expires.After(time.Now())
}

func (m *authMemory) addSession(key string, s session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= 512 {
		return false
	}
	m.sessions[key] = s
	return true
}

func (m *authMemory) getSession(key string) (session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, found := m.sessions[key]
	if found && s.expires.After(time.Now()) {
		return s, true
	}
	delete(m.sessions, key)
	return session{}, false
}

func (m *authMemory) deleteSession(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, key)
}

func (m *authMemory) prune(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, f := range m.flows {
		if !f.expires.After(now) {
			delete(m.flows, id)
		}
	}
	for id, s := range m.sessions {
		if !s.expires.After(now) {
			delete(m.sessions, id)
		}
	}
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func sameToken(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (a *app) cookieName(suffix string) string {
	if strings.HasPrefix(a.cfg.origin, "https://") {
		return "__Host-metric_" + suffix
	}
	return "metric_" + suffix
}

func (a *app) setCookie(w http.ResponseWriter, suffix, value string, age time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(suffix), Value: value, Path: "/", MaxAge: int(age.Seconds()),
		HttpOnly: true, Secure: strings.HasPrefix(a.cfg.origin, "https://"), SameSite: http.SameSiteLaxMode,
	})
}

func (a *app) cookie(r *http.Request, suffix string) string {
	if c, err := r.Cookie(a.cookieName(suffix)); err == nil {
		return c.Value
	}
	return ""
}

func (a *app) startOAuth(w http.ResponseWriter, r *http.Request) {
	if a.cfg.clientID == "" {
		a.problem(w, http.StatusServiceUnavailable, "GitHub 登录正在配置", "登录启用后，可从这里进入后台或为文章留下阅读记录。")
		return
	}
	article := r.URL.Query().Get("article")
	if article != "" && !validArticle(article) {
		a.problem(w, http.StatusBadRequest, "文章地址有误", "请从文章的阅读统计入口重试。")
		return
	}
	if !a.rate.allow("oauth:"+clientIP(r), 20) {
		a.problem(w, http.StatusTooManyRequests, "请求过于频繁", "请稍后重试 GitHub 登录。")
		return
	}
	state, verifier := randomToken(), randomToken()
	if !a.auth.addFlow(state, oauthFlow{verifier, article, time.Now().Add(flowLifetime)}) {
		a.problem(w, http.StatusServiceUnavailable, "登录暂时繁忙", "请稍后重试。")
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	params := url.Values{
		"client_id":             {a.cfg.clientID},
		"redirect_uri":          {a.cfg.origin + "/oauth/callback"},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
		"scope":                 {""},
	}
	if article == "" {
		params.Set("scope", "read:org")
	}
	a.setCookie(w, "oauth", state, flowLifetime)
	http.Redirect(w, r, a.github.web+"/login/oauth/authorize?"+params.Encode(), http.StatusSeeOther)
}

func (g githubClient) exchange(ctx context.Context, cfg config, code, verifier string) (string, error) {
	form := url.Values{
		"client_id": {cfg.clientID}, "client_secret": {cfg.clientSecret},
		"redirect_uri": {cfg.origin + "/oauth/callback"}, "code": {code}, "code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, g.web+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	res, err := g.http.Do(request)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if res.StatusCode != http.StatusOK ||
		json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(&result) != nil ||
		result.AccessToken == "" || !strings.EqualFold(result.TokenType, "bearer") {
		return "", errors.New("GitHub rejected the OAuth exchange")
	}
	return result.AccessToken, nil
}

func (g githubClient) get(ctx context.Context, path, token string, result any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, g.api+path, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	res, err := g.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return res.StatusCode, fmt.Errorf("GitHub returned %d", res.StatusCode)
	}
	return res.StatusCode, json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(result)
}

func (g githubClient) user(ctx context.Context, token string) (identity, error) {
	var user identity
	_, err := g.get(ctx, "/user", token, &user)
	if err == nil && (user.ID <= 0 || !loginPattern.MatchString(user.Login)) {
		err = errors.New("invalid GitHub identity")
	}
	return user, err
}

func (g githubClient) owner(ctx context.Context, token string, id int64) (bool, error) {
	var membership struct {
		State        string
		Role         string
		User         identity
		Organization identity
	}
	code, err := g.get(ctx, "/user/memberships/orgs/"+org, token, &membership)
	if code == http.StatusNotFound || code == http.StatusUnauthorized || code == http.StatusForbidden {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return membership.State == "active" && membership.Role == "admin" &&
		membership.User.ID == id && strings.EqualFold(membership.Organization.Login, org), nil
}

func (g githubClient) owners(ctx context.Context, token string) ([]identity, error) {
	var all []identity
	for page := 1; ; page++ {
		var batch []identity
		_, err := g.get(ctx, "/orgs/"+org+"/members?role=admin&per_page=100&page="+strconv.Itoa(page), token, &batch)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			return all, nil
		}
	}
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if !sameToken(state, a.cookie(r, "oauth")) {
		a.problem(w, http.StatusBadRequest, "登录链接已失效", "请重新发起 GitHub 登录。")
		return
	}
	a.setCookie(w, "oauth", "", -time.Second)
	flow, ok := a.auth.takeFlow(state)
	code := r.URL.Query().Get("code")
	if !ok || code == "" || len(code) > 256 {
		a.problem(w, http.StatusBadRequest, "登录未完成", "请重新发起 GitHub 登录。")
		return
	}
	token, err := a.github.exchange(r.Context(), a.cfg, code, flow.verifier)
	if err != nil {
		a.problem(w, http.StatusBadGateway, "GitHub 登录失败", "请返回后重新登录。")
		return
	}
	user, err := a.github.user(r.Context(), token)
	if err != nil {
		a.problem(w, http.StatusBadGateway, "无法核对 GitHub 账号", "请返回后重新登录。")
		return
	}
	s := session{user: user, article: flow.article, csrf: randomToken()}
	age, suffix, destination := readerLifetime, "reader", "/read"
	if flow.article == "" {
		if !a.authorize(w, r, user.ID, token) {
			return
		}
		s.token = token
		age, suffix, destination = sessionLifetime, "admin", "/visits"
	}
	id := randomToken()
	s.expires = time.Now().Add(age)
	if !a.auth.addSession(id, s) {
		a.problem(w, http.StatusServiceUnavailable, "登录暂时繁忙", "请稍后重试。")
		return
	}
	a.auth.deleteSession(a.cookie(r, suffix))
	a.setCookie(w, suffix, id, age)
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

func (a *app) authorize(w http.ResponseWriter, r *http.Request, id int64, token string) bool {
	owner, err := a.github.owner(r.Context(), token, id)
	if err != nil {
		a.problem(w, http.StatusServiceUnavailable, "暂时无法核验组织权限", "请稍后重试。")
		return false
	}
	if !owner {
		a.problem(w, http.StatusForbidden, "后台仅供组织管理员访问", "请使用 sec4si 的组织管理员账号登录，并授权读取组织身份。")
		return false
	}
	blocked, err := a.store.isBlocked(r.Context(), id)
	if err != nil {
		a.problem(w, http.StatusServiceUnavailable, "权限服务暂时不可用", "请稍后重试。")
		return false
	}
	if blocked {
		a.problem(w, http.StatusForbidden, "后台访问已暂停", "请联系 sec4si 核心管理员。")
		return false
	}
	return true
}

func (a *app) admin(w http.ResponseWriter, r *http.Request, coreOnly bool) (session, bool) {
	s, ok := a.auth.getSession(a.cookie(r, "admin"))
	if !ok || s.token == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return session{}, false
	}
	if !a.authorize(w, r, s.user.ID, s.token) {
		return session{}, false
	}
	if coreOnly && !isCore(s.user.ID) {
		a.problem(w, http.StatusForbidden, "只有核心管理员可以管理权限", "组织管理员可以查看统计数据。")
		return session{}, false
	}
	return s, true
}

func (a *app) formOK(w http.ResponseWriter, r *http.Request, s session) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if r.Header.Get("Origin") == a.cfg.origin && r.ParseForm() == nil &&
		sameToken(s.csrf, r.PostForm.Get("csrf")) {
		return true
	}
	a.problem(w, http.StatusForbidden, "表单验证失败", "请刷新页面后再试。")
	return false
}
