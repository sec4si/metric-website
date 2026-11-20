package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testOrigin  = "https://metric.sec4.si"
	testSite    = "https://sec4.si"
	testArticle = "/articles/readme/"
)

func testApp(t *testing.T) (*app, *atomic.Bool) {
	t.Helper()
	users := map[string]identity{
		"core":   {13946521, "VillanCh"},
		"owner":  {24248456, "zh-Processor"},
		"reader": {123, "test-reader"},
	}
	var ownerRemoved atomic.Bool
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		user := users[token]
		switch r.URL.Path {
		case "/login/oauth/access_token":
			if r.Method != "POST" || r.FormValue("client_secret") != "test-secret" ||
				len(r.FormValue("code_verifier")) != 43 || r.FormValue("redirect_uri") != testOrigin+"/oauth/callback" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": r.FormValue("code"), "token_type": "bearer"})
		case "/user":
			_ = json.NewEncoder(w).Encode(user)
		case "/user/memberships/orgs/sec4si":
			role := "admin"
			if token == "reader" || (token == "owner" && ownerRemoved.Load()) {
				role = "member"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"state": "active", "role": role, "user": user,
				"organization": map[string]string{"login": "sec4si"},
			})
		case "/orgs/sec4si/members":
			_ = json.NewEncoder(w).Encode([]identity{users["owner"], users["core"]})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)
	s, err := openStore(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.db.Close() })
	cfg := config{origin: testOrigin, articleOrigin: testSite, clientID: "test-id", clientSecret: "test-secret"}
	return newApp(cfg, s, githubClient{web: github.URL, api: github.URL, http: github.Client()}), &ownerRemoved
}

func request(handler http.Handler, method, path, origin, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Origin", origin)
	if method == "POST" {
		contentType := "application/x-www-form-urlencoded"
		if path == "/api/views" {
			contentType = "application/json"
		}
		r.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("got HTTP %d, want %d: %s", w.Code, status, w.Body.String())
	}
}

func startAndCallback(t *testing.T, a *app, h http.Handler, user, article string) *httptest.ResponseRecorder {
	t.Helper()
	start := request(h, "GET", "/oauth/start?article="+url.QueryEscape(article), "", "", nil)
	wantStatus(t, start, http.StatusSeeOther)
	loc, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	params := loc.Query()
	cookie := start.Result().Cookies()[0]
	state := params.Get("state")
	if cookie.Value != state || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("OAuth state cookie must be host-bound and secure")
	}
	scope := "read:org"
	if article != "" {
		scope = ""
	}
	if params.Get("scope") != scope || params.Get("code_challenge_method") != "S256" {
		t.Fatal("incorrect OAuth scopes or missing PKCE")
	}
	entry := a.auth.flows[state]
	hash := sha256.Sum256([]byte(entry.verifier))
	if params.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(hash[:]) {
		t.Fatal("PKCE challenge does not match the verifier")
	}
	callback := "/oauth/callback?code=" + user + "&state=" + state
	wantStatus(t, request(h, "GET", callback, "", "", nil), http.StatusBadRequest)
	result := request(h, "GET", callback, "", "", cookie)
	wantStatus(t, request(h, "GET", callback, "", "", cookie), http.StatusBadRequest)
	return result
}

func sessionCookie(t *testing.T, w *httptest.ResponseRecorder, kind string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-metric_"+kind && c.Value != "" {
			return c
		}
	}
	t.Fatalf("missing session cookie for %s", kind)
	return nil
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func formCSRF(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	field := csrfField.FindStringSubmatch(w.Body.String())
	if len(field) != 2 {
		t.Fatal("missing CSRF token")
	}
	return field[1]
}

func TestOwnerAuthorizationAndRevocation(t *testing.T) {
	a, ownerRemoved := testApp(t)
	h := a.handler()
	wantStatus(t, request(h, "GET", "/dashboard", "", "", nil), http.StatusSeeOther)
	wantStatus(t, startAndCallback(t, a, h, "reader", ""), http.StatusForbidden)
	coreLogin := startAndCallback(t, a, h, "core", "")
	wantStatus(t, coreLogin, http.StatusSeeOther)
	core := sessionCookie(t, coreLogin, "admin")
	ownerLogin := startAndCallback(t, a, h, "owner", "")
	wantStatus(t, ownerLogin, http.StatusSeeOther)
	owner := sessionCookie(t, ownerLogin, "admin")
	wantStatus(t, request(h, "GET", "/dashboard", "", "", owner), http.StatusOK)
	wantStatus(t, request(h, "GET", "/access", "", "", owner), http.StatusForbidden)
	ownerRemoved.Store(true)
	wantStatus(t, request(h, "GET", "/dashboard", "", "", owner), http.StatusForbidden)
	ownerRemoved.Store(false)
	access := request(h, "GET", "/access", "", "", core)
	wantStatus(t, access, http.StatusOK)
	form := url.Values{"csrf": {formCSRF(t, access)}, "id": {"24248456"}, "change": {"block"}}
	wantStatus(t, request(h, "POST", "/access", testSite, form.Encode(), core), http.StatusForbidden)
	wantStatus(t, request(h, "POST", "/access", testOrigin, form.Encode(), owner), http.StatusForbidden)
	form.Set("id", "18380453")
	wantStatus(t, request(h, "POST", "/access", testOrigin, form.Encode(), core), http.StatusBadRequest)
	form.Set("id", "24248456")
	wantStatus(t, request(h, "POST", "/access", testOrigin, form.Encode(), core), http.StatusSeeOther)
	wantStatus(t, request(h, "GET", "/dashboard", "", "", owner), http.StatusForbidden)
	form.Set("change", "restore")
	wantStatus(t, request(h, "POST", "/access", testOrigin, form.Encode(), core), http.StatusSeeOther)
	wantStatus(t, request(h, "GET", "/dashboard", "", "", owner), http.StatusOK)
}

func TestConsentAndAnonymousViewsStaySeparate(t *testing.T) {
	a, _ := testApp(t)
	h := a.handler()
	const view = `{"path":"/articles/readme/"}`
	wantStatus(t, request(h, "POST", "/api/views", "https://unrelated.example", view, nil), http.StatusForbidden)
	wantStatus(t, request(h, "POST", "/api/views", testSite, `{"path":"/articles/readme/","login":"test-reader"}`, nil), http.StatusBadRequest)
	wantStatus(t, request(h, "POST", "/api/views", testSite, `{"path":"/articles/readme/?token=1"}`, nil), http.StatusBadRequest)
	preflight := request(h, "OPTIONS", "/api/views", testSite, "", nil)
	wantStatus(t, preflight, http.StatusNoContent)
	if preflight.Header().Get("Access-Control-Allow-Origin") != testSite {
		t.Fatal("preflight did not permit the article site")
	}
	ignored := httptest.NewRequest("POST", "/api/views", strings.NewReader(view))
	ignored.Header.Set("Origin", testSite)
	ignored.Header.Set("Sec-GPC", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, ignored)
	wantStatus(t, w, http.StatusNoContent)
	wantStatus(t, request(h, "POST", "/api/views", testSite, view, nil), http.StatusNoContent)

	readerLogin := startAndCallback(t, a, h, "reader", testArticle)
	wantStatus(t, readerLogin, http.StatusSeeOther)
	reader := sessionCookie(t, readerLogin, "reader")
	wantStatus(t, request(h, "GET", "/dashboard", "", "", reader), http.StatusSeeOther)
	confirm := request(h, "GET", "/read", "", "", reader)
	wantStatus(t, confirm, http.StatusOK)
	ctx := context.Background()
	check := func(want int) {
		t.Helper()
		n, err := a.store.summary(ctx, day(time.Now()), testArticle)
		if err != nil || n.Views != 1 || n.Readers != want || n.Records != want {
			t.Fatalf("unexpected current totals: %+v, %v", n, err)
		}
	}
	check(0)
	form := url.Values{"csrf": {formCSRF(t, confirm)}}
	wantStatus(t, request(h, "POST", "/read", testSite, form.Encode(), reader), http.StatusForbidden)
	check(0)
	wantStatus(t, request(h, "POST", "/read", testOrigin, form.Encode(), reader), http.StatusSeeOther)
	wantStatus(t, request(h, "POST", "/read", testOrigin, form.Encode(), reader), http.StatusUnauthorized)
	check(1)
	core := sessionCookie(t, startAndCallback(t, a, h, "core", ""), "admin")
	dashboard := request(h, "GET", "/dashboard?article="+url.QueryEscape(testArticle), "", "", core)
	wantStatus(t, dashboard, http.StatusOK)
	if !strings.Contains(dashboard.Body.String(), "@test-reader") ||
		dashboard.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("confirmed reader did not appear in the private dashboard")
	}
}
