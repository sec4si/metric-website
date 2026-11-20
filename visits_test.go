package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSiteVisitsRecordOnlyAllowedSiteAndTrustedIP(t *testing.T) {
	a, _ := testApp(t)
	h := a.handler()
	path := "/api/visits"
	post := func(origin, body, remote, reportedIP, dnt string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Real-IP", reportedIP)
		r.Header.Set("DNT", dnt)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	lens := "https://lens.sec4.si"
	wantStatus(t, request(h, "OPTIONS", path, lens, "", nil), http.StatusNoContent)
	wantStatus(t, post("https://unrelated.example", `{"path":"/"}`, "127.0.0.1:4321", "203.0.113.1", ""), http.StatusForbidden)
	wantStatus(t, post(lens, `{"path":"/?token=value"}`, "127.0.0.1:4321", "203.0.113.1", ""), http.StatusBadRequest)
	wantStatus(t, post(lens, `{"path":"/","referrer":"example.com/path"}`, "127.0.0.1:4321", "203.0.113.1", ""), http.StatusBadRequest)
	wantStatus(t, post(lens, `{"path":"/"}`, "127.0.0.1:4321", "203.0.113.1", "1"), http.StatusNoContent)
	wantStatus(t, post(lens, `{"path":"/research/index.html","referrer":"github.com"}`,
		"127.0.0.1:4321", "203.0.113.2", ""), http.StatusNoContent)
	wantStatus(t, post(testSite, `{"path":"/articles/readme/"}`,
		"198.51.100.1:12345", "203.0.113.3", ""), http.StatusNoContent)

	now := time.Now()
	details, err := a.store.siteVisitDetails(context.Background(), "", now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(details) != 2 || details[0].IP != "198.51.100.1" || details[1].IP != "203.0.113.2" ||
		details[1].Path != "/research/" || details[1].Referrer != "github.com" {
		t.Fatalf("unexpected stored visits: %+v", details)
	}
	views, err := a.store.summary(context.Background(), sinceDay(now, 7), "/articles/readme/")
	if err != nil || views.Views != 1 {
		t.Fatalf("article visit not counted once: %+v %v", views, err)
	}
	anonymous := request(h, "GET", "/visits", "", "", nil)
	wantStatus(t, anonymous, http.StatusSeeOther)
	if strings.Contains(anonymous.Body.String(), "203.0.113.2") {
		t.Fatal("public response exposed visit addresses")
	}
	owner := sessionCookie(t, startAndCallback(t, a, h, "owner", ""), "admin")
	dashboard := request(h, "GET", "/visits?site=https%3A%2F%2Flens.sec4.si", "", "", owner)
	wantStatus(t, dashboard, http.StatusOK)
	if !strings.Contains(dashboard.Body.String(), "203.0.113.2") || strings.Contains(dashboard.Body.String(), "198.51.100.1") {
		t.Fatal("visit dashboard did not isolate the selected site")
	}
}

func TestVisitIPRetentionKeepsDailyCounts(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	now := time.Now()
	if err := a.store.recordSiteVisit(ctx, testSite, "/", "203.0.113.4", "", now.Add(-8*24*time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if err := a.store.prune(ctx, now); err != nil {
		t.Fatal(err)
	}
	total, addresses, err := a.store.siteVisitTotals(ctx, testSite, reportingSince(now, 90), now.Add(-90*24*time.Hour))
	if err != nil || total != 1 || addresses != 0 {
		t.Fatalf("daily counts and IP detail should expire separately: %d %d %v", total, addresses, err)
	}
}
