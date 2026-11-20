package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCollectActionsUsesPerAttemptActor(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 14, 0, 0, 0, time.UTC)
	first := githubActionRun{
		ID: 42, Name: "Check changes", Event: "pull_request", Status: "completed", Result: "failure",
		Attempt: 1, Created: now.Add(-8 * time.Hour),
		Actor: actionsActor{identity{18, "first-actor"}, "User"},
	}
	second := first
	second.Attempt = 2
	second.Created = now.Add(-time.Hour)
	second.Result = "success"
	second.Triggerer = actionsActor{identity{19, "rerun-actor"}, "User"}

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		tokenCall := r.URL.Path == "/orgs/sec4si/installation" || r.URL.Path == "/app/installations/77/access_tokens"
		if (tokenCall && (!strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, ".") != 2)) ||
			(!tokenCall && authorization != "Bearer test-installation") {
			http.Error(w, "wrong test authorization", http.StatusUnauthorized)
			return
		}
		var body any
		switch r.URL.Path {
		case "/orgs/sec4si/installation":
			body = json.RawMessage(`{"id":77,"repository_selection":"all","target_type":"Organization","account":{"login":"sec4si"}}`)
		case "/app/installations/77/access_tokens":
			var requested struct {
				Permissions map[string]string `json:"permissions"`
			}
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&requested) != nil ||
				len(requested.Permissions) != 2 || requested.Permissions["actions"] != "read" || requested.Permissions["metadata"] != "read" {
				http.Error(w, "expected read-only permissions", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			body = json.RawMessage(`{"token":"test-installation"}`)
		case "/installation/repositories":
			body = json.RawMessage(`{"repositories":[{"id":12,"name":"private-work","visibility":"private","owner":{"login":"sec4si"}},{"id":34,"name":"empty","visibility":"public","owner":{"login":"sec4si"}}]}`)
		case "/repos/sec4si/private-work/actions/runs":
			run := second
			run.Created = first.Created
			body = map[string]any{"total_count": 1, "workflow_runs": []githubActionRun{run}}
		case "/repos/sec4si/empty/actions/runs":
			body = json.RawMessage(`{"total_count":0,"workflow_runs":[]}`)
		case "/repos/sec4si/private-work/actions/runs/42/attempts/1":
			body = first
		case "/repos/sec4si/private-work/actions/runs/42/attempts/2":
			body = second
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(source.Close)

	g := githubClient{api: source.URL, http: source.Client()}
	snapshot, err := g.collectActions(context.Background(), &actionsCredentials{"12345", key}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Repositories) != 2 || len(snapshot.Attempts) != 2 ||
		snapshot.Attempts[0].Actor.Login != "first-actor" || snapshot.Attempts[1].Actor.Login != "rerun-actor" ||
		!snapshot.Attempts[1].Created.Equal(second.Created) || snapshot.Attempts[0].Result != "failure" {
		t.Fatalf("incorrect repository coverage or attempt attribution: %+v", snapshot)
	}
	view := buildActionsPage(snapshot, false, now, 90, 12, 19, 1)
	if view.Executions != 1 || view.Reruns != 1 || view.People != 1 || len(view.Runs) != 1 || view.Runs[0].Attempt != 2 {
		t.Fatalf("incorrect filtered rerun totals: %+v", view)
	}
}

func TestActionsDashboardProtectsPrivateRunData(t *testing.T) {
	a, removed := testApp(t)
	a.cfg.actions = &actionsCredentials{}
	now := time.Now().UTC()
	snapshot := actionsSnapshot{
		SyncedAt:     now,
		Repositories: []actionsRepository{{ID: 12, Name: "private-work", Visibility: "private"}},
		Attempts: []actionsAttempt{{
			RepositoryID: 12, RunID: 42, Attempt: 2, Created: now,
			Workflow: "Check changes", Result: "success", Actor: actionsActor{identity{19, "rerun-actor"}, "User"},
		}},
	}
	if err := a.store.saveActionsSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	h := a.handler()
	path := "/actions?days=90&repo=12&actor=19"
	wantStatus(t, request(h, "GET", path, "", "", nil), http.StatusSeeOther)
	reader := sessionCookie(t, startAndCallback(t, a, h, "reader", testArticle), "reader")
	wantStatus(t, request(h, "GET", path, "", "", reader), http.StatusSeeOther)

	owner := sessionCookie(t, startAndCallback(t, a, h, "owner", ""), "admin")
	page := request(h, "GET", path, "", "", owner)
	wantStatus(t, page, http.StatusOK)
	html := page.Body.String()
	for _, value := range []string{"private-work", "@rerun-actor", "Check changes", "查看全部账号"} {
		if !strings.Contains(html, value) {
			t.Fatalf("Actions page did not render %q", value)
		}
	}
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private metrics must not be cacheable")
	}
	removed.Store(true)
	denied := request(h, "GET", path, "", "", owner)
	wantStatus(t, denied, http.StatusForbidden)
	if strings.Contains(denied.Body.String(), "private-work") {
		t.Fatal("revoked owner can see repository metadata")
	}
}
