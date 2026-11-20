package main

import (
	"cmp"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type actionsAccountTotal struct {
	actionsActor
	Executions int
	Reruns     int
	FilterURL  string
	lastSeen   time.Time
}

type actionsDisplayRun struct {
	actionsAttempt
	Repository string
	TimeLabel  string
	RunURL     string
	CommitID   string
	CommitURL  string
}

type actionsPage struct {
	Configured   bool
	SyncFailed   bool
	SyncedAt     string
	Repositories []actionsRepository
	RepositoryID int64
	ActorID      int64
	Executions   int
	People       int
	Reruns       int
	Unavailable  int
	Accounts     []actionsAccountTotal
	Runs         []actionsDisplayRun
	ClearActor   string
}

func actionsPageURL(days int, repo, actor int64, page int) string {
	values := url.Values{"days": {strconv.Itoa(days)}}
	if repo != 0 {
		values.Set("repo", strconv.FormatInt(repo, 10))
	}
	if actor != 0 {
		values.Set("actor", strconv.FormatInt(actor, 10))
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	return "/actions?" + values.Encode()
}

func (a *app) actionsDashboard(w http.ResponseWriter, r *http.Request) {
	s, ok := a.admin(w, r, false)
	if !ok {
		return
	}
	query := r.URL.Query()
	days, _ := strconv.Atoi(query.Get("days"))
	if days != 7 && days != 30 && days != 90 {
		days = 90
	}
	repoID, _ := strconv.ParseInt(query.Get("repo"), 10, 64)
	actorID, _ := strconv.ParseInt(query.Get("actor"), 10, 64)
	index, _ := strconv.Atoi(query.Get("page"))
	if index < 1 || index > 20000 {
		index = 1
	}
	data := page{
		Title: "Actions 统计", User: s.user, Core: isCore(s.user.ID), CSRF: s.csrf,
		Period: days, Actions: actionsPage{Configured: a.cfg.actions != nil, SyncFailed: a.actionsSyncFailed.Load()},
	}
	if data.Actions.Configured {
		snapshot, err := a.store.actionsSnapshot(r.Context())
		if err != nil {
			a.storeError(w)
			return
		}
		if !snapshot.SyncedAt.IsZero() {
			data.Actions = buildActionsPage(snapshot, data.Actions.SyncFailed, time.Now(), days, repoID, actorID, index)
			if index > 1 {
				data.Prev = actionsPageURL(days, data.Actions.RepositoryID, data.Actions.ActorID, index-1)
			}
			if len(data.Actions.Runs) > 50 {
				data.Actions.Runs = data.Actions.Runs[:50]
				data.Next = actionsPageURL(days, data.Actions.RepositoryID, data.Actions.ActorID, index+1)
			}
		}
	}
	a.render(w, "actionsDashboard", http.StatusOK, data)
}

func buildActionsPage(snapshot actionsSnapshot, failed bool, now time.Time, days int, repoID, actorID int64, index int) actionsPage {
	result := actionsPage{
		Configured: true, SyncFailed: failed, SyncedAt: snapshot.SyncedAt.In(reportingTimeZone).Format("2006-01-02 15:04"),
		Repositories: snapshot.Repositories, Unavailable: snapshot.UnavailableHistory,
	}
	slices.SortFunc(result.Repositories, func(a, b actionsRepository) int {
		return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	repositories := make(map[int64]string, len(result.Repositories))
	for _, repo := range result.Repositories {
		repositories[repo.ID] = repo.Name
	}
	if _, exists := repositories[repoID]; !exists {
		repoID = 0
	}
	if actorID < 0 {
		actorID = 0
	}
	result.RepositoryID = repoID
	result.ActorID = actorID
	result.ClearActor = actionsPageURL(days, repoID, 0, 1)

	accounts := make(map[int64]actionsAccountTotal)
	people := make(map[int64]bool)
	var runs []actionsAttempt
	cutoff := reportingSince(now, days)
	for _, attempt := range snapshot.Attempts {
		if attempt.Created.Before(cutoff) || (repoID != 0 && attempt.RepositoryID != repoID) {
			continue
		}
		id := attempt.Actor.ID
		if id > 0 {
			account := accounts[id]
			if attempt.Created.After(account.lastSeen) {
				account.actionsActor = attempt.Actor
				account.lastSeen = attempt.Created
			}
			account.Executions++
			if attempt.Attempt > 1 {
				account.Reruns++
			}
			accounts[id] = account
		}
		if actorID != 0 && actorID != id {
			continue
		}
		runs = append(runs, attempt)
		if id > 0 && attempt.Actor.Type == "User" {
			people[id] = true
		}
		if attempt.Attempt > 1 {
			result.Reruns++
		}
	}
	result.Executions = len(runs)
	result.People = len(people)
	for _, account := range accounts {
		account.FilterURL = actionsPageURL(days, repoID, account.ID, 1)
		result.Accounts = append(result.Accounts, account)
	}
	slices.SortFunc(result.Accounts, func(a, b actionsAccountTotal) int {
		return cmp.Or(cmp.Compare(b.Executions, a.Executions), cmp.Compare(strings.ToLower(a.Login), strings.ToLower(b.Login)), cmp.Compare(a.ID, b.ID))
	})
	slices.SortFunc(runs, func(a, b actionsAttempt) int {
		return cmp.Or(b.Created.Compare(a.Created), cmp.Compare(b.RunID, a.RunID), cmp.Compare(b.Attempt, a.Attempt))
	})
	start := min(len(runs), (index-1)*50)
	for _, run := range runs[start:min(len(runs), start+51)] {
		name := repositories[run.RepositoryID]
		repoURL := "https://github.com/" + org + "/" + url.PathEscape(name)
		display := actionsDisplayRun{
			actionsAttempt: run, Repository: name, TimeLabel: run.Created.In(reportingTimeZone).Format("01-02 15:04"),
			RunURL: repoURL + "/actions/runs/" + strconv.FormatInt(run.RunID, 10),
		}
		if run.CommitSHA != "" {
			display.CommitID = run.CommitSHA[:min(7, len(run.CommitSHA))]
			display.CommitURL = repoURL + "/commit/" + url.PathEscape(run.CommitSHA)
		}
		result.Runs = append(result.Runs, display)
	}
	return result
}
