package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const actionsSyncInterval = 15 * time.Minute

type actionsCredentials struct {
	appID string
	key   *rsa.PrivateKey
}

func readActionsCredentials() (*actionsCredentials, error) {
	id := os.Getenv("METRIC_ACTIONS_APP_ID")
	if id == "" {
		return nil, nil
	}
	if value, err := strconv.ParseUint(id, 10, 64); err != nil || value == 0 {
		return nil, errors.New("METRIC_ACTIONS_APP_ID must be a GitHub App ID")
	}
	path := os.Getenv("METRIC_ACTIONS_KEY_FILE")
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			path = filepath.Join(dir, "github-actions-key")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("could not read the GitHub Actions App credential")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the GitHub Actions App credential must be a PEM private key")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if err != nil || key == nil || key.Size() < 256 {
		return nil, errors.New("the GitHub Actions App credential must be an RSA key of at least 2048 bits")
	}
	return &actionsCredentials{appID: id, key: key}, nil
}

type actionsRepository struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Visibility string `json:"visibility"`
	Owner      struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type actionsActor struct {
	identity
	Type string `json:"type"`
}

type githubActionRun struct {
	ID        int64        `json:"id"`
	Name      string       `json:"name"`
	Event     string       `json:"event"`
	Status    string       `json:"status"`
	Result    string       `json:"conclusion"`
	Attempt   int          `json:"run_attempt"`
	Created   time.Time    `json:"created_at"`
	Actor     actionsActor `json:"actor"`
	Triggerer actionsActor `json:"triggering_actor"`
	HeadSHA   string       `json:"head_sha"`
	Commit    struct {
		Author struct {
			Name string `json:"name"`
		} `json:"author"`
		Committer struct {
			Name string `json:"name"`
		} `json:"committer"`
	} `json:"head_commit"`
}

type actionsAttempt struct {
	RepositoryID int64
	RunID        int64
	Attempt      int
	Workflow     string
	Event        string
	Status       string
	Result       string
	Created      time.Time
	Actor        actionsActor
	CommitSHA    string
	CommitAuthor string
	Committer    string
}

type actionsSnapshot struct {
	SyncedAt           time.Time
	Repositories       []actionsRepository
	Attempts           []actionsAttempt
	UnavailableHistory int
}

func (c *actionsCredentials) jwt(now time.Time) (string, error) {
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": c.appID,
	})
	if err != nil {
		return "", err
	}
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	unsigned := head + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (g githubClient) actionsToken(ctx context.Context, cred *actionsCredentials, now time.Time) (string, error) {
	jwt, err := cred.jwt(now)
	if err != nil {
		return "", err
	}
	var installation struct {
		ID        int64  `json:"id"`
		Selection string `json:"repository_selection"`
		Target    string `json:"target_type"`
		Account   struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if _, err := g.get(ctx, "/orgs/"+org+"/installation", jwt, &installation); err != nil {
		return "", err
	}
	if installation.ID <= 0 || installation.Target != "Organization" || !strings.EqualFold(installation.Account.Login, org) || installation.Selection != "all" {
		return "", errors.New("the Actions App must cover all repositories in sec4si")
	}
	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", g.api, installation.ID)
	body := strings.NewReader(`{"permissions":{"actions":"read","metadata":"read"}}`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+jwt)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := g.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("GitHub Actions App token request returned %d", response.StatusCode)
	}
	var data struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&data); err != nil {
		return "", err
	}
	if data.Token == "" {
		return "", errors.New("GitHub returned an empty installation token")
	}
	return data.Token, nil
}

func (g githubClient) actionsRepositories(ctx context.Context, token string) ([]actionsRepository, error) {
	var repositories []actionsRepository
	seen := make(map[int64]bool)
	for page := 1; ; page++ {
		var batch struct {
			Repositories []actionsRepository `json:"repositories"`
		}
		path := "/installation/repositories?per_page=100&page=" + strconv.Itoa(page)
		if _, err := g.get(ctx, path, token, &batch); err != nil {
			return nil, err
		}
		for _, repo := range batch.Repositories {
			if repo.ID <= 0 || repo.Name == "" || !strings.EqualFold(repo.Owner.Login, org) {
				return nil, errors.New("unexpected repository in the Actions App installation")
			}
			if !seen[repo.ID] {
				repositories = append(repositories, repo)
				seen[repo.ID] = true
			}
		}
		if len(batch.Repositories) < 100 {
			return repositories, nil
		}
	}
}

func (g githubClient) listActionRuns(ctx context.Context, token, repoPath string, from, to time.Time) ([]githubActionRun, error) {
	const pageSize = 30
	var all []githubActionRun
	for page := 1; ; page++ {
		query := url.Values{
			"created":  {from.Format(time.RFC3339) + ".." + to.Format(time.RFC3339)},
			"per_page": {strconv.Itoa(pageSize)},
			"page":     {strconv.Itoa(page)},
		}
		var batch struct {
			Total int               `json:"total_count"`
			Runs  []githubActionRun `json:"workflow_runs"`
		}
		if _, err := g.get(ctx, repoPath+"?"+query.Encode(), token, &batch); err != nil {
			return nil, err
		}
		if batch.Total >= 1000 {
			if from.Equal(to) {
				return nil, errors.New("GitHub limited workflow results for one second")
			}
			middle := from.Add(to.Sub(from) / 2).Truncate(time.Second)
			before, err := g.listActionRuns(ctx, token, repoPath, from, middle)
			if err != nil {
				return nil, err
			}
			after, err := g.listActionRuns(ctx, token, repoPath, middle.Add(time.Second), to)
			return append(before, after...), err
		}
		all = append(all, batch.Runs...)
		if len(batch.Runs) < pageSize {
			return all, nil
		}
	}
}

func (g githubClient) collectActions(ctx context.Context, cred *actionsCredentials, now time.Time) (actionsSnapshot, error) {
	snapshot := actionsSnapshot{SyncedAt: now.UTC()}
	token, err := g.actionsToken(ctx, cred, now)
	if err != nil {
		return snapshot, err
	}
	snapshot.Repositories, err = g.actionsRepositories(ctx, token)
	if err != nil {
		return snapshot, err
	}
	cutoff := reportingSince(now, retentionDays)
	// A run can be rerun for 30 days after its original execution.
	originalRunCutoff := cutoff.AddDate(0, 0, -30)
	for _, repo := range snapshot.Repositories {
		path := "/repos/" + org + "/" + url.PathEscape(repo.Name) + "/actions/runs"
		runs, err := g.listActionRuns(ctx, token, path, originalRunCutoff, now.UTC().Truncate(time.Second))
		if err != nil {
			return snapshot, fmt.Errorf("list Actions runs for %s: %w", repo.Name, err)
		}
		seen := make(map[int64]bool)
		for _, run := range runs {
			if run.ID <= 0 || seen[run.ID] {
				continue
			}
			seen[run.ID] = true
			for number := 1; number <= max(1, run.Attempt); number++ {
				data := run
				if run.Attempt > 1 {
					attemptPath := fmt.Sprintf("%s/%d/attempts/%d", path, run.ID, number)
					status, err := g.get(ctx, attemptPath, token, &data)
					if status == http.StatusNotFound {
						snapshot.UnavailableHistory++
						continue
					}
					if err != nil {
						return snapshot, fmt.Errorf("read Actions attempt in %s: %w", repo.Name, err)
					}
				}
				if data.Created.Before(cutoff) {
					continue
				}
				actor := data.Actor
				if number > 1 {
					actor = data.Triggerer
				}
				snapshot.Attempts = append(snapshot.Attempts, actionsAttempt{
					RepositoryID: repo.ID, RunID: run.ID, Attempt: number, Workflow: run.Name,
					Event: run.Event, Status: data.Status, Result: data.Result, Created: data.Created.UTC(), Actor: actor,
					CommitSHA: run.HeadSHA, CommitAuthor: run.Commit.Author.Name, Committer: run.Commit.Committer.Name,
				})
			}
		}
	}
	return snapshot, nil
}

func (a *app) syncActions(ctx context.Context) {
	ticker := time.NewTicker(actionsSyncInterval)
	defer ticker.Stop()
	for {
		deadline, cancel := context.WithTimeout(ctx, 5*time.Minute)
		snapshot, err := a.github.collectActions(deadline, a.cfg.actions, time.Now())
		if err == nil {
			err = a.store.saveActionsSnapshot(deadline, snapshot)
			if err == nil {
				a.actionsSynced.Store(true)
			}
		}
		cancel()
		a.actionsSyncFailed.Store(err != nil)
		if err != nil && ctx.Err() == nil {
			log.Printf("could not sync GitHub Actions statistics: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
