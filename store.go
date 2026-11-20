package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA busy_timeout = 5000;
		PRAGMA secure_delete = ON;
		CREATE TABLE IF NOT EXISTS article_views (
			path TEXT NOT NULL,
			day TEXT NOT NULL,
			views INTEGER NOT NULL,
			PRIMARY KEY (path, day)
		);
		CREATE TABLE IF NOT EXISTS reading_records (
			path TEXT NOT NULL,
			day TEXT NOT NULL,
			github_id INTEGER NOT NULL,
			login TEXT NOT NULL,
			PRIMARY KEY (path, day, github_id)
		);
		CREATE TABLE IF NOT EXISTS blocked_owners (
			github_id INTEGER PRIMARY KEY,
			blocked_by INTEGER NOT NULL,
			blocked_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS actions_snapshot (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			snapshot TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS site_daily_views (
			site TEXT NOT NULL,
			path TEXT NOT NULL,
			day TEXT NOT NULL,
			views INTEGER NOT NULL,
			PRIMARY KEY (site, path, day)
		);
		CREATE TABLE IF NOT EXISTS site_visit_details (
			id INTEGER PRIMARY KEY,
			site TEXT NOT NULL,
			path TEXT NOT NULL,
			ip TEXT NOT NULL,
			referrer TEXT NOT NULL,
			visited_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS site_daily_views_day ON site_daily_views(day);
		CREATE INDEX IF NOT EXISTS site_visit_details_time ON site_visit_details(visited_at);
		CREATE INDEX IF NOT EXISTS article_views_day ON article_views(day);
		CREATE INDEX IF NOT EXISTS reading_records_day ON reading_records(day);
	`); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db: db}, nil
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func sinceDay(t time.Time, days int) string { return day(t.UTC().AddDate(0, 0, 1-days)) }

func (s *store) prune(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	cutoff := sinceDay(now, retentionDays)
	if _, err = tx.ExecContext(ctx, "DELETE FROM article_views WHERE day < ?", cutoff); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM reading_records WHERE day < ?", cutoff); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM site_visit_details WHERE visited_at < ?", now.Add(-visitIPRetention).Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM site_daily_views WHERE day < ?", reportingSince(now, retentionDays).In(reportingTimeZone).Format("2006-01-02")); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *store) countView(ctx context.Context, path, date string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO article_views (path, day, views) VALUES (?, ?, 1)
		ON CONFLICT (path, day) DO UPDATE SET views = views + 1`, path, date)
	return err
}

func (s *store) recordRead(ctx context.Context, path, date string, user identity) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO reading_records (path, day, github_id, login) VALUES (?, ?, ?, ?)
		ON CONFLICT (path, day, github_id) DO UPDATE SET login = excluded.login`, path, date, user.ID, user.Login)
	return err
}

type articleTotals struct {
	Path    string
	Views   int
	Readers int
}

type reading struct {
	Path  string
	Day   string
	Login string
}

type totals struct {
	Views   int
	Readers int
	Records int
}

func (s *store) summary(ctx context.Context, since, path string) (totals, error) {
	var result totals
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT coalesce(sum(views),0) FROM article_views WHERE day >= ?1 AND (?2 = '' OR path = ?2)),
		count(DISTINCT github_id), count(*)
		FROM reading_records WHERE day >= ?1 AND (?2 = '' OR path = ?2)`, since, path).
		Scan(&result.Views, &result.Readers, &result.Records)
	return result, err
}

func (s *store) articles(ctx context.Context, since string) ([]articleTotals, error) {
	rows, err := s.db.QueryContext(ctx, `WITH
		views AS (SELECT path, sum(views) AS total FROM article_views WHERE day >= ?1 GROUP BY path),
		readers AS (SELECT path, count(DISTINCT github_id) AS total FROM reading_records WHERE day >= ?1 GROUP BY path),
		paths AS (SELECT path FROM views UNION SELECT path FROM readers)
		SELECT paths.path, coalesce(views.total,0), coalesce(readers.total,0)
		FROM paths LEFT JOIN views USING (path) LEFT JOIN readers USING (path)
		ORDER BY 2 DESC, 3 DESC, 1 LIMIT 100`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []articleTotals
	for rows.Next() {
		var article articleTotals
		if err := rows.Scan(&article.Path, &article.Views, &article.Readers); err != nil {
			return nil, err
		}
		result = append(result, article)
	}
	return result, rows.Err()
}

func (s *store) readings(ctx context.Context, since, path string, offset int) ([]reading, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT path, day, login FROM reading_records
		WHERE day >= ? AND (? = '' OR path = ?)
		ORDER BY day DESC, path, login COLLATE NOCASE, github_id LIMIT 51 OFFSET ?`, since, path, path, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []reading
	for rows.Next() {
		var entry reading
		if err := rows.Scan(&entry.Path, &entry.Day, &entry.Login); err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}

func (s *store) isBlocked(ctx context.Context, id int64) (bool, error) {
	var blocked bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM blocked_owners WHERE github_id = ?)", id).Scan(&blocked)
	return blocked, err
}

func (s *store) setBlocked(ctx context.Context, id, actor int64, blocked bool) error {
	if blocked {
		_, err := s.db.ExecContext(ctx, `INSERT INTO blocked_owners VALUES (?, ?, ?)
			ON CONFLICT (github_id) DO UPDATE SET blocked_by = excluded.blocked_by, blocked_at = excluded.blocked_at`,
			id, actor, time.Now().UTC().Format(time.RFC3339))
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM blocked_owners WHERE github_id = ?", id)
	return err
}

func (s *store) saveActionsSnapshot(ctx context.Context, snapshot actionsSnapshot) error {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO actions_snapshot (id, snapshot) VALUES (1, ?)
		ON CONFLICT (id) DO UPDATE SET snapshot = excluded.snapshot`, string(payload))
	return err
}

func (s *store) actionsSnapshot(ctx context.Context) (actionsSnapshot, error) {
	var snapshot actionsSnapshot
	var payload string
	err := s.db.QueryRowContext(ctx, "SELECT snapshot FROM actions_snapshot WHERE id = 1").Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	err = json.Unmarshal([]byte(payload), &snapshot)
	return snapshot, err
}
