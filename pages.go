package main

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type page struct {
	Title         string
	ArticleOrigin string
	OAuthReady    bool
	User          identity
	Core          bool
	CSRF          string
	Problem       string
	Description   string
	Article       string
	BackToArticle string
	Recorded      bool
	AccessSaved   bool
	Period        int
	Totals        totals
	Articles      []articleTotals
	Readings      []reading
	Owners        []ownerRow
	Prev          string
	Next          string
}

type ownerRow struct {
	identity
	Core    bool
	Blocked bool
}

func (a *app) render(w http.ResponseWriter, name string, status int, data page) {
	data.ArticleOrigin = a.cfg.articleOrigin
	data.OAuthReady = a.cfg.clientID != ""
	var body bytes.Buffer
	if err := a.templates.ExecuteTemplate(&body, name, data); err != nil {
		log.Printf("render template %s: %v", name, err)
		http.Error(w, "页面暂时无法显示", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

func (a *app) problem(w http.ResponseWriter, status int, title, description string) {
	a.render(w, "problem", status, page{Title: title, Problem: title, Description: description})
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	s, signedIn := a.auth.getSession(a.cookie(r, "admin"))
	if signedIn && s.token != "" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	a.render(w, "home", http.StatusOK, page{Title: "阅读统计"})
}

func (a *app) privacy(w http.ResponseWriter, _ *http.Request) {
	a.render(w, "privacy", http.StatusOK, page{Title: "阅读数据说明"})
}

func dashboardURL(period int, article string, index int) string {
	q := url.Values{"days": {strconv.Itoa(period)}, "page": {strconv.Itoa(index)}}
	if article != "" {
		q.Set("article", article)
	}
	return "/dashboard?" + q.Encode()
}

func (a *app) dashboard(w http.ResponseWriter, r *http.Request) {
	s, ok := a.admin(w, r, false)
	if !ok {
		return
	}
	query := r.URL.Query()
	period, _ := strconv.Atoi(query.Get("days"))
	switch period {
	case 7, 30, 90:
	default:
		period = 30
	}
	article := query.Get("article")
	if article != "" && !validArticle(article) {
		a.problem(w, http.StatusBadRequest, "文章地址有误", "请从阅读统计列表选择文章。")
		return
	}
	index, _ := strconv.Atoi(query.Get("page"))
	if index < 1 || index > 20000 {
		index = 1
	}
	ctx := r.Context()
	cutoff := sinceDay(time.Now(), period)
	sum, err := a.store.summary(ctx, cutoff, article)
	if err != nil {
		a.storeError(w)
		return
	}
	grouped, err := a.store.articles(ctx, cutoff)
	if err != nil {
		a.storeError(w)
		return
	}
	readings, err := a.store.readings(ctx, cutoff, article, (index-1)*50)
	if err != nil {
		a.storeError(w)
		return
	}
	data := page{
		Title: "阅读统计", User: s.user, Core: isCore(s.user.ID), CSRF: s.csrf,
		Period: period, Article: article, Totals: sum, Articles: grouped, Readings: readings,
	}
	if index > 1 {
		data.Prev = dashboardURL(period, article, index-1)
	}
	if len(readings) > 50 {
		data.Readings = readings[:50]
		data.Next = dashboardURL(period, article, index+1)
	}
	a.render(w, "dashboard", http.StatusOK, data)
}

func (a *app) storeError(w http.ResponseWriter) {
	a.problem(w, http.StatusServiceUnavailable, "统计暂时不可用", "请稍后刷新页面。")
}

func (a *app) access(w http.ResponseWriter, r *http.Request) {
	s, ok := a.admin(w, r, true)
	if !ok {
		return
	}
	owners, err := a.github.owners(r.Context(), s.token)
	if err != nil {
		a.problem(w, http.StatusServiceUnavailable, "无法读取组织管理员", "请稍后重试。")
		return
	}
	sort.Slice(owners, func(i, j int) bool {
		return strings.ToLower(owners[i].Login) < strings.ToLower(owners[j].Login)
	})
	access := make([]ownerRow, 0, len(owners))
	for _, owner := range owners {
		blocked, err := a.store.isBlocked(r.Context(), owner.ID)
		if err != nil {
			a.storeError(w)
			return
		}
		access = append(access, ownerRow{owner, isCore(owner.ID), blocked})
	}
	a.render(w, "access", http.StatusOK, page{
		Title: "访问权限", User: s.user, Core: true, CSRF: s.csrf, Owners: access,
		AccessSaved: r.URL.Query().Get("updated") == "1",
	})
}

func (a *app) changeAccess(w http.ResponseWriter, r *http.Request) {
	s, ok := a.admin(w, r, true)
	if !ok || !a.formOK(w, r, s) {
		return
	}
	target, err := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	change := r.PostForm.Get("change")
	if err != nil || target <= 0 || isCore(target) || (change != "block" && change != "restore") {
		a.problem(w, http.StatusBadRequest, "无法更新此账号", "请选择其他组织管理员。")
		return
	}
	owners, err := a.github.owners(r.Context(), s.token)
	if err != nil {
		a.problem(w, http.StatusServiceUnavailable, "无法读取组织管理员", "请稍后重试。")
		return
	}
	for _, owner := range owners {
		if owner.ID == target {
			if err := a.store.setBlocked(r.Context(), target, s.user.ID, change == "block"); err != nil {
				a.storeError(w)
				return
			}
			http.Redirect(w, r, "/access?updated=1", http.StatusSeeOther)
			return
		}
	}
	a.problem(w, http.StatusBadRequest, "账号不在管理员列表", "请刷新 GitHub 组织权限列表。")
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	key := a.cookie(r, "admin")
	s, ok := a.auth.getSession(key)
	if ok && !a.formOK(w, r, s) {
		return
	}
	a.auth.deleteSession(key)
	a.setCookie(w, "admin", "", -time.Second)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) read(w http.ResponseWriter, r *http.Request) {
	if recorded := r.URL.Query().Get("recorded"); validArticle(recorded) {
		a.render(w, "read", http.StatusOK, page{
			Title: "阅读记录", BackToArticle: a.cfg.articleOrigin + recorded, Recorded: true,
		})
		return
	}
	s, ok := a.auth.getSession(a.cookie(r, "reader"))
	if !ok || s.article == "" {
		a.problem(w, http.StatusUnauthorized, "阅读确认已过期", "请回到文章重新用 GitHub 发起确认。")
		return
	}
	a.render(w, "read", http.StatusOK, page{
		Title: "确认阅读记录", User: s.user, CSRF: s.csrf, Article: s.article,
		BackToArticle: a.cfg.articleOrigin + s.article,
	})
}

func (a *app) record(w http.ResponseWriter, r *http.Request) {
	key := a.cookie(r, "reader")
	s, ok := a.auth.getSession(key)
	if !ok || s.article == "" {
		a.problem(w, http.StatusUnauthorized, "阅读确认已过期", "请回到文章重新用 GitHub 发起确认。")
		return
	}
	if !a.formOK(w, r, s) {
		return
	}
	if err := a.store.recordRead(r.Context(), s.article, day(time.Now()), s.user); err != nil {
		a.storeError(w)
		return
	}
	a.auth.deleteSession(key)
	a.setCookie(w, "reader", "", -time.Second)
	http.Redirect(w, r, "/read?recorded="+url.QueryEscape(s.article), http.StatusSeeOther)
}
