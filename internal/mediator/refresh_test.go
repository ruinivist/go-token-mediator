// These tests verify automatic refresh, rotation, and upstream failure handling.
// They exercise the browser token route against controlled OAuth providers.
package mediator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"token-mediator/internal/session"
)

// ---------- Refresh behavior ----------

func TestProviderToken_Refresh(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		lifetime                    time.Duration
		noRefresh                   bool
		body                        string
		wantRefresh                 bool
		wantScope, wantRefreshToken string
		unknownExpiry               bool
	}{
		{name: "unknown expiry", wantScope: "old-scope", wantRefreshToken: "private-refresh", unknownExpiry: true},
		{name: "outside margin", lifetime: 2*time.Minute + time.Second, wantScope: "old-scope", wantRefreshToken: "private-refresh"},
		{name: "at margin", lifetime: 2 * time.Minute, body: `{"access_token":"new","token_type":"bearer","refresh_token":"rotated","scope":"new-scope","expires_in":3600}`, wantRefresh: true, wantScope: "new-scope", wantRefreshToken: "rotated"},
		{name: "near expiry", lifetime: time.Minute, body: `{"access_token":"new","expires_in":3600}`, wantRefresh: true, wantScope: "old-scope", wantRefreshToken: "private-refresh"},
		{name: "expired", lifetime: -time.Second, body: `{"access_token":"new","expires_in":3600}`, wantRefresh: true, wantScope: "old-scope", wantRefreshToken: "private-refresh"},
		{name: "omitted metadata", lifetime: time.Minute, body: `{"access_token":"new"}`, wantRefresh: true, wantScope: "old-scope", wantRefreshToken: "private-refresh", unknownExpiry: true},
		{name: "explicit empty scope", lifetime: time.Minute, body: `{"access_token":"new","scope":"","expires_in":3600}`, wantRefresh: true, wantRefreshToken: "private-refresh"},
		{name: "no refresh token", lifetime: time.Minute, noRefresh: true, wantScope: "old-scope"},
		{name: "response at limit", lifetime: time.Minute, body: `{"access_token":"new"}` + strings.Repeat(" ", (64<<10)-len(`{"access_token":"new"}`)), wantRefresh: true, wantScope: "old-scope", wantRefreshToken: "private-refresh", unknownExpiry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
					t.Errorf("bad refresh request headers: %v", r.Header)
				}
				if len(r.PostForm) != 4 || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "private-refresh" || r.PostForm.Get("client_id") != "client" || r.PostForm.Get("client_secret") != "private-secret" {
					t.Errorf("incorrect refresh form fields")
				}
				io.WriteString(w, tc.body)
			}))
			defer provider.Close()
			store, id, handler := refreshFixture(t, provider.URL, tc.lifetime, !tc.noRefresh)
			req := browserRequest("/oauth/mock/token", "{}")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			wantCalls := int32(0)
			wantToken := "old"
			if tc.wantRefresh {
				wantCalls = 1
				wantToken = "new"
			}
			if calls.Load() != wantCalls {
				t.Fatalf("refresh calls = %d, want %d", calls.Load(), wantCalls)
			}
			conn, ok := store.GetConnection(id, "mock")
			if !ok || conn.AccessToken != wantToken || conn.RefreshToken != tc.wantRefreshToken || conn.Scopes != tc.wantScope {
				t.Fatalf("stored refresh fields did not match")
			}
			if tc.unknownExpiry != conn.ExpiresAt.IsZero() {
				t.Fatal("incorrect stored expiry")
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["access_token"] != wantToken || body["token_type"] != "Bearer" {
				t.Fatal("incorrect browser token")
			}
			for key := range body {
				if key != "access_token" && key != "token_type" && key != "expires_in" && key != "scope" {
					t.Errorf("unexpected browser field: %s", key)
				}
			}
			if tc.unknownExpiry {
				if _, ok := body["expires_in"]; ok {
					t.Fatal("returned unknown expiry")
				}
			} else {
				want := tc.lifetime.Seconds()
				if tc.wantRefresh {
					want = 3600
				}
				got, ok := body["expires_in"].(float64)
				if !ok || got > want || got < want-2 {
					t.Errorf("remaining lifetime = %v, want near %v", got, want)
				}
			}
			if tc.wantScope == "" {
				if _, ok := body["scope"]; ok {
					t.Fatal("returned empty scope")
				}
			} else if body["scope"] != tc.wantScope {
				t.Fatal("incorrect browser scope")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
			if tc.wantRefresh && tc.unknownExpiry {
				again := httptest.NewRecorder()
				handler.ServeHTTP(again, browserTokenRequest(id))
				if again.Code != 200 || calls.Load() != 1 {
					t.Fatal("unknown expiry was not cached")
				}
			}
		})
	}
}

func TestProviderToken_ConcurrentRefresh(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		io.WriteString(w, `{"access_token":"shared","refresh_token":"rotated","expires_in":3600}`)
	}))
	defer provider.Close()
	_, id, handler := refreshFixture(t, provider.URL, time.Minute, true)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, browserTokenRequest(id))
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Error(err)
				return
			}
			if rec.Code != 200 || body["access_token"] != "shared" {
				t.Errorf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
	<-started
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("refreshes = %d, want 1", calls.Load())
	}
}

// ---------- Failure and credential isolation ----------

func TestProviderToken_RefreshFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantStatus int
		remove     bool
	}{
		{"invalid grant", 400, `{"error":"invalid_grant","error_description":"private-secret"}`, 401, true},
		{"invalid grant with 200", 200, `{"error":"invalid_grant"}`, 401, true},
		{"other oauth error", 400, `{"error":"invalid_client"}`, 502, false},
		{"oauth error with 200", 200, `{"error":"temporarily_unavailable"}`, 502, false},
		{"upstream failure", 500, `private-secret`, 502, false},
		{"malformed success", 200, `{`, 502, true},
		{"null", 200, `null`, 502, true},
		{"array", 200, `[]`, 502, true},
		{"trailing json", 200, `{"access_token":"new"} {}`, 502, true},
		{"empty token", 200, `{"access_token":""}`, 502, true},
		{"unsupported token type", 200, `{"access_token":"new","token_type":"MAC"}`, 502, true},
		{"empty token type", 200, `{"access_token":"new","token_type":""}`, 502, true},
		{"empty refresh token", 200, `{"access_token":"new","refresh_token":""}`, 502, true},
		{"zero lifetime", 200, `{"access_token":"new","expires_in":0}`, 502, true},
		{"negative lifetime", 200, `{"access_token":"new","expires_in":-1}`, 502, true},
		{"overflow lifetime", 200, `{"access_token":"new","expires_in":9223372036854775807}`, 502, true},
		{"wrong shape", 200, `{"access_token":"new","scope":[]}`, 502, true},
		{"oversized", 200, `{"access_token":"new"}` + strings.Repeat(" ", 64<<10), 502, true},
		{"transport", 0, "", 502, true},
		{"timeout", -1, "", 504, true},
		{"redirect", 307, "", 502, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirected" {
					t.Error("followed token redirect")
					w.WriteHeader(500)
					return
				}
				calls.Add(1)
				switch tc.status {
				case 0:
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
				case -1:
					io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
				case 307:
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(307)
				default:
					w.WriteHeader(tc.status)
					io.WriteString(w, tc.body)
				}
			}))
			defer provider.Close()
			store, id, handler := refreshFixture(t, provider.URL, time.Minute, true)
			req := browserRequest("/oauth/mock/token", "{}")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			if tc.status == -1 {
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				req = req.WithContext(ctx)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "private") {
				t.Fatal("exposed provider details")
			}
			if calls.Load() > 1 {
				t.Fatal("retried refresh")
			}
			conn, ok := store.GetConnection(id, "mock")
			if ok == tc.remove {
				t.Fatalf("connection exists = %v, remove = %v", ok, tc.remove)
			}
			if ok && (conn.AccessToken != "old" || conn.RefreshToken != "private-refresh") {
				t.Fatal("changed credentials on failure")
			}
			if _, ok := store.GetConnection(id, "other"); !ok {
				t.Fatal("removed unrelated connection")
			}
			if tc.remove {
				again := httptest.NewRecorder()
				handler.ServeHTTP(again, browserTokenRequest(id))
				if again.Code != 401 || calls.Load() > 1 {
					t.Fatal("retried unusable refresh token")
				}
			}
		})
	}
}

// ---------- Fixtures ----------

func browserTokenRequest(id session.ID) *http.Request {
	req := browserRequest("/oauth/mock/token", "{}")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
	return req
}

func refreshFixture(t *testing.T, tokenURL string, lifetime time.Duration, refresh bool) (*session.Store, session.ID, http.Handler) {
	t.Helper()
	store := session.NewStore()
	id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	conn := session.Connection{Provider: "mock", AccessToken: "old", Scopes: "old-scope"}
	if refresh {
		conn.RefreshToken = "private-refresh"
	}
	if lifetime != 0 {
		conn.ExpiresAt = time.Now().Add(lifetime)
	}
	if !store.SaveConnection(id, conn) || !store.SaveConnection(id, session.Connection{Provider: "other", AccessToken: "unrelated"}) {
		t.Fatal("save connection failed")
	}
	cfg := &Config{FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {ClientId: "client", ClientSecret: "private-secret", TokenUrl: tokenURL}}}
	return store, id, NewServer(cfg, store).routes()
}
