// These tests cover request budgets, local Caddy client addresses, and rejection safety.
// They exercise the OAuth middleware with controlled time and mock providers.
package mediator

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"token-mediator/internal/session"
)

// ---------- Request counters ----------

func TestRateLimiter(t *testing.T) {
	limiter := newRateLimiter(2, 2)
	now := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		ip      string
		elapsed time.Duration
		wait    time.Duration
	}{
		{"192.0.2.1", 0, 0},
		{"192.0.2.1", time.Second, 0},
		{"192.0.2.1", 1500 * time.Millisecond, 58500 * time.Millisecond},
		{"192.0.2.2", 2 * time.Second, 0},
		{"192.0.2.3", 3 * time.Second, 57 * time.Second},
		{"192.0.2.2", 4 * time.Second, 0},
		{"192.0.2.1", 59900 * time.Millisecond, 100 * time.Millisecond},
		{"192.0.2.3", time.Minute, 0},
		{"192.0.2.1", time.Minute, 0},
		{"192.0.2.3", time.Minute, 0},
		{"192.0.2.2", 61 * time.Second, 59 * time.Second},
		{"192.0.2.2", 3 * time.Minute, 0},
	} {
		if got := limiter.allow(netip.MustParseAddr(tc.ip), now.Add(tc.elapsed)); got != tc.wait {
			t.Fatalf("%s at %s: wait = %s, want %s", tc.ip, tc.elapsed, got, tc.wait)
		}
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	limiter := newRateLimiter(25, 1)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	now := time.Now()
	for range 100 {
		wg.Go(func() {
			if limiter.allow(netip.MustParseAddr("192.0.2.1"), now) == 0 {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if got := admitted.Load(); got != 25 {
		t.Fatalf("admitted = %d, want 25", got)
	}
}

// ---------- Client addresses ----------

func TestClientIP(t *testing.T) {
	for _, tc := range []struct {
		name, peer string
		forwarded  []string
		want       string
	}{
		{"direct IPv4", "192.0.2.1:1234", nil, "192.0.2.1"},
		{"direct IPv6", "[2001:db8:2::1]:1234", nil, "2001:db8:2::1"},
		{"mapped IPv4", "[::ffff:192.0.2.1]:1234", nil, "192.0.2.1"},
		{"scoped peer", "[fe80::1%eth0]:1234", nil, "fe80::1"},
		{"untrusted header", "192.0.2.1:1234", []string{"198.51.100.1"}, "192.0.2.1"},
		{"untrusted malformed header", "192.0.2.1:1234", []string{"invalid"}, "192.0.2.1"},
		{"invalid peer", "invalid", nil, ""},
		{"direct local IPv4", "127.0.0.1:1234", nil, "127.0.0.1"},
		{"direct local IPv6", "[::1]:1234", nil, "::1"},
		{"local Caddy", "127.0.0.1:1234", []string{" 192.0.2.1 "}, "192.0.2.1"},
		{"mapped loopback", "[::ffff:127.0.0.1]:1234", []string{"192.0.2.1"}, "192.0.2.1"},
		{"mapped forwarded IP", "127.0.0.1:1234", []string{"::ffff:192.0.2.1"}, "192.0.2.1"},
		{"IPv6 Caddy and client", "[::1]:1234", []string{"2001:db8:2::1"}, "2001:db8:2::1"},
		{"local client through Caddy", "127.0.0.1:1234", []string{"127.0.0.1"}, "127.0.0.1"},
		{"empty forwarded IP", "127.0.0.1:1234", []string{""}, ""},
		{"malformed forwarded IP", "127.0.0.1:1234", []string{"invalid"}, ""},
		{"multiple header values", "127.0.0.1:1234", []string{"192.0.2.1", "192.0.2.2"}, ""},
		{"proxy chain", "127.0.0.1:1234", []string{"192.0.2.1, 10.0.0.2"}, ""},
		{"scoped forwarded IP", "127.0.0.1:1234", []string{"fe80::1%eth0"}, ""},
		{"forwarded port", "127.0.0.1:1234", []string{"192.0.2.1:1234"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			for _, value := range tc.forwarded {
				req.Header.Add("X-Forwarded-For", value)
			}
			got, ok := clientIP(req)
			if tc.want == "" {
				if ok {
					t.Fatalf("accepted invalid client IP: %s", got)
				}
			} else if !ok || got != netip.MustParseAddr(tc.want) {
				t.Fatalf("client IP = %s, valid = %v, want %s", got, ok, tc.want)
			}
		})
	}
}

// ---------- HTTP behavior ----------

func TestRateLimit_CaddyIdentity(t *testing.T) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.FeOrigin = "https://frontend.example"
	cfg.RateLimitPerMinute = 1
	cfg.RateLimitMaxIPs = 3
	handler := NewServer(cfg, nil).routes()
	for _, tc := range []struct {
		peer      string
		forwarded []string
		status    int
	}{
		{"127.0.0.1:1234", []string{""}, 400},
		{"127.0.0.1:1234", []string{"invalid"}, 400},
		{"127.0.0.1:1234", []string{"198.51.100.1, 192.0.2.1"}, 400},
		{"127.0.0.1:1234", []string{"192.0.2.1", "192.0.2.2"}, 400},
		{"127.0.0.1:1234", []string{"192.0.2.1"}, 404},
		{"127.0.0.1:5678", []string{"::ffff:192.0.2.1"}, 429},
		{"127.0.0.1:1234", []string{"192.0.2.2"}, 404},
		{"[::1]:1234", []string{"192.0.2.2"}, 429},
		{"127.0.0.1:1234", nil, 404},
		{"127.0.0.1:5678", nil, 429},
	} {
		req := browserRequest("/oauth/unknown/token", "{}")
		req.RemoteAddr = tc.peer
		for _, value := range tc.forwarded {
			req.Header.Add("X-Forwarded-For", value)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("peer %s, forwarded %q: status = %d, want %d", tc.peer, tc.forwarded, rec.Code, tc.status)
		}
		if tc.status == http.StatusBadRequest && (rec.Body.String() != "{\"error\":\"invalid_request\"}\n" || rec.Header().Get("Retry-After") != "") {
			t.Fatal("invalid proxy information did not receive a sanitized request error")
		}
	}
}

func TestRateLimit_SharedRoutesAndExemptions(t *testing.T) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.FeOrigin = "https://frontend.example"
	cfg.RateLimitPerMinute = 1
	cfg.RateLimitMaxIPs = 2
	store := session.NewStore(1)
	srv := NewServer(cfg, store)
	handler := srv.routes()
	first := browserRequest("/oauth/github/token", "{}")
	first.RemoteAddr = "192.0.2.1:1000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, first)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("first request = %d, want 401", rec.Code)
	}
	for _, path := range []string{"/oauth/github/start", "/oauth/google/token", "/oauth/github/callback?code=code&state=state"} {
		req := browserRequest(path, "{}")
		req.RemoteAddr = "[::ffff:192.0.2.1]:2000"
		callback := path == "/oauth/github/callback?code=code&state=state"
		if callback {
			req.Method = http.MethodGet
		}
		before := time.Now()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		after := time.Now()
		if rec.Code != http.StatusTooManyRequests || rec.Body.String() != "{\"error\":\"rate_limited\"}\n" {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		seconds, err := strconv.Atoi(rec.Header().Get("Retry-After"))
		minSeconds := int((srv.limiter.resetAt.Sub(after) + time.Second - 1) / time.Second)
		maxSeconds := int((srv.limiter.resetAt.Sub(before) + time.Second - 1) / time.Second)
		if err != nil || seconds < 1 || seconds < minSeconds || seconds > maxSeconds {
			t.Fatalf("Retry-After = %q, want %d..%d", rec.Header().Get("Retry-After"), minSeconds, maxSeconds)
		}
		if len(rec.Result().Cookies()) != 0 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatal("rejection set a cookie or lost response protections")
		}
		if callback {
			if rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("callback rejection lost referrer protection")
			}
		} else if rec.Header().Get("Access-Control-Allow-Origin") != cfg.FeOrigin || rec.Header().Get("Access-Control-Allow-Credentials") != "true" || rec.Header().Get("Access-Control-Expose-Headers") != "Retry-After" || rec.Header().Get("Vary") != "Origin" {
			t.Fatal("rejection lost browser CORS headers")
		}
	}
	if _, err := store.Create(time.Hour); err != nil {
		t.Fatal("rejected authorization start created a session")
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/health", 200},
		{http.MethodOptions, "/oauth/github/start", 204},
		{http.MethodOptions, "/oauth/github/token", 204},
		{http.MethodOptions, "/session/logout", 204},
		{http.MethodPost, "/session/logout", 204},
	} {
		req := browserRequest(tc.path, "{}")
		req.Method = tc.method
		req.RemoteAddr = "192.0.2.1:3000"
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status || rec.Header().Get("Retry-After") != "" {
			t.Fatalf("exempt %s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
	for _, tc := range []struct {
		ip     string
		status int
	}{
		{"192.0.2.2:1000", 401},
		{"192.0.2.3:1000", 429},
	} {
		req := browserRequest("/oauth/github/token", "{}")
		req.RemoteAddr = tc.ip
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("%s: %d, want %d", tc.ip, rec.Code, tc.status)
		}
	}
}

func TestRateLimit_BrowserValidationFirst(t *testing.T) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.FeOrigin = "https://frontend.example"
	cfg.RateLimitPerMinute = 1
	handler := NewServer(cfg, nil).routes()
	for _, tc := range []struct {
		body, header, value string
		status              int
	}{
		{"{}", "Origin", "https://evil.example", 403},
		{"{}", "X-OAuth-Bridge", "", 403},
		{"{", "", "", 400},
		{"{}", "", "", 404},
		{"{}", "", "", 429},
	} {
		req := browserRequest("/oauth/unknown/token", tc.body)
		if tc.header != "" {
			req.Header.Set(tc.header, tc.value)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("status = %d, want %d", rec.Code, tc.status)
		}
	}
}

func TestRateLimit_RejectedOAuthPreservesState(t *testing.T) {
	for _, operation := range []string{"callback", "token"} {
		t.Run(operation, func(t *testing.T) {
			provider, calls := newMockOAuthServer(t)
			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg.FeOrigin = "https://frontend.example"
			cfg.RateLimitPerMinute = 1
			p := cfg.Providers["github"]
			p.TokenUrl = provider.URL + "/token"
			cfg.Providers["github"] = p
			store := session.NewStore(1)
			id, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			original := session.Connection{Provider: "github", AccessToken: "old", RefreshToken: "private-refresh", ExpiresAt: time.Now().Add(-time.Second)}
			if !store.SaveConnection(id, original) || !store.SetPendingAuth(id, session.PendingAuth{Provider: "github", State: "state", PKCEVerifier: "verifier", CreatedAt: time.Now()}) {
				t.Fatal("could not prepare session")
			}
			srv := NewServer(cfg, store)
			handler := srv.routes()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, browserRequest("/oauth/github/token", "{}"))
			if rec.Code != 401 {
				t.Fatalf("initial request = %d", rec.Code)
			}
			req := browserRequest("/oauth/github/token", "{}")
			if operation == "callback" {
				req = httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=code&state=state", nil)
			}
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 429 || len(calls) != 0 || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("rejected %s: status = %d, provider calls = %d", operation, rec.Code, len(calls))
			}
			if got, ok := store.GetConnection(id, "github"); !ok || got != original {
				t.Fatal("rejection changed the provider connection")
			}
			// A different IP can finish the same attempt without waiting for the rate window.
			retry := browserRequest("/oauth/github/token", "{}")
			if operation == "callback" {
				retry = httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=code&state=state", nil)
			}
			retry.RemoteAddr = "192.0.2.2:1234"
			retry.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, retry)
			want := http.StatusOK
			if operation == "callback" {
				want = http.StatusSeeOther
			}
			if rec.Code != want || len(calls) != 1 {
				t.Fatalf("retry %s: status = %d, provider calls = %d", operation, rec.Code, len(calls))
			}
		})
	}
}
