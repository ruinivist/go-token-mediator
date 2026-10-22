package mediator

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"token-mediator/internal/session"
)

func browserRequest(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Origin", "https://frontend.example")
	req.Header.Set("X-OAuth-Bridge", "1")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestSessionLogout(t *testing.T) {
	for _, state := range []string{"active", "missing cookie", "unknown", "expired", "deleted"} {
		t.Run(state, func(t *testing.T) {
			store, id, handler := refreshFixture(t, "", time.Hour, false)
			otherID, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if !store.SetPendingAuth(id, session.PendingAuth{Provider: "mock", State: "state", CreatedAt: time.Now()}) {
				t.Fatal("set pending auth failed")
			}
			switch state {
			case "unknown":
				id = "unknown"
			case "expired":
				id, err = store.Create(-time.Second)
				if err != nil {
					t.Fatal(err)
				}
			case "deleted":
				store.Delete(id)
			}
			for range 2 {
				req := browserRequest("/session/logout", "{}")
				if state != "missing cookie" {
					req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
					t.Fatalf("logout status = %d, body = %s", rec.Code, rec.Body.String())
				}
				cookies := rec.Result().Cookies()
				if len(cookies) != 1 {
					t.Fatalf("cookies = %v, want one clearing cookie", cookies)
				}
				c := cookies[0]
				if c.Name != sessionCookieName || c.Value != "" || c.MaxAge != -1 || c.Expires.IsZero() || !c.Expires.Before(time.Now()) || c.Path != "/" || c.Domain != "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
					t.Fatalf("invalid clearing cookie: %+v", c)
				}
				if !store.Has(otherID) {
					t.Fatal("logout deleted another session")
				}
				if state == "missing cookie" {
					if !store.Has(id) {
						t.Fatal("logout without cookie deleted a session")
					}
					continue
				}
				if store.Has(id) {
					t.Fatal("session survived logout")
				}
				for _, provider := range []string{"mock", "other"} {
					if _, ok := store.GetConnection(id, provider); ok {
						t.Fatal("connection survived logout")
					}
				}
				if _, ok := store.ConsumePendingAuth(id, "mock", "state"); ok {
					t.Fatal("pending authorization survived logout")
				}
				token := httptest.NewRecorder()
				handler.ServeHTTP(token, browserTokenRequest(id))
				if token.Code != http.StatusUnauthorized {
					t.Fatalf("token status after logout = %d", token.Code)
				}
			}
		})
	}
}

func TestSessionLogout_InFlightOAuth(t *testing.T) {
	for _, operation := range []string{"refresh", "callback"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-release
				io.WriteString(w, `{"access_token":"new","token_type":"Bearer","refresh_token":"rotated","expires_in":3600}`)
			}))
			defer provider.Close()
			defer unblock()
			store, id, handler := refreshFixture(t, provider.URL, time.Minute, true)
			req := browserTokenRequest(id)
			wantStatus := http.StatusUnauthorized
			if operation == "callback" {
				if !store.SetPendingAuth(id, session.PendingAuth{Provider: "mock", State: "state", PKCEVerifier: "verifier", CreatedAt: time.Now()}) {
					t.Fatal("set pending auth failed")
				}
				req = httptest.NewRequest(http.MethodGet, "/oauth/mock/callback?code=code&state=state", nil)
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
				wantStatus = http.StatusBadRequest
			}
			req = req.WithContext(t.Context())
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				result <- rec
			}()
			select {
			case <-started:
			case rec := <-result:
				t.Fatalf("OAuth request ended before exchange: %d %s", rec.Code, rec.Body.String())
			case <-time.After(5 * time.Second):
				t.Fatal("OAuth request did not reach provider")
			}
			logout := browserRequest("/session/logout", "{}")
			logout.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, logout)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("logout status = %d", rec.Code)
			}
			unblock()
			completed := <-result
			if completed.Code != wantStatus || strings.Contains(completed.Body.String(), "new") || len(completed.Result().Cookies()) != 0 {
				t.Fatalf("in-flight %s response = %d %s", operation, completed.Code, completed.Body.String())
			}
			if store.Has(id) {
				t.Fatal("in-flight OAuth restored deleted session")
			}
		})
	}
}

// Checks that a client cannot hold a POST open by leaving its body unfinished.
func TestServer_UnfinishedBody(t *testing.T) {
	cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 10000, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
	server := NewServer(cfg, session.NewStore(1000))
	if server.httpServer.ReadTimeout <= 0 {
		t.Fatal("server must have a request read timeout")
	}
	server.httpServer.ReadTimeout = 100 * time.Millisecond
	testServer := httptest.NewUnstartedServer(server.httpServer.Handler)
	testServer.Config = server.httpServer
	testServer.Start()
	defer testServer.Close()

	conn, err := net.DialTimeout("tcp", testServer.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Promise four bytes but send only two, so the handler waits for the rest.
	_, err = io.WriteString(conn, "POST /oauth/mock/start HTTP/1.1\r\n"+
		"Host: mediator.example\r\nOrigin: https://frontend.example\r\n"+
		"X-OAuth-Bridge: 1\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n{}")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("server did not reject the unfinished body: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.StatusCode)
	}
}

// Checks that each session gets its own token, only the allowed token fields, and remaining expiry.
func TestProviderToken_Response(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		scope    string
	}{
		{name: "unknown expiry"},
		{name: "remaining expiry and scope", lifetime: time.Hour, scope: "read:user,user:email"},
		{name: "less than thirty seconds", lifetime: 15 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := session.NewStore(1000)
			id, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			conn := session.Connection{Provider: "mock", AccessToken: "own-token", Scopes: tc.scope}
			if tc.lifetime > 2*time.Minute || tc.lifetime == 0 {
				conn.RefreshToken = "private-refresh"
			}
			if tc.lifetime != 0 {
				conn.ExpiresAt = time.Now().Add(tc.lifetime)
			}
			if !store.SaveConnection(id, conn) {
				t.Fatal("save connection failed")
			}
			otherID, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if !store.SaveConnection(otherID, session.Connection{Provider: "mock", AccessToken: "other-token"}) ||
				!store.SaveConnection(id, session.Connection{Provider: "other", AccessToken: "other-provider-token"}) {
				t.Fatal("save other connections failed")
			}
			cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 10000, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}, "other": {}}}
			req := browserRequest("/oauth/mock/token", "{}")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			rec := httptest.NewRecorder()
			NewServer(cfg, store).routes().ServeHTTP(rec, req)
			if rec.Header().Get("Access-Control-Allow-Origin") != cfg.FeOrigin || rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
				t.Fatal("missing credentialed CORS headers")
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unexpected headers: %v", rec.Header())
			}
			var result map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["access_token"] != "own-token" || result["token_type"] != "Bearer" {
				t.Fatalf("wrong token response: %v", result)
			}
			for key := range result {
				if key != "access_token" && key != "token_type" && key != "expires_in" && key != "scope" {
					t.Fatalf("unexpected response field: %s", key)
				}
			}
			if tc.scope == "" {
				if _, ok := result["scope"]; ok {
					t.Fatal("empty scope must be omitted")
				}
			} else if result["scope"] != tc.scope {
				t.Fatalf("scope = %v, want %q", result["scope"], tc.scope)
			}
			if tc.lifetime == 0 {
				if _, ok := result["expires_in"]; ok {
					t.Fatal("unknown expiry must be omitted")
				}
			} else {
				seconds, ok := result["expires_in"].(float64)
				want := tc.lifetime.Seconds()
				if !ok || seconds < want-2 || seconds > want {
					t.Fatalf("remaining expiry = %v, want near %v seconds", result["expires_in"], want)
				}
			}
		})
	}
}

// Checks that missing or expired sessions/connections return 401 without issuing a cookie.
func TestProviderToken_Unauthorized(t *testing.T) {
	for _, name := range []string{"missing cookie", "unknown cookie", "expired session", "deleted session", "missing connection", "other provider only", "expired token"} {
		t.Run(name, func(t *testing.T) {
			store := session.NewStore(1000)
			lifetime := time.Hour
			if name == "expired session" {
				lifetime = -time.Second
			}
			id, err := store.Create(lifetime)
			if err != nil {
				t.Fatal(err)
			}
			if name == "deleted session" {
				store.Delete(id)
			}
			if name == "expired token" {
				if !store.SaveConnection(id, session.Connection{Provider: "mock", AccessToken: "expired", ExpiresAt: time.Now().Add(-time.Second)}) {
					t.Fatal("save expired connection failed")
				}
			}
			if name == "other provider only" {
				if !store.SaveConnection(id, session.Connection{Provider: "other", AccessToken: "other-token"}) {
					t.Fatal("save other connection failed")
				}
			}
			req := browserRequest("/oauth/mock/token", "{}")
			if name == "unknown cookie" {
				id = "unknown"
			}
			if name != "missing cookie" {
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			}
			cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 10000, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
			rec := httptest.NewRecorder()
			NewServer(cfg, store).routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"reauthorization_required"}` {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected error headers: %v", rec.Header())
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Fatal("token retrieval must not set a session cookie")
			}
		})
	}
}

// Checks that browser POST routes reject invalid headers/bodies and accept valid JSON requests.
func TestValidateBrowserPost_Validation(t *testing.T) {
	for _, route := range []string{"start", "token", "logout"} {
		for _, tc := range []struct {
			name, body, header, value string
			status                    int
		}{
			{name: "missing origin", body: "{}", header: "Origin", status: 403},
			{name: "wrong origin", body: "{}", header: "Origin", value: "https://evil.example", status: 403},
			{name: "missing csrf header", body: "{}", header: "X-OAuth-Bridge", status: 403},
			{name: "wrong csrf header", body: "{}", header: "X-OAuth-Bridge", value: "0", status: 403},
			{name: "missing content type", body: "{}", header: "Content-Type", status: 400},
			{name: "form content type", body: "{}", header: "Content-Type", value: "application/x-www-form-urlencoded", status: 400},
			{name: "empty body", status: 400},
			{name: "malformed", body: "{", status: 400},
			{name: "unknown field", body: `{"force_refresh":true}`, status: 400},
			{name: "null", body: "null", status: 400},
			{name: "array", body: "[]", status: 400},
			{name: "string", body: `"hello"`, status: 400},
			{name: "trailing json", body: "{} {}", status: 400},
			{name: "trailing junk", body: "{} junk", status: 400},
			{name: "oversized body", body: "{}" + strings.Repeat(" ", 8<<10), status: 400},
			{name: "valid", body: "{}", status: map[string]int{"start": 200, "token": 401, "logout": 204}[route]},
			{name: "charset and whitespace", body: " {} \n", header: "Content-Type", value: "application/json; charset=utf-8", status: map[string]int{"start": 200, "token": 401, "logout": 204}[route]},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				store := session.NewStore(1000)
				cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 10000, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {AuthUrl: "https://provider.example/authorize"}}}
				path := "/oauth/mock/" + route
				if route == "logout" {
					path = "/session/logout"
				}
				id, err := store.Create(time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				req := browserRequest(path, tc.body)
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
				if tc.header != "" {
					req.Header.Set(tc.header, tc.value)
				}
				rec := httptest.NewRecorder()
				NewServer(cfg, store).routes().ServeHTTP(rec, req)
				if rec.Code != tc.status {
					t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.status, rec.Body.String())
				}
				if tc.status >= 400 && !store.Has(id) {
					t.Fatal("rejected request deleted the session")
				}
				if tc.status >= 400 && len(rec.Result().Cookies()) != 0 {
					t.Fatal("rejected request must not create a session cookie")
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("missing no-store header")
				}
				allowedOrigin, allowedCredentials := cfg.FeOrigin, "true"
				if tc.header == "Origin" {
					allowedOrigin, allowedCredentials = "", ""
				}
				if rec.Header().Get("Access-Control-Allow-Origin") != allowedOrigin || rec.Header().Get("Access-Control-Allow-Credentials") != allowedCredentials {
					t.Fatal("unexpected CORS permissions")
				}
				if rec.Header().Get("Vary") != "Origin" {
					t.Fatal("missing Vary: Origin")
				}
			})
		}
	}
}

func TestProviderPreflight(t *testing.T) {
	for _, route := range []string{"start", "token", "logout"} {
		for _, tc := range []struct {
			name, origin, method, provider, headers string
			status                                  int
		}{
			{name: "valid", origin: "https://frontend.example", method: "POST", provider: "mock", headers: "content-type, x-oauth-bridge", status: 204},
			{name: "no requested headers", origin: "https://frontend.example", method: "POST", provider: "mock", status: 204},
			{name: "extra requested header", origin: "https://frontend.example", method: "POST", provider: "mock", headers: "X-Untrusted", status: 204},
			{name: "missing origin", method: "POST", provider: "mock", status: 403},
			{name: "wrong origin", origin: "https://evil.example", method: "POST", provider: "mock", status: 403},
			{name: "missing method", origin: "https://frontend.example", provider: "mock", status: 403},
			{name: "wrong method", origin: "https://frontend.example", method: "DELETE", provider: "mock", status: 403},
			{name: "unknown provider", origin: "https://frontend.example", method: "POST", provider: "unknown", status: 404},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 10000, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
				path := "/oauth/" + tc.provider + "/" + route
				if route == "logout" {
					if tc.name == "unknown provider" {
						return
					}
					path = "/session/logout"
				}
				req := httptest.NewRequest(http.MethodOptions, path, nil)
				req.Header.Set("Origin", tc.origin)
				req.Header.Set("Access-Control-Request-Method", tc.method)
				req.Header.Set("Access-Control-Request-Headers", tc.headers)
				rec := httptest.NewRecorder()
				// No store is needed: preflight must never touch sessions or start OAuth.
				NewServer(cfg, nil).routes().ServeHTTP(rec, req)
				if rec.Code != tc.status {
					t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.status, rec.Body.String())
				}
				allowedOrigin, allowedCredentials := "", ""
				if tc.origin == cfg.FeOrigin {
					allowedOrigin, allowedCredentials = cfg.FeOrigin, "true"
				}
				if rec.Header().Get("Access-Control-Allow-Origin") != allowedOrigin || rec.Header().Get("Access-Control-Allow-Credentials") != allowedCredentials {
					t.Fatal("unexpected CORS permissions")
				}
				if rec.Header().Get("Vary") != "Origin" || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("missing cache controls")
				}
				if len(rec.Result().Cookies()) != 0 {
					t.Fatal("preflight must not set a cookie")
				}
				if tc.status == http.StatusNoContent {
					if rec.Body.Len() != 0 {
						t.Fatal("successful preflight must have no body")
					}
					if rec.Header().Get("Access-Control-Allow-Methods") != "POST" || rec.Header().Get("Access-Control-Allow-Headers") != "Content-Type, X-OAuth-Bridge" {
						t.Fatal("preflight must advertise only the fixed method and header allowlists")
					}
				} else if rec.Header().Get("Access-Control-Allow-Methods") != "" || rec.Header().Get("Access-Control-Allow-Headers") != "" {
					t.Fatal("rejected preflight must not advertise methods or headers")
				}
			})
		}
	}
}

// Checks that unknown providers return 404 and unsupported HTTP methods return 405.
func TestProviderToken_Routing(t *testing.T) {
	cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 10000, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
	handler := NewServer(cfg, session.NewStore(1000)).routes()
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/oauth/unknown/token", http.StatusNotFound},
		{http.MethodGet, "/oauth/mock/token", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/oauth/mock/token", http.StatusMethodNotAllowed},
		{http.MethodGet, "/session/logout", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/session/logout", http.StatusMethodNotAllowed},
	} {
		req := browserRequest(tc.path, "{}")
		req.Method = tc.method
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Errorf("%s %s status = %d, want %d", tc.method, tc.path, rec.Code, tc.status)
		}
	}
}

// Checks that the health endpoint responds with 200.
func TestServer_Health(t *testing.T) {
	cfg, err := LoadConfig("../../config.example.json")
	if err != nil {
		t.Fatalf("failed to load fixture config: %v", err)
	}

	store := session.NewStore(1000)
	srv := NewServer(cfg, store)

	// Simulate GET /health request
	// the Recorder package helps test without creating any ports
	// all simulated in memory
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestOAuthStart_SessionLimit(t *testing.T) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SessionLimit = 1
	store := session.NewStore(cfg.SessionLimit)
	handler := NewServer(cfg, store).routes()
	start := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		req := browserRequest("/oauth/github/start", "{}")
		req.Header.Set("Origin", cfg.FeOrigin)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	first := start(nil)
	if first.Code != http.StatusOK || len(first.Result().Cookies()) != 1 {
		t.Fatalf("first start = %d: %s", first.Code, first.Body.String())
	}
	cookie := first.Result().Cookies()[0]
	full := start(nil)
	if full.Code != http.StatusTooManyRequests || full.Body.String() != "{\"error\":\"session_limit_reached\"}\n" {
		t.Fatalf("start at capacity = %d: %s", full.Code, full.Body.String())
	}
	if len(full.Result().Cookies()) != 0 || full.Header().Get("Access-Control-Allow-Origin") != cfg.FeOrigin || full.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("capacity rejection set a cookie or lost browser response protections")
	}
	if reused := start(cookie); reused.Code != http.StatusOK || len(reused.Result().Cookies()) != 0 {
		t.Fatalf("existing session at capacity = %d: %s", reused.Code, reused.Body.String())
	}
}

func TestOAuthStart_SessionLifetime(t *testing.T) {
	for _, tc := range []struct {
		lifetime   string
		wantCookie time.Duration
	}{
		{"1h", time.Hour},
		{"9600h", 400 * 24 * time.Hour},
	} {
		t.Run(tc.lifetime, func(t *testing.T) {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg.SessionLifetime = tc.lifetime
			if err := validate(cfg); err != nil {
				t.Fatal(err)
			}
			store := session.NewStore(1000)
			handler := NewServer(cfg, store).routes()
			start := func(cookie *http.Cookie) *httptest.ResponseRecorder {
				req := browserRequest("/oauth/github/start", "{}")
				req.Header.Set("Origin", cfg.FeOrigin)
				if cookie != nil {
					req.AddCookie(cookie)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("start status = %d: %s", rec.Code, rec.Body.String())
				}
				return rec
			}
			before := time.Now()
			rec := start(nil)
			after := time.Now()
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookies = %d", len(cookies))
			}
			cookie := cookies[0]
			// HTTP cookie timestamps have one-second precision.
			if cookie.Expires.Before(before.Add(tc.wantCookie).Truncate(time.Second)) || cookie.Expires.After(after.Add(tc.wantCookie)) {
				t.Fatalf("unexpected cookie expiry: %v", cookie.Expires)
			}
			id := session.ID(cookie.Value)
			deadline, ok := store.ExpiresAt(id)
			if !ok || deadline.Before(before.Add(cfg.sessionLifetime)) || deadline.After(after.Add(cfg.sessionLifetime)) {
				t.Fatalf("unexpected session deadline: %v", deadline)
			}
			if !cookie.Expires.Equal(deadline.UTC().Truncate(time.Second)) {
				t.Fatal("cookie does not match stored deadline")
			}
			if rec := start(cookie); len(rec.Result().Cookies()) != 0 {
				t.Fatal("reusing session renewed cookie")
			}
			if after, ok := store.ExpiresAt(id); !ok || !after.Equal(deadline) {
				t.Fatal("reusing session changed deadline")
			}
			store.Delete(id)
			if rec := start(cookie); len(rec.Result().Cookies()) != 1 || rec.Result().Cookies()[0].Value == cookie.Value {
				t.Fatal("unknown cookie did not create a new session")
			}
		})
	}
}
