package mediator

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Checks that a client cannot hold a POST open by leaving its body unfinished.
func TestServer_UnfinishedBody(t *testing.T) {
	cfg := &Config{FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
	server := NewServer(cfg, session.NewStore())
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
			store := session.NewStore()
			id, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			conn := session.Connection{Provider: "mock", AccessToken: "own-token", RefreshToken: "private-refresh", Scopes: tc.scope}
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
			cfg := &Config{FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}, "other": {}}}
			req := browserRequest("/oauth/mock/token", "{}")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			rec := httptest.NewRecorder()
			NewServer(cfg, store).routes().ServeHTTP(rec, req)
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
			store := session.NewStore()
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
				if !store.SaveConnection(id, session.Connection{Provider: "mock", AccessToken: "expired", RefreshToken: "private", ExpiresAt: time.Now().Add(-time.Second)}) {
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
			cfg := &Config{FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
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

// Checks that both POST routes reject invalid headers/bodies and accept valid JSON requests.
func TestValidateBrowserPost_Validation(t *testing.T) {
	for _, route := range []string{"start", "token"} {
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
			{name: "valid", body: "{}", status: map[string]int{"start": 200, "token": 401}[route]},
			{name: "charset and whitespace", body: " {} \n", header: "Content-Type", value: "application/json; charset=utf-8", status: map[string]int{"start": 200, "token": 401}[route]},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				store := session.NewStore()
				cfg := &Config{FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {AuthUrl: "https://provider.example/authorize"}}}
				req := browserRequest("/oauth/mock/"+route, tc.body)
				if tc.header != "" {
					req.Header.Set(tc.header, tc.value)
				}
				rec := httptest.NewRecorder()
				NewServer(cfg, store).routes().ServeHTTP(rec, req)
				if rec.Code != tc.status {
					t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.status, rec.Body.String())
				}
				if tc.status != http.StatusOK && len(rec.Result().Cookies()) != 0 {
					t.Fatal("rejected request must not create a session cookie")
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("missing no-store header")
				}
			})
		}
	}
}

// Checks that unknown providers return 404 and unsupported HTTP methods return 405.
func TestProviderToken_Routing(t *testing.T) {
	cfg := &Config{FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
	handler := NewServer(cfg, session.NewStore()).routes()
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/oauth/unknown/token", http.StatusNotFound},
		{http.MethodGet, "/oauth/mock/token", http.StatusMethodNotAllowed},
		{http.MethodOptions, "/oauth/mock/token", http.StatusMethodNotAllowed},
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

	store := session.NewStore()
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
