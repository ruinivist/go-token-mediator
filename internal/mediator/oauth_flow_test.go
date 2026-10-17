// This file tests the mediator's OAuth start, callback, and token storage flow.
// It exercises the HTTP routes against the mock OAuth token endpoint.
package mediator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"token-mediator/internal/session"
)

// ---------- OAuth flow ----------

func TestOAuthFlow(t *testing.T) {
	providerServer, tokenRequests := newMockOAuthServer(t)
	provider := ProviderConfig{
		ClientId:     "test-client",
		ClientSecret: "test-secret",
		AuthUrl:      "https://provider.example/authorize",
		TokenUrl:     providerServer.URL + "/token",
		RedirectUrl:  "https://mediator.example/oauth/mock/callback",
		Scopes:       []string{"read:user", "user:email"},
	}
	cfg := &Config{
		SessionLifetime: "24h",
		sessionLifetime: 24 * time.Hour,
		Host:            "127.0.0.1",
		Port:            8080,
		FeOrigin:        "https://frontend.example",
		FeCompletion:    "https://frontend.example/oauth/complete",
		Providers:       map[string]ProviderConfig{"mock": provider},
	}
	store := session.NewStore()
	handler := NewServer(cfg, store).routes()

	// ---------- Start ----------

	start := httptest.NewRecorder()
	handler.ServeHTTP(start, browserRequest("/oauth/mock/start", "{}"))
	if start.Code != http.StatusOK {
		t.Fatalf("start status = %d, body = %s", start.Code, start.Body.String())
	}
	var payload struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.NewDecoder(start.Body).Decode(&payload); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	authURL, err := url.Parse(payload.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if authURL.Scheme != "https" || authURL.Host != "provider.example" || authURL.Path != "/authorize" {
		t.Fatalf("unexpected authorization URL: %s", authURL)
	}
	query := authURL.Query()
	for key, want := range map[string]string{
		"client_id":             provider.ClientId,
		"redirect_uri":          provider.RedirectUrl,
		"response_type":         "code",
		"scope":                 "read:user user:email",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("authorization %s = %q, want %q", key, got, want)
		}
	}
	state, challenge := query.Get("state"), query.Get("code_challenge")
	if state == "" || challenge == "" {
		t.Fatal("authorization URL is missing state or PKCE challenge")
	}

	var cookie *http.Cookie
	startResponse := start.Result()
	defer startResponse.Body.Close()
	for _, c := range startResponse.Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
			break
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("start did not set a session cookie")
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("unexpected session cookie attributes: %+v", cookie)
	}
	sessionID := session.ID(cookie.Value)
	if !store.Has(sessionID) {
		t.Fatal("session cookie does not identify an active session")
	}
	doCallback := func(callbackState string) *httptest.ResponseRecorder {
		params := url.Values{"code": {"test-code"}, "state": {callbackState}}
		req := httptest.NewRequest(http.MethodGet, "/oauth/mock/callback?"+params.Encode(), nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// ---------- State rejection ----------

	invalid := doCallback(state + "-wrong")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("wrong-state callback status = %d, want 400", invalid.Code)
	}
	select {
	case <-tokenRequests:
		t.Fatal("wrong-state callback contacted the token endpoint")
	default:
	}
	if _, ok := store.GetConnection(sessionID, "mock"); ok {
		t.Fatal("wrong-state callback saved a connection")
	}

	// ---------- Token exchange and storage ----------

	before := time.Now()
	callback := doCallback(state)
	after := time.Now()
	if callback.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, body = %s", callback.Code, callback.Body.String())
	}
	if got := callback.Header().Get("Location"); got != cfg.FeCompletion {
		t.Errorf("completion redirect = %q, want %q", got, cfg.FeCompletion)
	}
	var form url.Values
	select {
	case form = <-tokenRequests:
	default:
		t.Fatal("callback did not contact the token endpoint")
	}
	for key, want := range map[string]string{
		"client_id":     provider.ClientId,
		"client_secret": provider.ClientSecret,
		"redirect_uri":  provider.RedirectUrl,
		"code":          "test-code",
		"grant_type":    "authorization_code",
	} {
		if got := form.Get(key); got != want {
			t.Errorf("token form %s = %q, want %q", key, got, want)
		}
	}
	verifier := form.Get("code_verifier")
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("PKCE verifier length = %d, want 43–128", len(verifier))
	}
	hash := sha256.Sum256([]byte(verifier))
	if got := base64.RawURLEncoding.EncodeToString(hash[:]); got != challenge {
		t.Errorf("PKCE verifier hashes to %q, want %q", got, challenge)
	}
	connection, ok := store.GetConnection(sessionID, "mock")
	if !ok {
		t.Fatal("callback did not save a provider connection")
	}
	if connection.Provider != "mock" || connection.AccessToken != "mock-access-token" ||
		connection.RefreshToken != "mock-refresh-token" || connection.Scopes != "read:user" {
		t.Errorf("unexpected saved connection: %+v", connection)
	}
	if connection.ExpiresAt.Before(before.Add(time.Hour)) || connection.ExpiresAt.After(after.Add(time.Hour)) {
		t.Errorf("token expiry = %v, want one hour after exchange", connection.ExpiresAt)
	}

	// ---------- Browser token retrieval ----------

	tokenRequest := browserRequest("/oauth/mock/token", "{}")
	tokenRequest.AddCookie(cookie)
	token := httptest.NewRecorder()
	handler.ServeHTTP(token, tokenRequest)
	if token.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", token.Code, token.Body.String())
	}
	var browserToken map[string]any
	if err := json.Unmarshal(token.Body.Bytes(), &browserToken); err != nil {
		t.Fatal(err)
	}
	if len(browserToken) != 4 || browserToken["access_token"] != "mock-access-token" ||
		browserToken["token_type"] != "Bearer" || browserToken["scope"] != "read:user" {
		t.Fatalf("unexpected browser token: %v", browserToken)
	}
	if seconds, ok := browserToken["expires_in"].(float64); !ok || seconds <= 0 || seconds > 3600 {
		t.Fatalf("unexpected remaining expiry: %v", browserToken["expires_in"])
	}

	// ---------- Replay rejection ----------

	replay := doCallback(state)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want 400", replay.Code)
	}
	select {
	case <-tokenRequests:
		t.Fatal("replayed callback contacted the token endpoint")
	default:
	}
}

// ---------- Provider failures ----------

func TestOAuthCallback_ProviderFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		timeout    bool
		wantStatus int
		query      string
		noExchange bool
	}{
		{name: "denied consent", query: "error=access_denied&error_description=private-details&state=state", noExchange: true, wantStatus: 400},
		{name: "error with code", query: "error=access_denied&code=code&state=state", noExchange: true, wantStatus: 400},
		{name: "missing code", query: "state=state", noExchange: true, wantStatus: 400},
		{name: "empty access token", status: 200, body: `{"access_token":"","token_type":"Bearer"}`, wantStatus: 502},
		{name: "malformed JSON", status: 200, body: `{`, wantStatus: 502},
		{name: "OAuth error with 200", status: 200, body: `{"error":"invalid_client","error_description":"private-secret"}`, wantStatus: 502},
		{name: "upstream HTTP error", status: 503, body: `private-secret`, wantStatus: 502},
		{name: "timeout", timeout: true, wantStatus: 504},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := make(chan struct{}, 1)
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls <- struct{}{}
				if tc.noExchange {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if tc.timeout {
					io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
					return
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer provider.Close()
			store := session.NewStore()
			id, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			original := session.Connection{Provider: "mock", AccessToken: "existing", RefreshToken: "private-refresh"}
			if !store.SaveConnection(id, original) || !store.SetPendingAuth(id, session.PendingAuth{Provider: "mock", State: "state", CreatedAt: time.Now()}) {
				t.Fatal("failed to prepare reconnect")
			}
			cfg := &Config{Providers: map[string]ProviderConfig{"mock": {TokenUrl: provider.URL}}}
			query := tc.query
			if query == "" {
				query = "code=code&state=state"
			}
			req := httptest.NewRequest(http.MethodGet, "/oauth/mock/callback?"+query, nil)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(id)})
			if tc.timeout {
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				req = req.WithContext(ctx)
			}
			rec := httptest.NewRecorder()
			NewServer(cfg, store).routes().ServeHTTP(rec, req)
			if tc.noExchange && len(calls) != 0 {
				t.Fatal("invalid callback contacted the token endpoint")
			}
			if _, ok := store.ConsumePendingAuth(id, "mock", "state"); ok {
				t.Fatal("failed callback left authorization attempt reusable")
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if rec.Header().Get("Location") != "" || strings.Contains(rec.Body.String(), "private") {
				t.Fatal("redirected or exposed provider details on failure")
			}
			if got, ok := store.GetConnection(id, "mock"); !ok || got != original {
				t.Fatal("changed existing connection after failed reconnect")
			}
		})
	}
}
