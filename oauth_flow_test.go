// This file tests the mediator's OAuth start, callback, and token storage flow.
// It exercises the HTTP routes against the mock OAuth token endpoint.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		Host:         "127.0.0.1",
		Port:         8080,
		FeOrigin:     "https://frontend.example",
		FeCompletion: "https://frontend.example/oauth/complete",
		Providers:    map[string]ProviderConfig{"mock": provider},
	}
	store := session.NewStore()
	handler := NewServer(cfg, store).routes()

	// ---------- Start ----------

	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/oauth/mock/start", nil))
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
