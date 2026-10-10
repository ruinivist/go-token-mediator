// This file provides a mock OAuth token endpoint and captures token requests.
// The mediator flow tests use it instead of contacting a real provider.
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// ---------- Mock token endpoint ----------

// newMockOAuthServer returns fixed tokens and records submitted token forms.
// Flow tests must drain the captured form before making another exchange.
func newMockOAuthServer(t *testing.T) (*httptest.Server, <-chan url.Values) {
	t.Helper()
	requests := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid token form", http.StatusBadRequest)
			return
		}
		select {
		case requests <- r.PostForm:
		default:
			t.Error("mock token request was not consumed before the next exchange")
			http.Error(w, "unconsumed token request", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{
			"access_token": "mock-access-token",
			"token_type": "Bearer",
			"refresh_token": "mock-refresh-token",
			"scope": "read:user",
			"expires_in": 3600
		}`); err != nil {
			t.Errorf("write mock token response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, requests
}
