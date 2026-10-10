package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"token-mediator/internal/session"
)

func TestServer_Health(t *testing.T) {
	cfg, err := LoadConfig("config.example.json")
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
