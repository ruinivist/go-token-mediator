package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// ==== server creation ====

type Server struct {
	cfg        *Config
	store      *SessionStore
	httpServer *http.Server
}

func NewServer(cfg *Config, store *SessionStore) *Server {
	s := &Server{
		cfg:   cfg,
		store: store,
	}

	// routes is define on server so that the handlers can use config
	// and store, but due to that we need to split the creation like this
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler: s.routes(),
		// history lesson: slowloris attack ( 2009 ), single laptop
		// opened hundreds of connections and sent headers extremely
		// slowly at 1 byte every 10 seconds. Servers had to keep the
		// connection open leading to a DoS
		ReadHeaderTimeout: 5 * time.Second,
		// how long to keep an idle TCP open, browsers keep the connection
		// alive so the whole handshake isn't done again
		IdleTimeout: 60 * time.Second,
	}

	return s
}

func (s *Server) Run(ctx context.Context) error {
	go func() {
		// triggers sigterm from main context
		<-ctx.Done()

		// once shutdown is triggers, wait max 5 seconds to allow graceful
		// shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s.httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("Server listenng on %s:%d", s.cfg.Host, s.cfg.Port)

	// listen and server must be blocking
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// if you call shutdown, listen and server returns "http.ErrServerClosed", not an actual error
		// so we filter
		return fmt.Errorf("server failure, err = %w", err)
	}

	return nil
}

// ==== routes ====
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("POST /oauth/{provider}/start", s.providerOAuthStart)
	mux.HandleFunc("GET /oauth/{provider}/callback", s.providerOAuthCallback)
	return mux
}

// ==== handlers ====

// handles /heatlth
func healthHandler(w http.ResponseWriter, r *http.Request) {
	type HealthResponse struct {
		Status string `json:"status"`
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
}

// handles /oauth/{provider}/start
func (s *Server) providerOAuthStart(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	p, ok := s.cfg.Providers[providerName]
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	var cookieID SessionId
	if c, err := r.Cookie(sessionCookieName); err == nil {
		cookieID = SessionId(c.Value)
	}

	sess, created, err := s.store.GetOrCreate(cookieID, 24*time.Hour)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	if created {
		setSessionCookie(w, sess.ID)
	}

	state, err := GenerateRandomString(32)
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		http.Error(w, "failed to generate pkce", http.StatusInternalServerError)
		return
	}

	if !s.store.SetPendingAuth(sess.ID, PendingAuth{
		Provider:     providerName,
		State:        state,
		PKCEVerifier: verifier,
		CreatedAt:    time.Now(),
	}) {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"authorization_url": p.BuildAuthUrl(state, challenge),
	})
}

func (s *Server) providerOAuthCallback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	p, ok := s.cfg.Providers[providerName]
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	// the callback will be from the browser so will have the cookie, we need that
	// to identify the user
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Error(w, "request missing cookie", http.StatusBadRequest)
		return
	}
	sessId := SessionId(c.Value)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// consume pending auth atomically so the flow cannot be replayed
	pa, ok := s.store.ConsumePendingAuth(sessId, providerName, state)
	if !ok {
		http.Error(w, "invalid auth state", http.StatusBadRequest)
		return
	}

	// now use this code to fetch the access token from the provider

	// use same context as the original request
	resp, err := p.FetchAccessToken(code, pa.PKCEVerifier, r.Context())
	if err != nil {
		http.Error(w, "failed to fetch access tokens", http.StatusForbidden)
		return
	}

	if resp.ErrorCode != "" || resp.AccessToken == "" {
		http.Error(w, "provider rejected token exchange", http.StatusBadGateway)
		return
	}

	conn := &Connection{
		Provider:     providerName,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		Scopes:       resp.Scope,
	}
	if resp.ExpiresIn != nil {
		// rfc declares it to be in seconds
		conn.ExpiresAt = time.Now().Add(time.Duration(*resp.ExpiresIn) * time.Second)
	}

	if !s.store.SaveConnection(sessId, *conn) {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.cfg.FeCompletion, http.StatusSeeOther)
}
