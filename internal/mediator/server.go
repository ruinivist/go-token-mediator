package mediator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"token-mediator/internal/session"
)

// ==== server creation ====

type Server struct {
	cfg        *Config
	store      *session.Store
	limiter    *rateLimiter
	httpServer *http.Server
	requests   sync.WaitGroup
	requestsMu sync.Mutex
	draining   bool
}

func NewServer(cfg *Config, store *session.Store) *Server {
	s := &Server{
		cfg:     cfg,
		store:   store,
		limiter: newRateLimiter(cfg.RateLimitPerMinute, cfg.RateLimitMaxIPs),
	}

	// routes is define on server so that the handlers can use config
	// and store, but due to that we need to split the creation like this
	s.httpServer = &http.Server{
		Addr:    net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler: s.trackRequests(s.routes()),
		// history lesson: slowloris attack ( 2009 ), single laptop
		// opened hundreds of connections and sent headers extremely
		// slowly at 1 byte every 10 seconds. Servers had to keep the
		// connection open leading to a DoS
		ReadHeaderTimeout: 5 * time.Second,
		// Limit how long a client can take to send the headers and body.
		ReadTimeout: 10 * time.Second,
		// how long to keep an idle TCP open, browsers keep the connection
		// alive so the whole handshake isn't done again
		IdleTimeout: 60 * time.Second,
	}

	return s
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("server listen failure: %w", err)
	}
	return s.serve(ctx, listener)
}

func (s *Server) trackRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requestsMu.Lock()
		if s.draining {
			s.requestsMu.Unlock()
			writeJSONError(w, "server_shutdown", http.StatusServiceUnavailable)
			return
		}
		s.requests.Add(1)
		s.requestsMu.Unlock()
		defer s.requests.Done()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serve(ctx context.Context, listener net.Listener) error {
	shutdownDone := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.httpServer.Close()
		}
	}()
	log.Printf("Server listening on %s:%d", s.cfg.Host, s.cfg.Port)
	err := s.httpServer.Serve(listener)
	close(runDone)
	<-shutdownDone
	s.requestsMu.Lock()
	s.draining = true
	s.requestsMu.Unlock()
	s.requests.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server failure: %w", err)
	}
	return nil
}

// ==== routes ====
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("POST /session/logout", s.allowBrowserOrigin(s.validateBrowserPost(s.sessionLogout)))
	mux.HandleFunc("OPTIONS /session/logout", s.allowBrowserOrigin(browserPreflight))
	mux.HandleFunc("POST /oauth/{provider}/start", s.allowBrowserOrigin(s.validateBrowserPost(s.rateLimit(s.providerOAuthStart))))
	mux.HandleFunc("OPTIONS /oauth/{provider}/start", s.allowBrowserOrigin(s.providerPreflight))
	mux.HandleFunc("GET /oauth/{provider}/callback", callbackHeaders(s.rateLimit(s.providerOAuthCallback)))
	mux.HandleFunc("POST /oauth/{provider}/token", s.allowBrowserOrigin(s.validateBrowserPost(s.rateLimit(s.providerToken))))
	mux.HandleFunc("OPTIONS /oauth/{provider}/token", s.allowBrowserOrigin(s.providerPreflight))
	return mux
}

// ==== handlers ====

func (s *Server) providerPreflight(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.cfg.Providers[r.PathValue("provider")]; !ok {
		writeJSONError(w, "unknown_provider", http.StatusNotFound)
		return
	}
	browserPreflight(w, r)
}

func browserPreflight(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Access-Control-Request-Method") != http.MethodPost {
		writeJSONError(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-OAuth-Bridge")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sessionLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.store.Logout(r.Context(), session.ID(cookie.Value)); err != nil {
			writeJSONError(w, "storage_unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
	w.WriteHeader(http.StatusNoContent)
}

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

	var cookieID session.ID
	if c, err := r.Cookie(sessionCookieName); err == nil {
		cookieID = session.ID(c.Value)
	}

	state, err := generateRandomString(32)
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		http.Error(w, "failed to generate pkce", http.StatusInternalServerError)
		return
	}
	authorizationURL, err := p.buildAuthUrl(state, challenge)
	if err != nil {
		writeJSONError(w, "provider_configuration_error", http.StatusInternalServerError)
		return
	}

	browser, err := s.store.BeginAuth(r.Context(), cookieID, session.PendingAuth{
		Provider: providerName, State: state, PKCEVerifier: verifier,
	})
	if err != nil {
		if errors.Is(err, session.ErrSessionLimit) {
			writeJSONError(w, "session_limit_reached", http.StatusTooManyRequests)
		} else {
			writeJSONError(w, "storage_unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	http.SetCookie(w, makeCookie(browser.ID, browser.ExpiresAt))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"authorization_url": authorizationURL,
	})
}

// handles /oauth/{provider}/callback
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
	sessId := session.ID(c.Value)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// consume pending auth atomically so the flow cannot be replayed
	verifier, handle, err := s.store.ConsumeAuth(r.Context(), sessId, providerName, state)
	if errors.Is(err, session.ErrStorage) {
		writeJSONError(w, "storage_unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "invalid auth state", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("error") != "" || code == "" {
		http.Error(w, "authorization denied or missing code", http.StatusBadRequest)
		return
	}

	// now use this code to fetch the access token from the provider

	// use same context as the original request
	resp, err := p.fetchAccessToken(code, verifier, r.Context())
	if err != nil {
		status := http.StatusBadGateway
		var timeout net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, "failed to fetch access tokens", status)
		return
	}

	if resp.TokenType == nil {
		http.Error(w, "provider rejected token exchange", http.StatusBadGateway)
		return
	}

	conn := &session.Connection{
		Provider:    providerName,
		AccessToken: resp.AccessToken,
	}
	if resp.RefreshToken != nil {
		conn.RefreshToken = *resp.RefreshToken
		if resp.RefreshTokenExpiresIn != nil {
			conn.RefreshExpiresAt = time.Now().Add(time.Duration(*resp.RefreshTokenExpiresIn) * time.Second)
		}
	}
	if resp.Scope != nil {
		conn.Scopes = *resp.Scope
	}
	if resp.ExpiresIn != nil {
		// rfc declares it to be in seconds
		conn.ExpiresAt = time.Now().Add(time.Duration(*resp.ExpiresIn) * time.Second)
	}

	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	browser, err := s.store.CompleteAuth(persistCtx, handle, *conn)
	if errors.Is(err, session.ErrStorage) {
		writeJSONError(w, "storage_unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, makeCookie(browser.ID, browser.ExpiresAt))
	http.Redirect(w, r, s.cfg.FeCompletion, http.StatusSeeOther)
}

// handles /oauth/{provider}/token
func (s *Server) providerToken(w http.ResponseWriter, r *http.Request) {
	type accessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   *int64 `json:"expires_in,omitempty"`
		Scope       string `json:"scope,omitempty"`
	}
	// resolve provider to be valid
	providerName := r.PathValue("provider")
	p, ok := s.cfg.Providers[providerName]
	if !ok {
		writeJSONError(w, "unknown_provider", http.StatusNotFound)
		return
	}

	// get cookie and check it's valid as well AND it has a connection
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeJSONError(w, "reauthorization_required", http.StatusUnauthorized)
		return
	}
	sessId := session.ID(c.Value)

	conn, err := s.accessConnection(r.Context(), sessId, providerName, p)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrStorage):
			writeJSONError(w, "storage_unavailable", http.StatusServiceUnavailable)
		case errors.Is(err, session.ErrNoConnection), errors.Is(err, session.ErrNoSession), errors.Is(err, session.ErrStale), errors.Is(err, session.ErrRefreshing):
			writeJSONError(w, "reauthorization_required", http.StatusUnauthorized)
		default:
			var timeout net.Error
			if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
				writeJSONError(w, "provider_timeout", http.StatusGatewayTimeout)
			} else {
				writeJSONError(w, "provider_error", http.StatusBadGateway)
			}
		}
		return
	}

	response := accessTokenResponse{
		AccessToken: conn.AccessToken,
		TokenType:   "Bearer",
		Scope:       conn.Scopes,
	}
	if !conn.ExpiresAt.IsZero() {
		remaining := time.Until(conn.ExpiresAt)
		if remaining <= 0 {
			writeJSONError(w, "reauthorization_required", http.StatusUnauthorized)
			return
		}
		seconds := int64(remaining / time.Second)
		response.ExpiresIn = &seconds
	}
	json.NewEncoder(w).Encode(response)
}
