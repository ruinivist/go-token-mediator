package mediator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"token-mediator/internal/session"
)

// ==== server creation ====

type Server struct {
	cfg        *Config
	store      *session.Store
	httpServer *http.Server
}

func NewServer(cfg *Config, store *session.Store) *Server {
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
		// Limit how long a client can take to send the headers and body.
		ReadTimeout: 10 * time.Second,
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
	mux.HandleFunc("POST /session/logout", s.allowBrowserOrigin(s.validateBrowserPost(s.sessionLogout)))
	mux.HandleFunc("OPTIONS /session/logout", s.allowBrowserOrigin(browserPreflight))
	mux.HandleFunc("POST /oauth/{provider}/start", s.allowBrowserOrigin(s.validateBrowserPost(s.providerOAuthStart)))
	mux.HandleFunc("OPTIONS /oauth/{provider}/start", s.allowBrowserOrigin(s.providerPreflight))
	mux.HandleFunc("GET /oauth/{provider}/callback", s.providerOAuthCallback)
	mux.HandleFunc("POST /oauth/{provider}/token", s.allowBrowserOrigin(s.validateBrowserPost(s.providerToken)))
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
		s.store.Delete(session.ID(cookie.Value))
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

	sessionID, created, err := s.store.GetOrCreate(cookieID, s.cfg.sessionLifetime)
	if err != nil {
		if errors.Is(err, session.ErrSessionLimit) {
			writeJSONError(w, "session_limit_reached", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	if created {
		expiresAt, ok := s.store.ExpiresAt(sessionID)
		if !ok {
			http.Error(w, "invalid session", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, makeCookie(sessionID, expiresAt))
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

	if !s.store.SetPendingAuth(sessionID, session.PendingAuth{
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
		"authorization_url": p.buildAuthUrl(state, challenge),
	})
}

// handles /oauth/{provider}/callback
func (s *Server) providerOAuthCallback(w http.ResponseWriter, r *http.Request) {
	// no cache signal to browsers, this also signals that it should not be sent as a referrer
	// to other pages
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

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
	pa, ok := s.store.ConsumePendingAuth(sessId, providerName, state)
	if !ok {
		http.Error(w, "invalid auth state", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("error") != "" || code == "" {
		http.Error(w, "authorization denied or missing code", http.StatusBadRequest)
		return
	}

	// now use this code to fetch the access token from the provider

	// use same context as the original request
	resp, err := p.fetchAccessToken(code, pa.PKCEVerifier, r.Context())
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
	}
	if resp.Scope != nil {
		conn.Scopes = *resp.Scope
	}
	if resp.ExpiresIn != nil {
		// rfc declares it to be in seconds
		conn.ExpiresAt = time.Now().Add(time.Duration(*resp.ExpiresIn) * time.Second)
	}

	newID, expiresAt, err := s.store.CompleteAuth(sessId, *conn)
	if err != nil {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, makeCookie(newID, expiresAt))
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

	conn, err := s.store.UpdateConnection(r.Context(), sessId, providerName, func(conn session.Connection) (*session.Connection, error) {
		if conn.ExpiresAt.IsZero() || time.Until(conn.ExpiresAt) > 2*time.Minute {
			return &conn, nil
		}
		if conn.RefreshToken == "" {
			if !time.Now().Before(conn.ExpiresAt) {
				return nil, session.ErrNoConnection
			}
			return &conn, nil
		}
		resp, err := p.refreshAccessToken(r.Context(), conn.RefreshToken)
		if err != nil {
			var upstream *tokenError
			if errors.As(err, &upstream) && (upstream.code == "invalid_grant" || upstream.uncertain) {
				if upstream.code == "invalid_grant" {
					return nil, session.ErrNoConnection
				}
				return nil, err
			}
			return &conn, err
		}
		conn.AccessToken = resp.AccessToken
		conn.ExpiresAt = time.Time{}
		if resp.ExpiresIn != nil {
			conn.ExpiresAt = time.Now().Add(time.Duration(*resp.ExpiresIn) * time.Second)
		}
		if resp.RefreshToken != nil {
			conn.RefreshToken = *resp.RefreshToken
		}
		if resp.Scope != nil {
			conn.Scopes = *resp.Scope
		}
		return &conn, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, session.ErrNoConnection):
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
