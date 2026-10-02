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
	return mux
}

// ==== handlers ====
func healthHandler(w http.ResponseWriter, r *http.Request) {
	type HealthResponse struct {
		Status string `json:"status"`
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
}
