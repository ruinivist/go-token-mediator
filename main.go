package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// load config
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		log.Fatalf("CONFIG_PATH env is unset")
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// setup context for graceful shutdowns on sigterms/ctrl c
	// this wraps the bg context to add notifs for the two evens
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// sesison store
	store := NewSessionStore()
	store.StartCleanupWorker(ctx, 10*time.Minute)

	// server
	server := NewServer(cfg, store)
	if err := server.Run(ctx); err != nil {
		log.Fatalf("server error, err = %v", err)
	}
}
