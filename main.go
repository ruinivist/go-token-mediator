// The executable wires configuration, durable storage, cleanup, and HTTP shutdown.
// It closes storage only after the server and cleanup worker have stopped.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"token-mediator/internal/mediator"
	"token-mediator/internal/session"
)

// ---------- Runtime ----------

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		return errors.New("CONFIG_PATH env is unset")
	}
	cfg, err := mediator.LoadConfig(configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := session.Open(ctx, cfg.DatabasePath, cfg.SessionDuration(), cfg.SessionLimit)
	if err != nil {
		return errors.New("failed to open session storage")
	}
	cleanupCtx, stopCleanup := context.WithCancel(context.Background())
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				if err := store.CleanupExpired(cleanupCtx); err != nil && cleanupCtx.Err() == nil {
					log.Print("session cleanup failed")
				}
			}
		}
	}()
	serverErr := mediator.NewServer(cfg, store).Run(ctx)
	stopCleanup()
	<-cleanupDone
	closeErr := store.Close()
	if serverErr != nil {
		return serverErr
	}
	if closeErr != nil {
		return errors.New("failed to close session storage")
	}
	return nil
}
