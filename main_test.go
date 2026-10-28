// Runtime tests verify that storage failures prevent HTTP startup.
// They use example configuration with temporary paths and no provider calls.
package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"token-mediator/internal/mediator"
)

// ---------- Startup ----------

func TestStorageFailurePreventsListen(t *testing.T) {
	data, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg mediator.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg.Port = listener.Addr().(*net.TCPAddr).Port
	// A directory is an invalid database file, regardless of filesystem permissions.
	cfg.DatabasePath = t.TempDir()
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", path)
	if err := run(); err == nil || err.Error() != "failed to open session storage" {
		t.Fatalf("startup should fail at storage before the occupied listener: %v", err)
	}
}
