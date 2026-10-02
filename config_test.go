package main

import (
	"testing"
)

// this file is expected to be in same path in repo if you want
// to run the tests
var configPath = "config.example.json"

func TestLoadConfig(t *testing.T) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("expected valid config at %s, err = %v", configPath, err)
	}
	// just one is enough
	if cfg.Port != 8080 {
		t.Fatalf("field 'port' is not expected ( 8080 ), got %d", cfg.Port)
	}
}
