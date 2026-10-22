package mediator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// this file is expected to be in same path in repo if you want
// to run the tests
var configPath = "../../config.example.json"

func TestLoadConfig(t *testing.T) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("expected valid config at %s, err = %v", configPath, err)
	}
	// just one is enough
	if cfg.Port != 8080 {
		t.Fatalf("field 'port' is not expected ( 8080 ), got %d", cfg.Port)
	}
	if cfg.SessionLimit != 1000 {
		t.Fatalf("session limit = %d, want 1000", cfg.SessionLimit)
	}
}

func TestLoadConfig_SessionLimit(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, 1000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg.SessionLimit = limit
			if err := validate(cfg); (err == nil) != (limit > 0) {
				t.Fatalf("session limit %d: validation error = %v", limit, err)
			}
		})
	}
}

func TestLoadConfig_RateLimiting(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       any
		valid       bool
	}{
		{"missing rate", "rate_limit_per_minute", nil, false},
		{"zero rate", "rate_limit_per_minute", 0, false},
		{"negative rate", "rate_limit_per_minute", -1, false},
		{"fractional rate", "rate_limit_per_minute", 1.5, false},
		{"string rate", "rate_limit_per_minute", "60", false},
		{"minimum rate", "rate_limit_per_minute", 1, true},
		{"missing capacity", "rate_limit_max_ips", nil, false},
		{"zero capacity", "rate_limit_max_ips", 0, false},
		{"negative capacity", "rate_limit_max_ips", -1, false},
		{"minimum capacity", "rate_limit_max_ips", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if err := json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			if tc.value == nil {
				delete(config, tc.field)
			} else {
				config[tc.field] = tc.value
			}
			data, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); (err == nil) != tc.valid {
				t.Fatalf("valid = %v, error = %v", tc.valid, err)
			}
		})
	}
}

func TestValidate_LoopbackHost(t *testing.T) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host  string
		valid bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true},
		{"", false},
		{"0.0.0.0", false},
		{"::", false},
		{"192.0.2.1", false},
		{"localhost", false},
		{"invalid", false},
		{"::1%eth0", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			cfg.Host = tc.host
			if err := validate(cfg); (err == nil) != tc.valid {
				t.Fatalf("host %q: valid = %v, error = %v", tc.host, tc.valid, err)
			}
		})
	}
}

func TestLoadConfig_SessionLifetime(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  time.Duration
		valid bool
	}{
		{"1s", time.Second, true},
		{"30m", 30 * time.Minute, true},
		{"24h", 24 * time.Hour, true},
		{"720h", 720 * time.Hour, true},
		{"9600h", 400 * 24 * time.Hour, true},
		{"9600h1ns", 0, false},
		{"12000h", 0, false},
		{"inf", 0, false},
		{nil, 0, false},
		{"", 0, false},
		{"0", 0, false},
		{"-1h", 0, false},
		{"500ms", 0, false},
		{"7d", 0, false},
		{"INF", 0, false},
		{"999999999999999999h", 0, false},
		{24, 0, false},
	} {
		t.Run(fmt.Sprint(tc.value), func(t *testing.T) {
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if err := json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			if tc.value == nil {
				delete(config, "session_lifetime")
			} else {
				config["session_lifetime"] = tc.value
			}
			data, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if !tc.valid {
				if err == nil {
					t.Fatal("accepted invalid session lifetime")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.SessionLifetime != tc.value || cfg.sessionLifetime != tc.want {
				t.Fatalf("lifetime = %q (%s), want %v (%s)", cfg.SessionLifetime, cfg.sessionLifetime, tc.value, tc.want)
			}
		})
	}
}
