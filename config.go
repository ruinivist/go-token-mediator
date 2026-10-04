package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// ==== models =====

type Config struct {
	Host         string                    `json:"host"`
	Port         int                       `json:"port"`
	FeOrigin     string                    `json:"frontend_origin_url"`
	FeCompletion string                    `json:"frontend_completion_url"`
	Providers    map[string]ProviderConfig `json:"providers"`
}

type ProviderConfig struct {
	ClientId     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthUrl      string   `json:"auth_url"`
	TokenUrl     string   `json:"token_url"`
	RedirectUrl  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

// ==== load and validation ====

// Load config at a supplied path. No fallbacks/default paths here
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, fmt.Errorf("failed to open config file at %s, err = %w", path, err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields() // reject any extra keys

	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file at %s, err = %w", path, err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check no keys are missing. Config does NOT default to any values
// everything MUST be explicit
func validate(c *Config) error {
	if c.Port == 0 {
		return errors.New("missing or zero 'port'")
	}
	if c.FeOrigin == "" {
		return errors.New("missing 'frontend_origin_url'")
	}
	if c.FeCompletion == "" {
		return errors.New("missing 'frontend_completion_url'")
	}
	if len(c.Providers) == 0 {
		return errors.New("missing 'providers'")
	}
	for name, p := range c.Providers {
		if p.ClientId == "" || p.ClientSecret == "" {
			return fmt.Errorf("provider %q missing credentials", name)
		}
		if p.AuthUrl == "" || p.TokenUrl == "" || p.RedirectUrl == "" {
			return fmt.Errorf("provider %q missing URLs", name)
		}
	}
	return nil
}
