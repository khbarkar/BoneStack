package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadStoredConfig loads AI config from the standard user config path.
func LoadStoredConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.Normalize()
}

// SaveStoredConfig writes AI config to the standard user config path.
func SaveStoredConfig(cfg Config) error {
	normalized, err := cfg.Normalize()
	if err != nil {
		return err
	}
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func configPath() (string, error) {
	if custom := strings.TrimSpace(os.Getenv("BONESTACK_CONFIG_DIR")); custom != "" {
		return filepath.Join(custom, "bonestack", "ai.json"), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "bonestack", "ai.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "bonestack", "ai.json"), nil
}
