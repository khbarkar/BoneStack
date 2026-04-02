package ai

import (
	"fmt"
	"os"
	"strings"
)

// Config holds LLM backend configuration.
type Config struct {
	Provider string
	BaseURL  string
	Model    string
	APIKey   string
}

// LoadConfig reads AI configuration from environment variables.
func LoadConfig() (*Config, error) {
	if stored, err := LoadStoredConfig(); err == nil {
		return stored, nil
	}

	provider := strings.ToLower(strings.TrimSpace(os.Getenv("BONESTACK_AI_PROVIDER")))
	if provider == "" {
		return nil, fmt.Errorf("BONESTACK_AI_PROVIDER is not set")
	}

	cfg := &Config{
		Provider: provider,
		BaseURL:  strings.TrimSpace(os.Getenv("BONESTACK_AI_BASE_URL")),
		Model:    strings.TrimSpace(os.Getenv("BONESTACK_AI_MODEL")),
		APIKey:   strings.TrimSpace(os.Getenv("BONESTACK_AI_API_KEY")),
	}

	return cfg.Normalize()
}

// Normalize validates a config and fills provider defaults.
func (cfg Config) Normalize() (*Config, error) {
	cfg.Provider = strings.ToLower(strings.TrimSpace(cfg.Provider))
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.Model = strings.TrimSpace(cfg.Model)
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)

	if cfg.Provider == "" {
		return nil, fmt.Errorf("provider is not set")
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel(cfg.Provider)
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("model is not set")
	}

	switch cfg.Provider {
	case "ollama":
		if cfg.BaseURL == "" {
			cfg.BaseURL = DefaultBaseURL(cfg.Provider)
		}
	case "openai":
		if cfg.BaseURL == "" {
			cfg.BaseURL = DefaultBaseURL(cfg.Provider)
		}
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("api key is not set")
		}
	case "openai-compatible":
		if cfg.BaseURL == "" {
			return nil, fmt.Errorf("base url is not set")
		}
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("api key is not set")
		}
	case "grok":
		if cfg.BaseURL == "" {
			cfg.BaseURL = DefaultBaseURL(cfg.Provider)
		}
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("api key is not set")
		}
	case "claude":
		if cfg.BaseURL == "" {
			cfg.BaseURL = DefaultBaseURL(cfg.Provider)
		}
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("api key is not set")
		}
	case "gemini":
		if cfg.BaseURL == "" {
			cfg.BaseURL = DefaultBaseURL(cfg.Provider)
		}
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("api key is not set")
		}
	case "kiro":
		return nil, fmt.Errorf("kiro does not currently expose an api-key model endpoint; use claude directly or keep using kiro separately")
	default:
		return nil, fmt.Errorf("unsupported provider %q", cfg.Provider)
	}

	return &cfg, nil
}

func ProviderOptions() []string {
	return []string{
		"ollama",
		"openai",
		"claude",
		"grok",
		"gemini",
		"openai-compatible",
		"kiro",
	}
}

func DefaultBaseURL(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "ollama":
		return "http://127.0.0.1:11434"
	case "openai":
		return "https://api.openai.com"
	case "grok":
		return "https://api.x.ai/v1"
	case "claude":
		return "https://api.anthropic.com"
	case "gemini":
		return "https://generativelanguage.googleapis.com/v1beta"
	default:
		return ""
	}
}

func DefaultModel(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "ollama":
		return "llama3.2"
	case "openai":
		return "gpt-4.1-mini"
	case "claude":
		return "claude-sonnet-4-20250514"
	case "grok":
		return "grok-3-mini"
	case "gemini":
		return "gemini-2.5-flash"
	default:
		return ""
	}
}
