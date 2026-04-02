package ai

import "testing"

func TestLoadConfigDefaultsForOllama(t *testing.T) {
	t.Setenv("BONESTACK_CONFIG_DIR", t.TempDir())
	t.Setenv("BONESTACK_AI_PROVIDER", "ollama")
	t.Setenv("BONESTACK_AI_MODEL", "")
	t.Setenv("BONESTACK_AI_BASE_URL", "")
	t.Setenv("BONESTACK_AI_API_KEY", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.BaseURL != "http://127.0.0.1:11434" {
		t.Fatalf("got base url %q", cfg.BaseURL)
	}
	if cfg.Model != "llama3.2" {
		t.Fatalf("got model %q", cfg.Model)
	}
}

func TestLoadConfigRequiresAPIKeyForOpenAI(t *testing.T) {
	t.Setenv("BONESTACK_CONFIG_DIR", t.TempDir())
	t.Setenv("BONESTACK_AI_PROVIDER", "openai")
	t.Setenv("BONESTACK_AI_MODEL", "gpt-4.1-mini")
	t.Setenv("BONESTACK_AI_API_KEY", "")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNormalizeDefaultsForClaudeGrokAndGemini(t *testing.T) {
	testCases := []struct {
		provider string
		baseURL  string
		model    string
	}{
		{"claude", "https://api.anthropic.com", "claude-sonnet-4-20250514"},
		{"grok", "https://api.x.ai/v1", "grok-3-mini"},
		{"gemini", "https://generativelanguage.googleapis.com/v1beta", "gemini-2.5-flash"},
	}

	for _, tc := range testCases {
		cfg, err := (Config{Provider: tc.provider, APIKey: "demo-key"}).Normalize()
		if err != nil {
			t.Fatalf("%s normalize failed: %v", tc.provider, err)
		}
		if cfg.BaseURL != tc.baseURL {
			t.Fatalf("%s base url = %q, want %q", tc.provider, cfg.BaseURL, tc.baseURL)
		}
		if cfg.Model != tc.model {
			t.Fatalf("%s model = %q, want %q", tc.provider, cfg.Model, tc.model)
		}
	}
}

func TestNormalizeRejectsKiro(t *testing.T) {
	_, err := (Config{Provider: "kiro", Model: "unused", APIKey: "unused"}).Normalize()
	if err == nil {
		t.Fatal("expected error")
	}
}
