package ai

import "testing"

func TestSaveAndLoadStoredConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg := Config{
		Provider: "ollama",
		Model:    "llama3.2",
	}
	if err := SaveStoredConfig(cfg); err != nil {
		t.Fatalf("SaveStoredConfig failed: %v", err)
	}

	loaded, err := LoadStoredConfig()
	if err != nil {
		t.Fatalf("LoadStoredConfig failed: %v", err)
	}
	if loaded.Provider != "ollama" || loaded.Model != "llama3.2" {
		t.Fatalf("unexpected config %#v", loaded)
	}
}
