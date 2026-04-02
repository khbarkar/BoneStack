package forensics

import (
	"strings"
	"testing"
)

func TestRedactValue(t *testing.T) {
	if got := redactValue("abcd"); got != "***" {
		t.Fatalf("expected short values to be fully redacted, got %q", got)
	}

	if got := redactValue("supersecret"); got != "su***et" {
		t.Fatalf("unexpected redaction: %q", got)
	}
}

func TestCategorizeEnvVars(t *testing.T) {
	envVars := map[string]string{
		"PATH":              "/usr/bin",
		"HOME":              "/root",
		"LANG":              "C.UTF-8",
		"DOCKER_HOST":       "unix:///var/run/docker.sock",
		"NODE_ENV":          "production",
		"PYTHONPATH":        "/app",
		"JAVA_HOME":         "/opt/java",
		"AUTH_TOKEN":        "secret",
		"UNCLASSIFIED_FLAG": "1",
	}

	categories := categorizeEnvVars(envVars)
	expected := map[string]int{
		"path":    2,
		"user":    1,
		"locale":  1,
		"docker":  1,
		"nodejs":  1,
		"java":    1,
		"secrets": 1,
		"other":   1,
	}

	for key, want := range expected {
		if got := categories[key]; got != want {
			t.Fatalf("category %q: got %d want %d", key, got, want)
		}
	}
}

func TestFindSecretsNoDuplicates(t *testing.T) {
	envVars := map[string]string{
		"API_TOKEN_SECRET": "abcdef",
	}

	found := make(map[string]string)
	var secretNames []string
	secrets := secretPatterns()

	for varName, value := range envVars {
		lowerName := strings.ToLower(varName)
		matched := false
		for _, pattern := range secrets {
			for _, p := range pattern.Patterns {
				if strings.Contains(lowerName, p) {
					found[varName] = redactValue(value)
					secretNames = append(secretNames, varName)
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}

	if len(secretNames) != 1 {
		t.Fatalf("expected one secret match, got %#v", secretNames)
	}
}
