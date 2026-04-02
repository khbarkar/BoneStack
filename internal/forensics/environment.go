package forensics

import (
	"context"
	"fmt"
	"strings"
)

// EnvironmentAnalyzer inspects container environment variables
type EnvironmentAnalyzer struct {
	inspector *ContainerInspector
}

// SecretPattern contains patterns that match sensitive data
type SecretPattern struct {
	Name        string
	Patterns    []string
	Description string
}

// NewEnvironmentAnalyzer creates a new environment analyzer
func NewEnvironmentAnalyzer(inspector *ContainerInspector) *EnvironmentAnalyzer {
	return &EnvironmentAnalyzer{
		inspector: inspector,
	}
}

// GetEnvironmentVariables retrieves all environment variables
func (ea *EnvironmentAnalyzer) GetEnvironmentVariables(ctx context.Context, containerID string) (map[string]string, error) {
	return ea.inspector.GetEnvironmentVariables(ctx, containerID)
}

// FindSecrets identifies environment variables that might contain secrets
func (ea *EnvironmentAnalyzer) FindSecrets(ctx context.Context, containerID string) (map[string]string, []string, error) {
	envVars, err := ea.GetEnvironmentVariables(ctx, containerID)
	if err != nil {
		return nil, nil, err
	}

	secrets := secretPatterns()
	found := make(map[string]string)
	var secretNames []string

	for varName, value := range envVars {
		lowerName := strings.ToLower(varName)

		for _, pattern := range secrets {
			for _, p := range pattern.Patterns {
				if strings.Contains(lowerName, p) {
					found[varName] = redactValue(value)
					secretNames = append(secretNames, varName)
					break
				}
			}
		}
	}

	return found, secretNames, nil
}

// SearchEnvironment searches for specific variables
func (ea *EnvironmentAnalyzer) SearchEnvironment(ctx context.Context, containerID, pattern string) (map[string]string, error) {
	envVars, err := ea.GetEnvironmentVariables(ctx, containerID)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	lowerPattern := strings.ToLower(pattern)

	for k, v := range envVars {
		if strings.Contains(strings.ToLower(k), lowerPattern) {
			result[k] = v
		}
	}

	return result, nil
}

// GetEnvironmentSummary provides a summary of environment variables
func (ea *EnvironmentAnalyzer) GetEnvironmentSummary(ctx context.Context, containerID string) (map[string]interface{}, error) {
	envVars, err := ea.GetEnvironmentVariables(ctx, containerID)
	if err != nil {
		return nil, err
	}

	_, secrets, _ := ea.FindSecrets(ctx, containerID)

	return map[string]interface{}{
		"total_variables": len(envVars),
		"secret_count":    len(secrets),
		"categories":      categorizeEnvVars(envVars),
	}, nil
}

// Helper functions

func secretPatterns() []SecretPattern {
	return []SecretPattern{
		{
			Name:        "Database Credentials",
			Patterns:    []string{"password", "pwd", "passwd", "db_pass", "database_password"},
			Description: "Database password variables",
		},
		{
			Name:        "API Keys & Tokens",
			Patterns:    []string{"api_key", "apikey", "api_token", "token", "secret_key", "secret"},
			Description: "API keys and authentication tokens",
		},
		{
			Name:        "AWS Credentials",
			Patterns:    []string{"aws_access_key", "aws_secret", "aws_key_id"},
			Description: "AWS access credentials",
		},
		{
			Name:        "Authentication",
			Patterns:    []string{"auth", "oauth", "jwt", "bearer"},
			Description: "Authentication related secrets",
		},
	}
}

func redactValue(value string) string {
	if len(value) <= 4 {
		return "***"
	}
	return value[:2] + "***" + value[len(value)-2:]
}

func categorizeEnvVars(envVars map[string]string) map[string]int {
	categories := make(map[string]int)

	for varName := range envVars {
		lower := strings.ToLower(varName)

		if strings.Contains(lower, "path") {
			categories["path"]++
		} else if strings.Contains(lower, "home") || strings.Contains(lower, "user") {
			categories["user"]++
		} else if strings.Contains(lower, "lang") || strings.Contains(lower, "locale") {
			categories["locale"]++
		} else if strings.Contains(lower, "docker") {
			categories["docker"]++
		} else if strings.Contains(lower, "node") || strings.Contains(lower, "npm") {
			categories["nodejs"]++
		} else if strings.Contains(lower, "python") {
			categories["python"]++
		} else if strings.Contains(lower, "java") {
			categories["java"]++
		} else if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "key") {
			categories["secrets"]++
		} else {
			categories["other"]++
		}
	}

	return categories
}
