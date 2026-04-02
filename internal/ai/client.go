package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client requests analysis from a configured LLM backend.
type Client struct {
	config     Config
	httpClient *http.Client
}

// NewClient creates an AI client from config.
func NewClient(cfg Config) *Client {
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

// Analyze sends context to the configured model and returns the response.
func (c *Client) Analyze(ctx context.Context, prompt string) (string, error) {
	switch c.config.Provider {
	case "ollama":
		return c.analyzeOllama(ctx, prompt)
	case "openai", "openai-compatible", "grok":
		return c.analyzeOpenAICompatible(ctx, prompt)
	case "claude":
		return c.analyzeClaude(ctx, prompt)
	case "gemini":
		return c.analyzeGemini(ctx, prompt)
	default:
		return "", fmt.Errorf("unsupported provider %q", c.config.Provider)
	}
}

func (c *Client) analyzeOllama(ctx context.Context, prompt string) (string, error) {
	payload := map[string]interface{}{
		"model":  c.config.Model,
		"prompt": buildPrompt(prompt),
		"stream": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.BaseURL, "/")+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama request failed: %s", strings.TrimSpace(string(data)))
	}

	var parsed struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	return strings.TrimSpace(parsed.Response), nil
}

func (c *Client) analyzeOpenAICompatible(ctx context.Context, prompt string) (string, error) {
	payload := map[string]interface{}{
		"model": c.config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(c.config.BaseURL, "/")
	if !strings.HasSuffix(endpoint, "/v1") {
		endpoint += "/v1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("llm request failed: %s", strings.TrimSpace(string(data)))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("llm returned no choices")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

// Ping performs a lightweight connectivity check against the configured backend.
func (c *Client) Ping(ctx context.Context) error {
	switch c.config.Provider {
	case "ollama":
		return c.pingOllama(ctx)
	case "openai", "openai-compatible", "grok":
		return c.pingOpenAICompatible(ctx)
	case "claude":
		return c.pingClaude(ctx)
	case "gemini":
		return c.pingGemini(ctx)
	default:
		return fmt.Errorf("unsupported provider %q", c.config.Provider)
	}
}

func (c *Client) analyzeClaude(ctx context.Context, prompt string) (string, error) {
	payload := map[string]interface{}{
		"model":      c.config.Model,
		"max_tokens": 1024,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.BaseURL, "/")+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("claude request failed: %s", strings.TrimSpace(string(data)))
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	for _, part := range parsed.Content {
		if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
			return strings.TrimSpace(part.Text), nil
		}
	}
	return "", fmt.Errorf("claude returned no text content")
}

func (c *Client) analyzeGemini(ctx context.Context, prompt string) (string, error) {
	payload := map[string]interface{}{
		"system_instruction": map[string]interface{}{
			"parts": []map[string]string{
				{"text": systemPrompt},
			},
		},
		"contents": []map[string]interface{}{
			{
				"role": "user",
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.BaseURL, "/")+"/models/"+c.config.Model+":generateContent", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("gemini request failed: %s", strings.TrimSpace(string(data)))
	}

	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if len(parsed.Candidates) == 0 {
		return "", fmt.Errorf("gemini returned no candidates")
	}
	for _, part := range parsed.Candidates[0].Content.Parts {
		if strings.TrimSpace(part.Text) != "" {
			return strings.TrimSpace(part.Text), nil
		}
	}
	return "", fmt.Errorf("gemini returned no text content")
}

func (c *Client) pingOllama(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.config.BaseURL, "/")+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama connectivity check failed: %s", strings.TrimSpace(string(data)))
	}
	return nil
}

func (c *Client) pingOpenAICompatible(ctx context.Context) error {
	endpoint := strings.TrimRight(c.config.BaseURL, "/")
	if !strings.HasSuffix(endpoint, "/v1") {
		endpoint += "/v1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("model connectivity check failed: %s", strings.TrimSpace(string(data)))
	}
	return nil
}

func (c *Client) pingClaude(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.config.BaseURL, "/")+"/v1/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("claude connectivity check failed: %s", strings.TrimSpace(string(data)))
	}
	return nil
}

func (c *Client) pingGemini(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.config.BaseURL, "/")+"/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-goog-api-key", c.config.APIKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gemini connectivity check failed: %s", strings.TrimSpace(string(data)))
	}
	return nil
}

const systemPrompt = "You are a container forensics analyst. Summarize findings, explain suspicious indicators, call out likely false positives, and recommend concrete next investigative steps."

func buildPrompt(contextText string) string {
	return systemPrompt + "\n\nAnalyze this selected BoneStack context:\n\n" + contextText
}
