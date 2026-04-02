package ai

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAnalyzeOllama(t *testing.T) {
	client := NewClient(Config{Provider: "ollama", BaseURL: "http://ollama.test", Model: "llama3"})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(`{"response":"investigate /tmp/revshell.sh and compare with timeline"}`), nil
	})}
	got, err := client.Analyze(context.Background(), "test context")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !strings.Contains(got, "timeline") {
		t.Fatalf("unexpected response %q", got)
	}
}

func TestAnalyzeOpenAICompatible(t *testing.T) {
	client := NewClient(Config{Provider: "openai", BaseURL: "http://openai.test", Model: "gpt-test", APIKey: "test-key"})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected auth header %q", got)
		}
		return jsonResponse(`{"choices":[{"message":{"content":"This looks like cron persistence."}}]}`), nil
	})}
	got, err := client.Analyze(context.Background(), "test context")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !strings.Contains(got, "cron persistence") {
		t.Fatalf("unexpected response %q", got)
	}
}

func TestAnalyzeClaude(t *testing.T) {
	client := NewClient(Config{Provider: "claude", BaseURL: "http://claude.test", Model: "claude-sonnet", APIKey: "anthropic-key"})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("x-api-key"); got != "anthropic-key" {
			t.Fatalf("unexpected anthropic api key %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("unexpected anthropic version %q", got)
		}
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		return jsonResponse(`{"content":[{"type":"text","text":"Check container diff against the suspicious service file."}]}`), nil
	})}
	got, err := client.Analyze(context.Background(), "test context")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !strings.Contains(got, "service file") {
		t.Fatalf("unexpected response %q", got)
	}
}

func TestAnalyzeGemini(t *testing.T) {
	client := NewClient(Config{Provider: "gemini", BaseURL: "http://gemini.test/v1beta", Model: "gemini-2.5-flash", APIKey: "gemini-key"})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("x-goog-api-key"); got != "gemini-key" {
			t.Fatalf("unexpected gemini api key %q", got)
		}
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash:generateContent" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		return jsonResponse(`{"candidates":[{"content":{"parts":[{"text":"Look at the timeline around the restart event."}]}}]}`), nil
	})}
	got, err := client.Analyze(context.Background(), "test context")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !strings.Contains(got, "restart event") {
		t.Fatalf("unexpected response %q", got)
	}
}

func TestPingOpenAICompatible(t *testing.T) {
	client := NewClient(Config{Provider: "openai", BaseURL: "http://openai.test", Model: "gpt-test", APIKey: "test-key"})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected auth header %q", got)
		}
		return jsonResponse(`{"data":[]}`), nil
	})}
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

func TestPingClaude(t *testing.T) {
	client := NewClient(Config{Provider: "claude", BaseURL: "http://claude.test", Model: "claude-sonnet", APIKey: "anthropic-key"})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		return jsonResponse(`{"data":[]}`), nil
	})}
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
