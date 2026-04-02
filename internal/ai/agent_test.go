package ai

import (
	"strings"
	"testing"
)

func TestParseAgentResponse(t *testing.T) {
	text := `ANALYSIS:
Check timeline and logs before assuming the restart was malicious.

REQUEST_CONTEXT:
- timeline
- logs
- none
- invalid
`
	resp := ParseAgentResponse(text)
	if !strings.Contains(resp.Analysis, "restart") {
		t.Fatalf("unexpected analysis %q", resp.Analysis)
	}
	if len(resp.Requests) != 2 || resp.Requests[0] != "timeline" || resp.Requests[1] != "logs" {
		t.Fatalf("unexpected requests %#v", resp.Requests)
	}
}

func TestBuildAgentPromptIncludesFormat(t *testing.T) {
	prompt := BuildAgentPrompt("Container: demo")
	if !strings.Contains(prompt, "REQUEST_CONTEXT:") || !strings.Contains(prompt, "filesystem") {
		t.Fatalf("unexpected prompt %q", prompt)
	}
}
