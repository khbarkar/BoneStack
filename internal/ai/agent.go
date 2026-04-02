package ai

import (
	"strings"
)

var allowedContextRequests = map[string]bool{
	"threat-hunt":    true,
	"container-diff": true,
	"timeline":       true,
	"logs":           true,
	"environment":    true,
	"resources":      true,
	"processes":      true,
	"filesystem":     true,
}

type AgentResponse struct {
	Analysis string
	Requests []string
}

func BuildAgentPrompt(contextText string) string {
	return contextText + `

Respond in this exact format:

ANALYSIS:
<your investigation summary, suspicious indicators, likely benign explanations, and next steps>

REQUEST_CONTEXT:
- <zero or more of: threat-hunt, container-diff, timeline, logs, environment, resources, processes, filesystem>

Only request more context if it would materially change your assessment. If no more context is needed, write:
- none
`
}

func ParseAgentResponse(text string) AgentResponse {
	lower := strings.ToLower(text)
	analysisStart := strings.Index(lower, "analysis:")
	requestStart := strings.Index(lower, "request_context:")

	response := AgentResponse{Analysis: strings.TrimSpace(text)}
	if analysisStart >= 0 {
		if requestStart > analysisStart {
			response.Analysis = strings.TrimSpace(text[analysisStart+len("analysis:") : requestStart])
		} else {
			response.Analysis = strings.TrimSpace(text[analysisStart+len("analysis:"):])
		}
	}

	if requestStart < 0 {
		return response
	}

	requestBlock := text[requestStart+len("request_context:"):]
	seen := map[string]bool{}
	for _, line := range strings.Split(requestBlock, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || line == "none" {
			continue
		}
		if allowedContextRequests[line] && !seen[line] {
			response.Requests = append(response.Requests, line)
			seen[line] = true
		}
	}

	if response.Analysis == "" {
		response.Analysis = strings.TrimSpace(text)
	}
	return response
}
