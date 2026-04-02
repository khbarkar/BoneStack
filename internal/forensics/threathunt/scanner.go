package threathunt

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// CommandRunner captures the subset of container exec behavior needed for live threat hunting.
type CommandRunner interface {
	ExecCommand(ctx context.Context, containerID string, cmd []string) (string, error)
}

// Finding is one suspicious artifact or indicator discovered during a live scan.
type Finding struct {
	Category string
	Path     string
	Severity string
	Detail   string
}

// Result contains the normalized findings from a threat hunt scan.
type Result struct {
	Findings []Finding
	Summary  map[string]int
}

// Scanner performs article-inspired IOC hunting inside a live container.
type Scanner struct {
	runner CommandRunner
}

// NewScanner creates a scanner backed by a container command runner.
func NewScanner(runner CommandRunner) *Scanner {
	return &Scanner{runner: runner}
}

// HuntLive scans a running container for suspicious persistence, credential, and shell indicators.
func (s *Scanner) HuntLive(ctx context.Context, containerID string) (*Result, error) {
	if s.runner == nil {
		return nil, fmt.Errorf("command runner not initialized")
	}

	fileOutput, err := s.runner.ExecCommand(ctx, containerID, suspiciousFileCommand())
	if err != nil {
		return nil, fmt.Errorf("scan suspicious files: %w", err)
	}

	contentOutput, err := s.runner.ExecCommand(ctx, containerID, suspiciousContentCommand())
	if err != nil {
		return nil, fmt.Errorf("scan suspicious content: %w", err)
	}

	findings := append(parseSuspiciousFiles(fileOutput), parseSuspiciousContent(contentOutput)...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			if findings[i].Category == findings[j].Category {
				return findings[i].Path < findings[j].Path
			}
			return findings[i].Category < findings[j].Category
		}
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})

	return &Result{
		Findings: findings,
		Summary:  summarizeFindings(findings),
	}, nil
}

func suspiciousFileCommand() []string {
	return []string{
		"sh", "-c",
		"find / \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o -type f \\( -name '.bash_history' -o -name '._history' -o -name 'authorized_keys' -o -name '*.service' -o -name '*.sh' -o -name '*.b64' -o -path '/etc/cron*' -o -path '/var/spool/cron/*' \\) -print 2>/dev/null | head -200",
	}
}

func suspiciousContentCommand() []string {
	return []string{
		"sh", "-c",
		"find / \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o -type f \\( -name '*.sh' -o -name '*.service' -o -name '.bash_history' -o -name '._history' -o -name 'authorized_keys' -o -name '*.b64' -o -path '/etc/cron*' -o -path '/var/spool/cron/*' \\) -exec grep -HniE 'nc -e|/dev/tcp|bash -i|curl |wget |base64 -d|LD_PRELOAD' {} + 2>/dev/null | head -200",
	}
}

func parseSuspiciousFiles(output string) []Finding {
	findings := []Finding{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		category, severity, detail := classifyPath(line)
		findings = append(findings, Finding{
			Category: category,
			Path:     line,
			Severity: severity,
			Detail:   detail,
		})
	}
	return findings
}

func parseSuspiciousContent(output string) []Finding {
	findings := []Finding{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		path, detail := splitGrepLine(line)
		category, severity := classifyContent(detail)
		findings = append(findings, Finding{
			Category: category,
			Path:     path,
			Severity: severity,
			Detail:   detail,
		})
	}
	return findings
}

func splitGrepLine(line string) (string, string) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) == 3 {
		return parts[0], parts[2]
	}
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return line, line
}

func classifyPath(path string) (string, string, string) {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "authorized_keys"):
		return "ssh-persistence", "high", "SSH authorized_keys file present"
	case strings.Contains(lower, "/etc/cron") || strings.Contains(lower, "/var/spool/cron"):
		return "cron-persistence", "high", "cron persistence artifact present"
	case strings.HasSuffix(lower, ".service"):
		return "service-persistence", "medium", "service unit present"
	case strings.HasSuffix(lower, ".bash_history") || strings.HasSuffix(lower, "._history"):
		return "shell-history", "medium", "shell history artifact present"
	case strings.HasSuffix(lower, ".b64"):
		return "encoded-payload", "high", "base64 payload artifact present"
	case strings.HasSuffix(lower, ".sh"):
		return "script", "medium", "shell script artifact present"
	default:
		return "file", "low", "suspicious file matched"
	}
}

func classifyContent(detail string) (string, string) {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "nc -e"), strings.Contains(lower, "/dev/tcp"), strings.Contains(lower, "bash -i"):
		return "reverse-shell", "critical"
	case strings.Contains(lower, "ld_preload"):
		return "preload-abuse", "high"
	case strings.Contains(lower, "base64 -d"):
		return "encoded-payload", "high"
	case strings.Contains(lower, "curl "), strings.Contains(lower, "wget "):
		return "download-exec", "medium"
	default:
		return "content-match", "medium"
	}
}

func summarizeFindings(findings []Finding) map[string]int {
	summary := make(map[string]int)
	for _, finding := range findings {
		summary[finding.Category]++
	}
	return summary
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
