package yarascan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrYARANotInstalled = errors.New("yara binary not installed")

// CommandRunner captures the subset of container exec behavior needed for live file collection.
type CommandRunner interface {
	ExecCommand(ctx context.Context, containerID string, cmd []string) (string, error)
}

// BinaryRunner abstracts host binary execution for testing.
type BinaryRunner interface {
	LookPath(file string) (string, error)
	Output(name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (execRunner) Output(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Finding is a YARA-backed finding mapped back to the original container path.
type Finding struct {
	Rule     string
	Path     string
	Severity string
	Detail   string
}

// Scanner runs host-side YARA against suspicious files collected from a live container.
type Scanner struct {
	runner CommandRunner
	binary BinaryRunner
}

// NewScanner creates a new YARA scanner.
func NewScanner(runner CommandRunner) *Scanner {
	return &Scanner{
		runner: runner,
		binary: execRunner{},
	}
}

// ScanLive collects suspicious files from a container and scans them with local YARA.
func (s *Scanner) ScanLive(ctx context.Context, containerID string) ([]Finding, error) {
	if s.runner == nil {
		return nil, fmt.Errorf("command runner not initialized")
	}
	if _, err := s.binary.LookPath("yara"); err != nil {
		return nil, ErrYARANotInstalled
	}

	output, err := s.runner.ExecCommand(ctx, containerID, candidateFileCommand())
	if err != nil {
		return nil, fmt.Errorf("collect yara candidate files: %w", err)
	}

	paths := parseCandidatePaths(output)
	if len(paths) == 0 {
		return nil, nil
	}

	tmpDir, err := os.MkdirTemp("", "bonestack-yara-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rulePath := filepath.Join(tmpDir, "bonestack-default.yar")
	if err := os.WriteFile(rulePath, []byte(defaultRules), 0644); err != nil {
		return nil, fmt.Errorf("write yara rules: %w", err)
	}

	pathMap := make(map[string]string)
	for i, originalPath := range paths {
		content, err := s.runner.ExecCommand(ctx, containerID, fileReadCommand(originalPath))
		if err != nil || strings.TrimSpace(content) == "" {
			continue
		}

		hostPath := filepath.Join(tmpDir, fmt.Sprintf("candidate-%03d.txt", i))
		if err := os.WriteFile(hostPath, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("write temp candidate: %w", err)
		}
		pathMap[hostPath] = originalPath
	}

	if len(pathMap) == 0 {
		return nil, nil
	}

	raw, err := s.binary.Output("yara", "-r", rulePath, tmpDir)
	if err != nil && len(raw) == 0 {
		return nil, fmt.Errorf("run yara: %w", err)
	}

	return parseYARAOutput(string(raw), pathMap), nil
}

func candidateFileCommand() []string {
	return []string{
		"sh", "-c",
		"find / \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o -type f \\( -name '.bash_history' -o -name '._history' -o -name 'authorized_keys' -o -name '*.service' -o -name '*.sh' -o -name '*.b64' -o -name '*.conf' -o -path '/etc/cron*' -o -path '/var/spool/cron/*' \\) -print 2>/dev/null | head -50",
	}
}

func fileReadCommand(path string) []string {
	return []string{
		"sh", "-c",
		fmt.Sprintf("head -c 65536 %s 2>/dev/null", shellQuote(path)),
	}
}

func parseCandidatePaths(output string) []string {
	paths := []string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths
}

func parseYARAOutput(output string, pathMap map[string]string) []Finding {
	findings := []Finding{}
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		rule := parts[0]
		hostPath := parts[len(parts)-1]
		originalPath, ok := pathMap[hostPath]
		if !ok {
			continue
		}

		key := rule + "|" + originalPath
		if seen[key] {
			continue
		}
		seen[key] = true

		findings = append(findings, Finding{
			Rule:     rule,
			Path:     originalPath,
			Severity: severityForRule(rule),
			Detail:   "YARA rule matched: " + rule,
		})
	}
	return findings
}

func severityForRule(rule string) string {
	switch rule {
	case "BoneStackReverseShell", "BoneStackLDPreload":
		return "high"
	case "BoneStackDownloadExec", "BoneStackEncodedPayload", "BoneStackSSHKeyDrop", "BoneStackCronPersistence":
		return "medium"
	default:
		return "low"
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

const defaultRules = `
rule BoneStackReverseShell {
  strings:
    $a = "nc -e" ascii nocase
    $b = "/dev/tcp/" ascii nocase
    $c = "bash -i" ascii nocase
  condition:
    any of them
}

rule BoneStackDownloadExec {
  strings:
    $a = "curl " ascii nocase
    $b = "wget " ascii nocase
    $c = "| sh" ascii nocase
  condition:
    (1 of ($a,$b)) and $c
}

rule BoneStackLDPreload {
  strings:
    $a = "LD_PRELOAD" ascii nocase
    $b = "/etc/ld.so.preload" ascii nocase
  condition:
    any of them
}

rule BoneStackEncodedPayload {
  strings:
    $a = "base64 -d" ascii nocase
    $b = ".b64" ascii nocase
  condition:
    any of them
}

rule BoneStackSSHKeyDrop {
  strings:
    $a = "ssh-rsa" ascii nocase
    $b = "authorized_keys" ascii nocase
  condition:
    any of them
}

rule BoneStackCronPersistence {
  strings:
    $a = "/etc/cron" ascii nocase
    $b = "crontab" ascii nocase
    $c = "@reboot" ascii nocase
  condition:
    any of them
}
`
