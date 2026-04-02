package containerdiff

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Change represents one filesystem diff entry from Docker.
type Change struct {
	Path       string
	Kind       string
	Suspicious bool
	Detail     string
}

// Result contains diff findings and rollup counts.
type Result struct {
	Changes []Change
	Summary map[string]int
}

// Scanner wraps Docker ContainerDiff for forensics use.
type Scanner struct {
	client *client.Client
}

// NewScanner creates a container diff scanner.
func NewScanner(cli *client.Client) *Scanner {
	return &Scanner{client: cli}
}

// Diff returns normalized filesystem changes for a container.
func (s *Scanner) Diff(ctx context.Context, containerID string) (*Result, error) {
	if s.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	changes, err := s.client.ContainerDiff(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("container diff failed: %w", err)
	}

	rows := make([]Change, 0, len(changes))
	summary := map[string]int{
		"added":      0,
		"modified":   0,
		"deleted":    0,
		"suspicious": 0,
	}

	for _, change := range changes {
		row := Change{
			Path:       change.Path,
			Kind:       kindString(change.Kind),
			Suspicious: isSuspiciousPath(change.Path),
			Detail:     describePath(change.Path),
		}
		summary[row.Kind]++
		if row.Suspicious {
			summary["suspicious"]++
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Suspicious == rows[j].Suspicious {
			if rows[i].Kind == rows[j].Kind {
				return rows[i].Path < rows[j].Path
			}
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].Suspicious
	})

	return &Result{Changes: rows, Summary: summary}, nil
}

func kindString(kind container.ChangeType) string {
	switch kind {
	case container.ChangeAdd:
		return "added"
	case container.ChangeDelete:
		return "deleted"
	default:
		return "modified"
	}
}

func isSuspiciousPath(path string) bool {
	lower := strings.ToLower(path)
	suspiciousMarkers := []string{
		"/etc/cron", "/var/spool/cron", "authorized_keys", ".ssh/",
		".bash_history", "._history", ".service", "ld.so.preload",
		"/tmp/", "/dev/shm/", ".b64", "revshell", "malware",
	}
	for _, marker := range suspiciousMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func describePath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "authorized_keys"):
		return "SSH persistence candidate"
	case strings.Contains(lower, "/etc/cron") || strings.Contains(lower, "/var/spool/cron"):
		return "cron persistence candidate"
	case strings.Contains(lower, ".service"):
		return "service persistence candidate"
	case strings.Contains(lower, "ld.so.preload"):
		return "LD_PRELOAD tampering candidate"
	case strings.Contains(lower, ".bash_history") || strings.Contains(lower, "._history"):
		return "shell history artifact"
	case strings.Contains(lower, "/tmp/") || strings.Contains(lower, "/dev/shm/"):
		return "temporary payload location"
	default:
		return "filesystem change"
	}
}
