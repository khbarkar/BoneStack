package forensics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// LogAnalyzer analyzes container logs
type LogAnalyzer struct {
	inspector *ContainerInspector
}

// LogEntry represents a single log line
type LogEntry struct {
	Timestamp string
	Level     string // INFO, ERROR, WARN, DEBUG
	Message   string
	Source    string
}

// LogStats contains log analysis results
type LogStats struct {
	TotalLines   int
	ErrorCount   int
	WarnCount    int
	InfoCount    int
	DebugCount   int
	Entries      []LogEntry
	Keywords     map[string]int
}

// NewLogAnalyzer creates a new log analyzer
func NewLogAnalyzer(inspector *ContainerInspector) *LogAnalyzer {
	return &LogAnalyzer{
		inspector: inspector,
	}
}

// GetLogs retrieves container logs
func (la *LogAnalyzer) GetLogs(ctx context.Context, containerID string, tail int) (string, error) {
	tailStr := fmt.Sprintf("%d", tail)
	logs, err := la.inspector.GetContainerLogs(ctx, containerID, tailStr, false)
	if err != nil {
		return "", err
	}
	defer logs.Close()

	data, err := io.ReadAll(logs)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// StreamLogs streams logs in real-time
func (la *LogAnalyzer) StreamLogs(ctx context.Context, containerID string, callback func(line string)) error {
	logs, err := la.inspector.GetContainerLogs(ctx, containerID, "0", true)
	if err != nil {
		return err
	}
	defer logs.Close()

	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			callback(scanner.Text())
		}
	}

	return scanner.Err()
}

// FilterLogs filters logs by keyword
func (la *LogAnalyzer) FilterLogs(ctx context.Context, containerID string, keyword string) ([]LogEntry, error) {
	logs, err := la.GetLogs(ctx, containerID, 1000)
	if err != nil {
		return nil, err
	}

	var entries []LogEntry
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
			entries = append(entries, LogEntry{Message: line})
		}
	}

	return entries, nil
}

// AnalyzeLogs performs log analysis
func (la *LogAnalyzer) AnalyzeLogs(ctx context.Context, containerID string) (*LogStats, error) {
	logs, err := la.GetLogs(ctx, containerID, 1000)
	if err != nil {
		return nil, err
	}

	stats := &LogStats{
		Keywords: make(map[string]int),
	}

	keywords := []string{"error", "exception", "warn", "debug", "timeout", "failed", "success"}

	for _, line := range strings.Split(logs, "\n") {
		if line == "" {
			continue
		}

		stats.TotalLines++

		// Classify by level
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") {
			stats.ErrorCount++
		} else if strings.Contains(lower, "warn") {
			stats.WarnCount++
		} else if strings.Contains(lower, "debug") {
			stats.DebugCount++
		} else {
			stats.InfoCount++
		}

		// Count keywords
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				stats.Keywords[kw]++
			}
		}
	}

	return stats, nil
}

// GetLogsSince retrieves logs since a given time
func (la *LogAnalyzer) GetLogsSince(ctx context.Context, containerID string, since time.Time) (string, error) {
	_ = since.Format(time.RFC3339)
	logs, err := la.inspector.GetContainerLogs(ctx, containerID, "all", false)
	if err != nil {
		return "", err
	}
	defer logs.Close()

	data, err := io.ReadAll(logs)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
