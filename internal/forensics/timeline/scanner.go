package timeline

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// EventRow is a normalized Docker event row for TUI/report output.
type EventRow struct {
	Time    string
	Action  string
	Type    string
	Actor   string
	Details string
}

// Result captures timeline rows and summary counts.
type Result struct {
	Events  []EventRow
	Summary map[string]int
}

// Scanner wraps Docker event streaming for short forensic timeline captures.
type Scanner struct {
	client *client.Client
}

// NewScanner creates a timeline scanner.
func NewScanner(cli *client.Client) *Scanner {
	return &Scanner{client: cli}
}

// RecentContainerEvents captures recent events for the target container.
func (s *Scanner) RecentContainerEvents(ctx context.Context, containerID string, window time.Duration) (*Result, error) {
	if s.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}
	if window <= 0 {
		window = time.Hour
	}

	since := time.Now().Add(-window).UTC().Format(time.RFC3339)
	opts := events.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("container", containerID),
			filters.Arg("type", "container"),
		),
		Since: since,
	}

	streamCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()

	msgCh, errCh := s.client.Events(streamCtx, opts)
	rows := []EventRow{}
	summary := map[string]int{}

	for {
		select {
		case msg, ok := <-msgCh:
			if !ok {
				return finalize(rows, summary), nil
			}
			row := normalize(msg)
			rows = append(rows, row)
			summary[row.Action]++
		case err, ok := <-errCh:
			if !ok {
				return finalize(rows, summary), nil
			}
			// The Docker client uses context cancellation/EOF to end event streams.
			if err == nil || err == context.DeadlineExceeded || err == context.Canceled {
				return finalize(rows, summary), nil
			}
			return nil, fmt.Errorf("read docker events: %w", err)
		case <-streamCtx.Done():
			return finalize(rows, summary), nil
		}
	}
}

func finalize(rows []EventRow, summary map[string]int) *Result {
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Time > rows[j].Time
	})
	return &Result{Events: rows, Summary: summary}
}

func normalize(msg events.Message) EventRow {
	actor := msg.Actor.ID
	if name, ok := msg.Actor.Attributes["name"]; ok && name != "" {
		actor = name
	}

	detail := ""
	if image, ok := msg.Actor.Attributes["image"]; ok && image != "" {
		detail = "image=" + image
	}
	if exitCode, ok := msg.Actor.Attributes["exitCode"]; ok && exitCode != "" {
		if detail != "" {
			detail += " "
		}
		detail += "exitCode=" + exitCode
	}

	return EventRow{
		Time:    time.Unix(msg.Time, 0).UTC().Format(time.RFC3339),
		Action:  string(msg.Action),
		Type:    string(msg.Type),
		Actor:   actor,
		Details: detail,
	}
}
