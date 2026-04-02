package timeline

import (
	"testing"
	"time"

	"github.com/docker/docker/api/types/events"
)

func TestNormalize(t *testing.T) {
	msg := events.Message{
		Type:   "container",
		Action: "die",
		Time:   time.Date(2026, 4, 2, 10, 0, 0, 0, time.UTC).Unix(),
		Actor: events.Actor{
			ID: "abc123",
			Attributes: map[string]string{
				"name":     "attacker-lab1",
				"image":    "attacker-lab:latest",
				"exitCode": "137",
			},
		},
	}

	row := normalize(msg)
	if row.Actor != "attacker-lab1" {
		t.Fatalf("got actor %q", row.Actor)
	}
	if row.Time != "2026-04-02T10:00:00Z" {
		t.Fatalf("got time %q", row.Time)
	}
	if row.Details != "image=attacker-lab:latest exitCode=137" {
		t.Fatalf("got details %q", row.Details)
	}
}

func TestFinalizeSortsDescending(t *testing.T) {
	result := finalize([]EventRow{
		{Time: "2026-04-02T09:00:00Z", Action: "start"},
		{Time: "2026-04-02T10:00:00Z", Action: "die"},
	}, map[string]int{"start": 1, "die": 1})

	if len(result.Events) != 2 {
		t.Fatalf("got %d events", len(result.Events))
	}
	if result.Events[0].Action != "die" {
		t.Fatalf("expected newest event first, got %q", result.Events[0].Action)
	}
}
