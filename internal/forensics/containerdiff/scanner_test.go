package containerdiff

import (
	"context"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
)

func TestKindString(t *testing.T) {
	if got := kindString(container.ChangeAdd); got != "added" {
		t.Fatalf("got %q want added", got)
	}
	if got := kindString(container.ChangeDelete); got != "deleted" {
		t.Fatalf("got %q want deleted", got)
	}
	if got := kindString(container.ChangeModify); got != "modified" {
		t.Fatalf("got %q want modified", got)
	}
}

func TestSuspiciousPathHeuristics(t *testing.T) {
	paths := []string{
		"/var/spool/cron/crontabs/root",
		"/root/.ssh/authorized_keys",
		"/etc/ld.so.preload",
		"/tmp/revshell.sh",
	}
	for _, path := range paths {
		if !isSuspiciousPath(path) {
			t.Fatalf("expected suspicious path for %q", path)
		}
	}

	if isSuspiciousPath("/app/static/index.html") {
		t.Fatal("did not expect static asset to be suspicious")
	}
}

func TestDescribePath(t *testing.T) {
	cases := map[string]string{
		"/etc/systemd/system/backdoor.service": "service persistence candidate",
		"/root/.bash_history":                  "shell history artifact",
		"/tmp/payload":                         "temporary payload location",
	}
	for path, want := range cases {
		if got := describePath(path); !strings.Contains(got, want) {
			t.Fatalf("describePath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestScannerNilClient(t *testing.T) {
	_, err := NewScanner(nil).Diff(context.Background(), "abc")
	if err == nil {
		t.Fatal("expected nil client error")
	}
}
