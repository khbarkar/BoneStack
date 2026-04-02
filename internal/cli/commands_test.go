package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInstallScriptPrefersResolvedExecutableDir(t *testing.T) {
	tmpDir := t.TempDir()
	exeDir := filepath.Join(tmpDir, "repo")
	linkDir := filepath.Join(tmpDir, "bin")

	if err := os.MkdirAll(exeDir, 0755); err != nil {
		t.Fatalf("mkdir exeDir: %v", err)
	}
	if err := os.MkdirAll(linkDir, 0755); err != nil {
		t.Fatalf("mkdir linkDir: %v", err)
	}

	exePath := filepath.Join(exeDir, "bonestack")
	if err := os.WriteFile(exePath, []byte("binary"), 0755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	installPath := filepath.Join(exeDir, "install.sh")
	if err := os.WriteFile(installPath, []byte("#!/usr/bin/env bash\n"), 0755); err != nil {
		t.Fatalf("write install.sh: %v", err)
	}

	linkPath := filepath.Join(linkDir, "bonestack")
	if err := os.Symlink(exePath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	path, err := resolveInstallScriptFrom(linkPath)
	if err != nil {
		t.Fatalf("resolveInstallScriptFrom failed: %v", err)
	}
	resolvedInstallPath, err := filepath.EvalSymlinks(installPath)
	if err != nil {
		resolvedInstallPath = installPath
	}
	if path != resolvedInstallPath {
		t.Fatalf("got %q want %q", path, resolvedInstallPath)
	}
}

func TestHandleCommandVersion(t *testing.T) {
	handled, err := HandleCommand([]string{"version"})
	if err != nil {
		t.Fatalf("HandleCommand returned error: %v", err)
	}
	if !handled {
		t.Fatal("expected command to be handled")
	}
}
