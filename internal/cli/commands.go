package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	InstallURL   = "https://raw.githubusercontent.com/khbarkar/BoneStack/main/install.sh"
	Version      = "v0.4.0"
	ReleaseLabel = "Container Forensics Expansion"
)

// HandleCommand runs non-TUI CLI commands. It returns true when a command was handled.
func HandleCommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}

	switch args[0] {
	case "help", "--help", "-h":
		printHelp()
		return true, nil
	case "version", "--version", "-v":
		printVersion()
		return true, nil
	case "update":
		return true, runUpdate()
	default:
		return false, nil
	}
}

func printHelp() {
	fmt.Println("BoneStack")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  bonestack           Start the TUI")
	fmt.Println("  bonestack update    Update or install BoneStack")
	fmt.Println("  bonestack version   Show version")
	fmt.Println("  bonestack help      Show this help")
	fmt.Println()
	fmt.Printf("Installer URL: %s\n", InstallURL)
}

func printVersion() {
	fmt.Printf("BoneStack %s - %s\n", Version, ReleaseLabel)
}

func runUpdate() error {
	scriptPath, err := resolveInstallScript()
	if err != nil {
		return err
	}

	cmd := exec.Command("bash", scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func resolveInstallScript() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	return resolveInstallScriptFrom(exePath)
}

func resolveInstallScriptFrom(exePath string) (string, error) {
	realExePath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realExePath = exePath
	}

	candidates := []string{
		filepath.Join(filepath.Dir(realExePath), "install.sh"),
		filepath.Join(filepath.Dir(exePath), "install.sh"),
		filepath.Join(".", "install.sh"),
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not find install.sh near %s; use %s", realExePath, InstallURL)
}
