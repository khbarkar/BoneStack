package main

import (
	"context"
	"fmt"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kristinb/bonestack/internal/cli"
	"github.com/kristinb/bonestack/internal/docker"
	"github.com/kristinb/bonestack/internal/ui"
)

func main() {
	if handled, err := cli.HandleCommand(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ctx := context.Background()

	dockerClient, err := docker.NewClient(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Make sure Docker daemon is running.\n")
		os.Exit(1)
	}
	defer dockerClient.Close()

	app := ui.NewApp(ctx, dockerClient)
	p := tea.NewProgram(app, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
