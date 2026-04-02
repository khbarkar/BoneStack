package sde

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

func TestInferProfileNode(t *testing.T) {
	g := NewGenerator()
	inspect := types.ImageInspect{Config: &dockerspec.DockerOCIImageConfig{}}
	inspect.Config.WorkingDir = "/srv/app"
	inspect.Config.ExposedPorts = map[string]struct{}{
		"3000/tcp": struct{}{},
	}
	inspect.Config.Cmd = []string{"node", "server.js"}

	profile := g.InferProfile("node:20-alpine", inspect)
	if profile.Runtime != "node" {
		t.Fatalf("Runtime = %q, want node", profile.Runtime)
	}
	if profile.Workdir != "/srv/app" {
		t.Fatalf("Workdir = %q, want /srv/app", profile.Workdir)
	}
	if len(profile.ExposedPorts) != 1 || profile.ExposedPorts[0] != "3000/tcp" {
		t.Fatalf("unexpected ports: %#v", profile.ExposedPorts)
	}
}

func TestGeneratePythonScaffold(t *testing.T) {
	g := NewGenerator()
	inspect := types.ImageInspect{Config: &dockerspec.DockerOCIImageConfig{}}
	inspect.Config.Cmd = []string{"python", "app.py"}

	scaffold := g.Generate("python:3.12-slim", inspect)
	if !strings.Contains(scaffold.Dockerfile, "pip install --no-cache-dir") {
		t.Fatalf("expected python dockerfile, got:\n%s", scaffold.Dockerfile)
	}
	if len(scaffold.PolicyChecklist) == 0 {
		t.Fatal("expected policy checklist items")
	}
}
