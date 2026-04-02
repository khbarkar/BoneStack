package sde

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/kristinb/bonestack/internal/layers"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

func TestInferProfileNode(t *testing.T) {
	g := NewGenerator()
	inspect := types.ImageInspect{Config: &dockerspec.DockerOCIImageConfig{}}
	inspect.Config.WorkingDir = "/srv/app"
	inspect.Config.ExposedPorts = map[string]struct{}{
		"3000/tcp": {},
	}
	inspect.Config.Cmd = []string{"node", "server.js"}

	profile := g.InferProfile("node:20-alpine", inspect, nil)
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
	if len(scaffold.SecurityArtifacts) == 0 {
		t.Fatal("expected security artifacts")
	}
}

func TestGenerateWithAnalysisUsesLanguageDetection(t *testing.T) {
	g := NewGenerator()
	inspect := types.ImageInspect{Config: &dockerspec.DockerOCIImageConfig{}}
	analysis := []layers.FileAnalysisResult{
		{
			LanguageDetected: []string{"Rust"},
			PackageManagers:  []string{"cargo"},
		},
	}

	scaffold := g.GenerateWithAnalysis("sha256:abc", inspect, analysis)
	if scaffold.Profile.Runtime != "rust" {
		t.Fatalf("Runtime = %q, want rust", scaffold.Profile.Runtime)
	}
	if !strings.Contains(scaffold.Dockerfile, "Cargo.lock") {
		t.Fatalf("expected cargo optimization hints in dockerfile, got:\n%s", scaffold.Dockerfile)
	}
}

func TestGenerateWithAnalysisUsesCargoPackageManagerFallback(t *testing.T) {
	g := NewGenerator()
	inspect := types.ImageInspect{Config: &dockerspec.DockerOCIImageConfig{}}
	analysis := []layers.FileAnalysisResult{
		{
			PackageManagers: []string{"cargo"},
		},
	}

	scaffold := g.GenerateWithAnalysis("sha256:abc", inspect, analysis)
	if scaffold.Profile.Runtime != "rust" {
		t.Fatalf("Runtime = %q, want rust", scaffold.Profile.Runtime)
	}
}

func TestGenerateWithAnalysisAddsBloatChecklistItem(t *testing.T) {
	g := NewGenerator()
	inspect := types.ImageInspect{Config: &dockerspec.DockerOCIImageConfig{}}
	analysis := []layers.FileAnalysisResult{
		{
			PotentialBloat: []layers.BloatFinding{
				{Path: "/var/cache/apt/pkg", Size: 60 * 1024 * 1024},
			},
		},
	}

	scaffold := g.GenerateWithAnalysis("ubuntu:22.04", inspect, analysis)
	joined := strings.Join(scaffold.PolicyChecklist, "\n")
	if !strings.Contains(joined, "bloat findings") {
		t.Fatalf("expected checklist to mention bloat findings, got:\n%s", joined)
	}
}
