package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kristinb/bonestack/internal/docker"
	"github.com/kristinb/bonestack/internal/forensics"
	"github.com/kristinb/bonestack/internal/layers"
	"github.com/kristinb/bonestack/internal/models"
	"github.com/kristinb/bonestack/internal/sde"
)

func TestHandleForensicsMenuKeysRoutesToEnvironmentAndResources(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "forensics-menu"}}

	app.selectedIndex = 4
	model, _ := app.handleForensicsMenuKeys(tea.KeyMsg{Type: tea.KeyEnter})
	updated := model.(*App)
	if updated.state.CurrentScreen != "environment" {
		t.Fatalf("expected environment screen, got %q", updated.state.CurrentScreen)
	}

	updated.state.CurrentScreen = "forensics-menu"
	updated.selectedIndex = 5
	model, _ = updated.handleForensicsMenuKeys(tea.KeyMsg{Type: tea.KeyEnter})
	updated = model.(*App)
	if updated.state.CurrentScreen != "resources" {
		t.Fatalf("expected resources screen, got %q", updated.state.CurrentScreen)
	}
}

func TestRenderEnvironmentAndResourcesWithNilAnalyzers(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "environment"}}

	if out := app.renderEnvironment(); !strings.Contains(out, "Environment analyzer not initialized") {
		t.Fatalf("unexpected environment render output: %q", out)
	}

	if out := app.renderResources(); !strings.Contains(out, "Resource monitor not initialized") {
		t.Fatalf("unexpected resources render output: %q", out)
	}
}

func TestSortedHelpers(t *testing.T) {
	intLines := sortedIntMapLines(map[string]int{"b": 2, "a": 1})
	if len(intLines) != 2 || !strings.HasPrefix(intLines[0], "a:") || !strings.HasPrefix(intLines[1], "b:") {
		t.Fatalf("unexpected sortedIntMapLines output: %#v", intLines)
	}

	stringLines := sortedStringMapLines(map[string]string{"z": "2", "a": "1", "m": "3"}, 2)
	if len(stringLines) != 2 || stringLines[0] != "a=1" || stringLines[1] != "m=3" {
		t.Fatalf("unexpected sortedStringMapLines output: %#v", stringLines)
	}
}

func TestResourceHealth(t *testing.T) {
	if got := resourceHealth(nil); got != "unknown" {
		t.Fatalf("got %q want unknown", got)
	}
	if got := resourceHealth(&forensics.ResourceStats{CPUPercent: 20, MemoryPercent: 40}); got != "normal" {
		t.Fatalf("got %q want normal", got)
	}
	if got := resourceHealth(&forensics.ResourceStats{CPUPercent: 80, MemoryPercent: 40}); got != "elevated" {
		t.Fatalf("got %q want elevated", got)
	}
	if got := resourceHealth(&forensics.ResourceStats{CPUPercent: 20, MemoryPercent: 95}); got != "critical" {
		t.Fatalf("got %q want critical", got)
	}
}

func TestHandleImageDetailKeysRoutesToOptimization(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "image-detail", ImageLayers: &layers.ImageLayers{}}}
	model, _ := app.handleImageDetailKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	updated := model.(*App)
	if updated.state.CurrentScreen != "optimization" {
		t.Fatalf("expected optimization screen, got %q", updated.state.CurrentScreen)
	}
}

func TestRenderOptimizationWithoutLayers(t *testing.T) {
	app := &App{
		bloatDetector: layers.NewBloatDetector(),
		state:         &models.AppState{CurrentScreen: "optimization", AnalysisStatus: "Preparing optimization analysis..."},
	}

	out := app.renderOptimization()
	if !strings.Contains(out, "Preparing optimization analysis") {
		t.Fatalf("unexpected optimization render output: %q", out)
	}
}

func TestHandleImageDetailKeysRoutesToScaffold(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "image-detail", ImageLayers: &layers.ImageLayers{}}}
	model, _ := app.handleImageDetailKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	updated := model.(*App)
	if updated.state.CurrentScreen != "scaffold" {
		t.Fatalf("expected scaffold screen, got %q", updated.state.CurrentScreen)
	}
}

func TestLayersLoadedMsgRoutesToTargetScreen(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "image-detail"}}
	model, _ := app.Update(layersLoadedMsg{
		layers:          &layers.ImageLayers{},
		analyses:        []layers.LayerAnalysis{},
		bloat:           map[int][]layers.BloatItem{},
		recommendations: []string{},
		targetScreen:    "optimization",
	})
	updated := model.(*App)
	if updated.state.CurrentScreen != "optimization" {
		t.Fatalf("expected optimization screen, got %q", updated.state.CurrentScreen)
	}
}

func TestHandleScaffoldKeysBack(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "scaffold"}}
	model, _ := app.handleScaffoldKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	updated := model.(*App)
	if updated.state.CurrentScreen != "image-detail" {
		t.Fatalf("expected image-detail screen, got %q", updated.state.CurrentScreen)
	}
}

func TestRenderScaffoldWithoutDockerClient(t *testing.T) {
	app := &App{
		scaffoldGenerator: sde.NewGenerator(),
		state: &models.AppState{
			CurrentScreen: "scaffold",
			SelectedImage: docker.ImageSummary{ID: "sha256:abc"},
		},
	}

	out := app.renderScaffold()
	if !strings.Contains(out, "Error inspecting image") {
		t.Fatalf("unexpected scaffold render output: %q", out)
	}
}

func TestScaffoldAnalysisFindingLines(t *testing.T) {
	lines := scaffoldAnalysisFindingLines([]layers.FileAnalysisResult{
		{
			PotentialBloat: []layers.BloatFinding{
				{Path: "/var/cache/apt/pkg", Type: "cache", Severity: "high"},
			},
		},
	})
	if len(lines) != 1 || !strings.Contains(lines[0], "/var/cache/apt/pkg") {
		t.Fatalf("unexpected analysis lines: %#v", lines)
	}
}

func TestExportScaffoldWritesFiles(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	app := &App{
		state: &models.AppState{
			SelectedImage: docker.ImageSummary{RepoTags: []string{"example:latest"}},
			Scaffold: sde.Scaffold{
				Dockerfile: "FROM alpine:3.20",
				SecurityArtifacts: []sde.GeneratedArtifact{
					{Name: ".dockerignore", Content: ".git"},
					{Name: "policy/test.md", Content: "policy"},
				},
			},
		},
	}

	msg := app.exportScaffold()().(scaffoldExportedMsg)
	if !strings.Contains(msg.message, "wrote scaffold files") {
		t.Fatalf("unexpected export message: %q", msg.message)
	}

	wantFiles := []string{
		filepath.Join(tmpDir, ".bonestack", "scaffolds", "example_latest", "Dockerfile.generated"),
		filepath.Join(tmpDir, ".bonestack", "scaffolds", "example_latest", ".dockerignore"),
		filepath.Join(tmpDir, ".bonestack", "scaffolds", "example_latest", "policy", "test.md"),
	}
	for _, file := range wantFiles {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("expected exported file %s: %v", file, err)
		}
	}
}
