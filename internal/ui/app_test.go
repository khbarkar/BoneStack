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

	updated.state.CurrentScreen = "forensics-menu"
	updated.selectedIndex = 6
	model, _ = updated.handleForensicsMenuKeys(tea.KeyMsg{Type: tea.KeyEnter})
	updated = model.(*App)
	if updated.state.CurrentScreen != "container-diff" {
		t.Fatalf("expected container-diff screen, got %q", updated.state.CurrentScreen)
	}

	updated.state.CurrentScreen = "forensics-menu"
	updated.selectedIndex = 7
	model, _ = updated.handleForensicsMenuKeys(tea.KeyMsg{Type: tea.KeyEnter})
	updated = model.(*App)
	if updated.state.CurrentScreen != "timeline" {
		t.Fatalf("expected timeline screen, got %q", updated.state.CurrentScreen)
	}

	updated.state.CurrentScreen = "forensics-menu"
	updated.selectedIndex = 8
	model, _ = updated.handleForensicsMenuKeys(tea.KeyMsg{Type: tea.KeyEnter})
	updated = model.(*App)
	if updated.state.CurrentScreen != "threat-hunt" {
		t.Fatalf("expected threat-hunt screen, got %q", updated.state.CurrentScreen)
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

func TestRenderThreatHuntWithoutFindings(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "threat-hunt", AnalysisStatus: "Scanning complete."}}

	out := app.renderThreatHunt()
	if !strings.Contains(out, "No threat-hunt findings loaded") {
		t.Fatalf("unexpected threat-hunt render output: %q", out)
	}
}

func TestRenderContainerDiffWithoutFindings(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "container-diff", AnalysisStatus: "Diff complete."}}

	out := app.renderContainerDiff()
	if !strings.Contains(out, "No container diff changes loaded") {
		t.Fatalf("unexpected container-diff render output: %q", out)
	}
}

func TestRenderTimelineWithoutEvents(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "timeline", AnalysisStatus: "Timeline complete."}}

	out := app.renderTimeline()
	if !strings.Contains(out, "No timeline events loaded") {
		t.Fatalf("unexpected timeline render output: %q", out)
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

func TestThreatHuntLoadedMsgUpdatesState(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "forensics-menu"}}
	model, _ := app.Update(threatHuntLoadedMsg{
		findings: []map[string]string{{"category": "reverse-shell", "severity": "critical", "path": "/tmp/x.sh", "detail": "bash -i"}},
		summary:  map[string]int{"reverse-shell": 1},
		status:   "Threat hunt completed.",
	})
	updated := model.(*App)
	if updated.state.CurrentScreen != "threat-hunt" {
		t.Fatalf("expected threat-hunt screen, got %q", updated.state.CurrentScreen)
	}
	if len(updated.state.ThreatFindings) != 1 {
		t.Fatalf("expected 1 threat finding, got %d", len(updated.state.ThreatFindings))
	}
	if updated.state.ThreatSummary["reverse-shell"] != 1 {
		t.Fatalf("unexpected threat summary: %#v", updated.state.ThreatSummary)
	}
}

func TestContainerDiffLoadedMsgUpdatesState(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "forensics-menu"}}
	model, _ := app.Update(containerDiffLoadedMsg{
		changes: []map[string]string{{"kind": "added", "path": "/tmp/x.sh", "suspicious": "true", "detail": "temporary payload location"}},
		summary: map[string]int{"added": 1, "suspicious": 1},
		status:  "Container diff loaded.",
	})
	updated := model.(*App)
	if updated.state.CurrentScreen != "container-diff" {
		t.Fatalf("expected container-diff screen, got %q", updated.state.CurrentScreen)
	}
	if len(updated.state.DiffChanges) != 1 {
		t.Fatalf("expected 1 diff change, got %d", len(updated.state.DiffChanges))
	}
	if updated.state.DiffSummary["suspicious"] != 1 {
		t.Fatalf("unexpected diff summary: %#v", updated.state.DiffSummary)
	}
}

func TestTimelineLoadedMsgUpdatesState(t *testing.T) {
	app := &App{state: &models.AppState{CurrentScreen: "forensics-menu"}}
	model, _ := app.Update(timelineLoadedMsg{
		events:  []map[string]string{{"time": "2026-04-02T10:00:00Z", "action": "start", "actor": "attacker-lab1", "details": "image=attacker-lab:latest"}},
		summary: map[string]int{"start": 1},
		status:  "Timeline loaded.",
	})
	updated := model.(*App)
	if updated.state.CurrentScreen != "timeline" {
		t.Fatalf("expected timeline screen, got %q", updated.state.CurrentScreen)
	}
	if len(updated.state.TimelineEvents) != 1 {
		t.Fatalf("expected 1 timeline event, got %d", len(updated.state.TimelineEvents))
	}
	if updated.state.TimelineSummary["start"] != 1 {
		t.Fatalf("unexpected timeline summary: %#v", updated.state.TimelineSummary)
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
	if msg.path == "" {
		t.Fatal("expected export path to be set")
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

func TestExportOptimizationReportWritesFiles(t *testing.T) {
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
			ImageLayers: &layers.ImageLayers{
				Layers: []layers.Layer{
					{Size: 100, Command: "RUN apt-get install curl"},
				},
			},
			BloatDetection: map[int][]layers.BloatItem{
				0: {{Pattern: "apt_cache", Description: "cache", EstimatedSize: 10}},
			},
			OptimizationReport: layers.OptimizationReport{
				EstimatedSavings: 10,
				LayerCount:       1,
				BloatItemCount:   1,
				Recommendations:  []string{"Clean apt cache"},
			},
			FileAnalysis: []layers.FileAnalysisResult{
				{PotentialBloat: []layers.BloatFinding{{Path: "/var/cache/apt/pkg", Type: "cache", Severity: "high", Size: 10}}},
			},
		},
	}

	msg := app.exportOptimizationReport()().(optimizationExportedMsg)
	if !strings.Contains(msg.message, "wrote JSON/CSV/HTML reports") {
		t.Fatalf("unexpected export message: %q", msg.message)
	}
	if msg.path == "" {
		t.Fatal("expected export path to be set")
	}

	wantFiles := []string{
		filepath.Join(tmpDir, ".bonestack", "reports", "example_latest", "optimization.json"),
		filepath.Join(tmpDir, ".bonestack", "reports", "example_latest", "optimization.csv"),
		filepath.Join(tmpDir, ".bonestack", "reports", "example_latest", "optimization.html"),
	}
	for _, file := range wantFiles {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("expected exported report %s: %v", file, err)
		}
	}
}

func TestExportContainerForensicsReportWritesFiles(t *testing.T) {
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
			SelectedContainer: docker.ContainerSummary{ID: "abc123", Names: []string{"/attacker-lab1"}},
			ThreatFindings: []map[string]string{
				{"category": "reverse-shell", "path": "/tmp/revshell.sh", "severity": "critical", "detail": "bash -i"},
			},
			ThreatSummary: map[string]int{"reverse-shell": 1},
			DiffChanges: []map[string]string{
				{"kind": "added", "path": "/root/.ssh/authorized_keys", "suspicious": "true", "detail": "SSH persistence candidate"},
			},
			DiffSummary: map[string]int{"added": 1, "suspicious": 1},
			TimelineEvents: []map[string]string{
				{"time": "2026-04-02T10:00:00Z", "action": "start", "type": "container", "actor": "attacker-lab1", "details": "image=attacker-lab:latest"},
			},
			TimelineSummary: map[string]int{"start": 1},
		},
	}

	msg := app.exportContainerForensicsReport()().(optimizationExportedMsg)
	if !strings.Contains(msg.message, "wrote container forensics reports") {
		t.Fatalf("unexpected export message: %q", msg.message)
	}

	wantFiles := []string{
		filepath.Join(tmpDir, ".bonestack", "reports", "attacker-lab1", "forensics.json"),
		filepath.Join(tmpDir, ".bonestack", "reports", "attacker-lab1", "forensics.csv"),
		filepath.Join(tmpDir, ".bonestack", "reports", "attacker-lab1", "forensics.html"),
	}
	for _, file := range wantFiles {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("expected exported report %s: %v", file, err)
		}
	}
}
