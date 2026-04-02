package layers

import (
	"testing"
)

func TestLayerString(t *testing.T) {
	layer := Layer{
		ID:      "sha256:1234567890abcdef",
		Size:    1024000,
		Created: 1234567890,
		Command: "RUN apt-get install",
	}

	result := layer.String()
	if result == "" {
		t.Error("Layer.String() returned empty string")
	}
}

func TestSizeFormatter(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{512, "512 B"},
		{1024, "1.00 KB"},
		{1024 * 1024, "1.00 MB"},
		{1024 * 1024 * 1024, "1.00 GB"},
	}

	for _, test := range tests {
		result := SizeFormatter(test.bytes)
		if result == "" {
			t.Errorf("SizeFormatter(%d) returned empty string", test.bytes)
		}
	}
}

func TestPercentageOfTotal(t *testing.T) {
	tests := []struct {
		size     int64
		total    int64
		expected float64
	}{
		{50, 100, 50.0},
		{25, 100, 25.0},
		{100, 200, 50.0},
		{0, 100, 0.0},
	}

	for _, test := range tests {
		result := PercentageOfTotal(test.size, test.total)
		if result != test.expected {
			t.Errorf("PercentageOfTotal(%d, %d) = %f, want %f", test.size, test.total, result, test.expected)
		}
	}
}

func TestBloatDetectorInit(t *testing.T) {
	detector := NewBloatDetector()
	if detector == nil {
		t.Error("NewBloatDetector() returned nil")
	}
}

func TestDiffEngineInit(t *testing.T) {
	engine := NewDiffEngine()
	if engine == nil {
		t.Error("NewDiffEngine() returned nil")
	}
}

func TestBloatPatterns(t *testing.T) {
	if len(BloatPatterns) == 0 {
		t.Error("BloatPatterns is empty")
	}

	for key, pattern := range BloatPatterns {
		if pattern.Name == "" {
			t.Errorf("BloatPattern %s has empty Name", key)
		}
		if len(pattern.Paths) == 0 {
			t.Errorf("BloatPattern %s has no Paths", key)
		}
	}
}

func TestLayerAnalysisString(t *testing.T) {
	analysis := LayerAnalysis{
		Index:       0,
		FilesAdded:  100,
		BloatIndicators: []BloatItem{
			{Pattern: "apt_cache"},
		},
	}

	result := analysis.String()
	if result == "" {
		t.Error("LayerAnalysis.String() returned empty string")
	}
}

func TestDiffSummary(t *testing.T) {
	engine := NewDiffEngine()
	diffs := []LayerDiff{
		{
			SizeChange:    1024 * 1024,
			FilesAdded:    10,
			FilesRemoved:  0,
		},
	}

	summary := engine.SummarizeChanges(diffs)
	if summary == "" {
		t.Error("SummarizeChanges() returned empty string")
	}
}

func TestFindLargestChanges(t *testing.T) {
	engine := NewDiffEngine()
	diffs := []LayerDiff{
		{SizeChange: 100},
		{SizeChange: 50},
		{SizeChange: 200},
	}

	largest := engine.FindLargestChanges(diffs, 2)
	if len(largest) == 0 {
		t.Error("FindLargestChanges() returned no results")
	}
	if len(largest) > 2 {
		t.Errorf("FindLargestChanges() returned %d results, expected at most 2", len(largest))
	}
}

func TestEstimateSavings(t *testing.T) {
	detector := NewBloatDetector()
	bloatMap := map[int][]BloatItem{
		0: {
			{Pattern: "apt_cache", Removable: true, EstimatedSize: 100},
			{Pattern: "build_tools", Removable: false, EstimatedSize: 200},
		},
	}

	savings := detector.EstimateSavings(bloatMap)
	if savings != 100 {
		t.Errorf("EstimateSavings() = %d, want 100", savings)
	}
}
