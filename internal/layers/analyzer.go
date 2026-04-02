package layers

import (
	"context"
	"fmt"

	"github.com/kristinb/bonestack/internal/docker"
)

// Analyzer provides layer analysis for Docker images
type Analyzer struct {
	dockerClient *docker.Client
}

// NewAnalyzer creates a new layer analyzer
func NewAnalyzer(dockerClient *docker.Client) *Analyzer {
	return &Analyzer{
		dockerClient: dockerClient,
	}
}

// AnalyzeImage analyzes all layers in a Docker image
func (a *Analyzer) AnalyzeImage(ctx context.Context, imageID string) (*ImageLayers, error) {
	// Get image history to understand layers
	history, err := a.dockerClient.GetImageHistory(ctx, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to get image history: %w", err)
	}

	inspect, err := a.dockerClient.InspectImage(ctx, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	imageLayers := &ImageLayers{
		ImageID: imageID,
		Layers:  make([]Layer, 0),
	}

	// Build layers from history
	// History is returned in reverse order (newest first), so we reverse it
	for i := len(history) - 1; i >= 0; i-- {
		h := history[i]
		
		layer := Layer{
			ID:      h.ID,
			Size:    h.Size,
			Created: h.Created,
			Command: h.CreatedBy,
		}

		imageLayers.Layers = append(imageLayers.Layers, layer)
	}

	// If we couldn't get layers from history, use image config as fallback
	if len(imageLayers.Layers) == 0 {
		layer := Layer{
			ID:      inspect.ID,
			Size:    inspect.Size,
			Created: 0, // Created time in inspect is a string, convert if needed
			Command: "Base Layer",
		}
		imageLayers.Layers = append(imageLayers.Layers, layer)
	}

	return imageLayers, nil
}

// DetectBloat analyzes a layer for common bloat patterns
func (a *Analyzer) DetectBloat(layer Layer) []BloatItem {
	var bloatItems []BloatItem

	// Check for common bloat patterns
	// In a real implementation, we'd inspect the actual layer contents
	// For now, we use heuristics based on size and command
	
	for _, pattern := range BloatPatterns {
		// Simple detection: check if pattern name appears in layer command
		// In Phase 2.5, we'd actually inspect tar contents
		if matchesBloatPattern(layer.Command, pattern.Name) {
			bloatItem := BloatItem{
				Pattern:       pattern.Name,
				Description:   pattern.Description,
				Paths:         pattern.Paths,
				EstimatedSize: 0, // Would be calculated from actual inspection
				Removable:     pattern.Removable,
			}
			bloatItems = append(bloatItems, bloatItem)
		}
	}

	return bloatItems
}

// CompareLayers compares two consecutive layers
func (a *Analyzer) CompareLayers(from, to Layer) LayerDiff {
	// Size difference is the most reliable metric we can easily get
	diff := LayerDiff{
		FromLayer: from,
		ToLayer:   to,
		SizeChange: to.Size - from.Size,
	}

	// Heuristics for file count estimates based on size and command
	if to.Size > from.Size {
		// Layer added content
		sizeDiff := to.Size - from.Size
		diff.FilesAdded = int(sizeDiff / 5000) // Rough estimate: 5KB per file average
	} else if to.Size < from.Size {
		// Layer removed content (unusual but possible with FROM scratch)
		diff.FilesRemoved = int((from.Size - to.Size) / 5000)
	}

	return diff
}

// AnalyzeLayerSequence provides analysis for a sequence of layers
func (a *Analyzer) AnalyzeLayerSequence(imageLayers *ImageLayers) ([]LayerAnalysis, int64) {
	analyses := make([]LayerAnalysis, len(imageLayers.Layers))
	totalSize := int64(0)

	for i, layer := range imageLayers.Layers {
		bloat := a.DetectBloat(layer)
		
		analysis := LayerAnalysis{
			Layer:           layer,
			Index:           i,
			BloatIndicators: bloat,
			ConfidenceScore: 0.85, // Default confidence - improves with tar inspection
		}

		// Calculate cumulative stats
		if i > 0 {
			// Estimate files based on size difference
			sizeDiff := layer.Size
			if i > 0 {
				sizeDiff = layer.Size - imageLayers.Layers[i-1].Size
			}
			if sizeDiff > 0 {
				analysis.FilesAdded = int(sizeDiff / 5000)
			}
		} else {
			// Base layer
			analysis.FilesAdded = int(layer.Size / 5000)
		}

		analyses[i] = analysis
		totalSize += layer.Size
	}

	return analyses, totalSize
}

// matchesBloatPattern checks if a command matches a bloat pattern
func matchesBloatPattern(command, patternName string) bool {
	patterns := map[string][]string{
		"npm_cache":    {"npm", "node"},
		"apt_cache":    {"apt", "apt-get"},
		"pip_cache":    {"pip", "python"},
		"yum_cache":    {"yum"},
		"git_folders":  {"git", "clone"},
		"node_modules": {"npm", "node"},
		"vendor_dir":   {"composer", "cargo", "bundler"},
	}

	keywords, ok := patterns[patternName]
	if !ok {
		return false
	}

	for _, keyword := range keywords {
		if contains(command, keyword) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive for keywords)
func contains(str, substr string) bool {
	// Simple substring check
	for i := 0; i <= len(str)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if str[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
