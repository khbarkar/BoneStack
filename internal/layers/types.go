package layers

import (
	"fmt"
)

// Layer represents a single layer in a Docker image
type Layer struct {
	ID      string // SHA256 digest
	Size    int64  // Size in bytes
	Created int64  // Unix timestamp
	Command string // Dockerfile instruction that created this layer
	Author  string // Optional author from LABEL
	Comment string // Optional comment
}

// LayerAnalysis contains analysis results for a layer
type LayerAnalysis struct {
	Layer              Layer
	Index              int           // Layer position (0 = base)
	FilesAdded         int           // Approximate files added
	DirsAdded          int           // Approximate dirs added
	LargeFiles         []string      // Paths to large files
	BloatIndicators    []BloatItem   // Detected bloat patterns
	InstalledPackages  []string      // Detected package installations
	ConfidenceScore    float64       // 0.0-1.0 estimation accuracy
}

// BloatItem represents detected bloat in a layer
type BloatItem struct {
	Pattern     string // The bloat pattern (e.g., "npm_cache", "apt_cache")
	Description string // Human-readable description
	Paths       []string // Detected paths
	EstimatedSize int64 // Approximate size
	Removable   bool   // Can this bloat be safely removed?
}

// ImageLayers holds all layers for an image
type ImageLayers struct {
	ImageID string
	Layers  []Layer
}

// OptimizationReport summarizes image optimization opportunities.
type OptimizationReport struct {
	EstimatedSavings int64
	LayerCount       int
	BloatItemCount   int
	Recommendations  []string
}

// LayerDiff represents the difference between two consecutive layers
type LayerDiff struct {
	FromLayer     Layer
	ToLayer       Layer
	FilesAdded    int
	FilesModified int
	FilesRemoved  int
	SizeChange    int64 // Positive = size increased, negative = decreased
}

// BloatPatterns defines common bloat patterns to detect
var BloatPatterns = map[string]BloatPattern{
	"npm_cache": {
		Name:        "npm cache",
		Paths:       []string{"/root/.npm", "/.npm", "/app/.npm"},
		Description: "npm package manager cache - can be removed",
		Removable:   true,
	},
	"apt_cache": {
		Name:        "apt cache",
		Paths:       []string{"/var/cache/apt", "/var/lib/apt/lists"},
		Description: "apt package manager cache - should be cleaned",
		Removable:   true,
	},
	"pip_cache": {
		Name:        "pip cache",
		Paths:       []string{"/root/.cache/pip", "/.cache/pip"},
		Description: "pip package manager cache - can be removed",
		Removable:   true,
	},
	"yum_cache": {
		Name:        "yum cache",
		Paths:       []string{"/var/cache/yum"},
		Description: "yum package manager cache - can be removed",
		Removable:   true,
	},
	"git_folders": {
		Name:        ".git folders",
		Paths:       []string{"/.git", "/app/.git"},
		Description: "Git version control metadata - unnecessary in production",
		Removable:   true,
	},
	"node_modules": {
		Name:        "node_modules",
		Paths:       []string{"/node_modules", "/app/node_modules"},
		Description: "npm dependencies (huge!) - consider multi-stage builds",
		Removable:   false, // Usually needed at runtime
	},
	"vendor_dir": {
		Name:        "vendor directories",
		Paths:       []string{"/vendor", "/app/vendor"},
		Description: "Language vendored dependencies - usually large",
		Removable:   false,
	},
}

// BloatPattern defines a pattern that indicates bloat
type BloatPattern struct {
	Name        string
	Paths       []string
	Description string
	Removable   bool
}

// String returns a string representation of a Layer
func (l Layer) String() string {
	return fmt.Sprintf("Layer{ID: %s, Size: %d bytes, Created: %d, Command: %s}",
		l.ID[:12], l.Size, l.Created, l.Command)
}

// String returns a string representation of LayerAnalysis
func (la LayerAnalysis) String() string {
	return fmt.Sprintf("LayerAnalysis{Index: %d, Files: %d, Bloat: %d}",
		la.Index, la.FilesAdded, len(la.BloatIndicators))
}

// SizeFormatter formats bytes into human-readable format
func SizeFormatter(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// PercentageOfTotal calculates percentage of a size relative to total
func PercentageOfTotal(size, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(size) / float64(total) * 100
}
