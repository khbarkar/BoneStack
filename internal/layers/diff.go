package layers

import (
	"fmt"
)

// DiffEngine provides layer comparison functionality
type DiffEngine struct{}

// NewDiffEngine creates a new diff engine
func NewDiffEngine() *DiffEngine {
	return &DiffEngine{}
}

// Compare generates a detailed diff between two ImageLayers
func (d *DiffEngine) Compare(from, to *ImageLayers) []LayerDiff {
	diffs := make([]LayerDiff, 0)

	// Compare corresponding layers
	minLen := len(from.Layers)
	if len(to.Layers) < minLen {
		minLen = len(to.Layers)
	}

	for i := 0; i < minLen; i++ {
		diff := LayerDiff{
			FromLayer:  from.Layers[i],
			ToLayer:    to.Layers[i],
			SizeChange: to.Layers[i].Size - from.Layers[i].Size,
		}

		// Estimate file changes based on size difference
		if diff.SizeChange > 0 {
			diff.FilesAdded = int(diff.SizeChange / 5000)
		} else if diff.SizeChange < 0 {
			diff.FilesRemoved = int(-diff.SizeChange / 5000)
		}

		diffs = append(diffs, diff)
	}

	// Handle layers that exist in only one image
	if len(to.Layers) > len(from.Layers) {
		for i := minLen; i < len(to.Layers); i++ {
			diff := LayerDiff{
				ToLayer:    to.Layers[i],
				SizeChange: to.Layers[i].Size,
				FilesAdded: int(to.Layers[i].Size / 5000),
			}
			diffs = append(diffs, diff)
		}
	} else if len(from.Layers) > len(to.Layers) {
		for i := minLen; i < len(from.Layers); i++ {
			diff := LayerDiff{
				FromLayer:  from.Layers[i],
				SizeChange: -from.Layers[i].Size,
				FilesRemoved: int(from.Layers[i].Size / 5000),
			}
			diffs = append(diffs, diff)
		}
	}

	return diffs
}

// SummarizeChanges produces a human-readable summary of differences
func (d *DiffEngine) SummarizeChanges(diffs []LayerDiff) string {
	if len(diffs) == 0 {
		return "No differences found"
	}

	totalAdded := int64(0)
	totalRemoved := int64(0)
	changedLayers := 0

	for _, diff := range diffs {
		if diff.SizeChange > 0 {
			totalAdded += diff.SizeChange
			changedLayers++
		} else if diff.SizeChange < 0 {
			totalRemoved += -diff.SizeChange
			changedLayers++
		}
	}

	netChange := totalAdded - totalRemoved
	summary := fmt.Sprintf("Layers changed: %d\n", changedLayers)
	summary += fmt.Sprintf("Total added: %s\n", SizeFormatter(totalAdded))
	summary += fmt.Sprintf("Total removed: %s\n", SizeFormatter(totalRemoved))
	summary += fmt.Sprintf("Net change: %+s", SizeFormatter(netChange))

	return summary
}

// FindLargestChanges identifies the layers with the biggest size changes
func (d *DiffEngine) FindLargestChanges(diffs []LayerDiff, limit int) []LayerDiff {
	if limit > len(diffs) {
		limit = len(diffs)
	}

	// Simple selection - would benefit from proper sorting in real implementation
	largest := make([]LayerDiff, 0, limit)

	for _, diff := range diffs {
		if len(largest) < limit {
			largest = append(largest, diff)
		} else {
			// Find smallest in current list and replace if current is larger
			minIdx := 0
			minVal := absDiff(largest[0].SizeChange)

			for i := 1; i < len(largest); i++ {
				if val := absDiff(largest[i].SizeChange); val < minVal {
					minVal = val
					minIdx = i
				}
			}

			if absDiff(diff.SizeChange) > minVal {
				largest[minIdx] = diff
			}
		}
	}

	return largest
}

// absDiff returns absolute value of a size change
func absDiff(change int64) int64 {
	if change < 0 {
		return -change
	}
	return change
}

// LayerChangeMetrics calculates statistics about layer changes
type LayerChangeMetrics struct {
	TotalLayersInFirst  int
	TotalLayersInSecond int
	LayersAdded         int
	LayersRemoved       int
	LayersModified      int
	TotalSizeIncrease   int64
	TotalSizeDecrease   int64
}

// CalculateMetrics generates metrics for comparing two images
func (d *DiffEngine) CalculateMetrics(from, to *ImageLayers) LayerChangeMetrics {
	metrics := LayerChangeMetrics{
		TotalLayersInFirst:  len(from.Layers),
		TotalLayersInSecond: len(to.Layers),
	}

	diffs := d.Compare(from, to)
	for _, diff := range diffs {
		if diff.SizeChange > 0 {
			metrics.TotalSizeIncrease += diff.SizeChange
		} else if diff.SizeChange < 0 {
			metrics.TotalSizeDecrease += -diff.SizeChange
		}

		if diff.FromLayer.ID == "" {
			metrics.LayersAdded++
		} else if diff.ToLayer.ID == "" {
			metrics.LayersRemoved++
		} else if diff.SizeChange != 0 {
			metrics.LayersModified++
		}
	}

	return metrics
}
