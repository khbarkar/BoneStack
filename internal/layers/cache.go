package layers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TarCache manages caching of extracted tar analysis results
type TarCache struct {
	cacheDir string
}

// CacheEntry stores cached tar analysis data
type CacheEntry struct {
	LayerID           string                 `json:"layer_id"`
	ImageDigest       string                 `json:"image_digest"`
	Timestamp         time.Time              `json:"timestamp"`
	TarData           *LayerTarData          `json:"tar_data"`
	FileAnalysis      *FileAnalysisResult    `json:"file_analysis"`
	EstimatedSavings  int64                  `json:"estimated_savings"`
	BlotPatternCount  int                    `json:"bloat_pattern_count"`
}

// NewTarCache creates a new tar cache manager
func NewTarCache(cacheDir string) (*TarCache, error) {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &TarCache{
		cacheDir: cacheDir,
	}, nil
}

// GetCacheKey generates a unique cache key for a layer
func (tc *TarCache) GetCacheKey(imageDigest, layerID string) string {
	// Use a simple combination of image digest and layer ID
	// In production, this would use a hash for consistency
	digestPrefix := imageDigest
	if len(imageDigest) > 12 {
		digestPrefix = imageDigest[:12]
	}
	
	layerPrefix := layerID
	if len(layerID) > 12 {
		layerPrefix = layerID[:12]
	}
	
	return fmt.Sprintf("%s_%s.json", digestPrefix, layerPrefix)
}

// Get retrieves cached tar analysis if it exists
func (tc *TarCache) Get(imageDigest, layerID string) (*CacheEntry, error) {
	cacheFile := filepath.Join(tc.cacheDir, tc.GetCacheKey(imageDigest, layerID))

	// Check if cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil, nil // Cache miss, not an error
	}

	// Read cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache: %w", err)
	}

	// Unmarshal
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	return &entry, nil
}

// Set stores tar analysis in cache
func (tc *TarCache) Set(entry *CacheEntry) error {
	if entry == nil {
		return fmt.Errorf("cannot cache nil entry")
	}

	cacheFile := filepath.Join(tc.cacheDir, tc.GetCacheKey(entry.ImageDigest, entry.LayerID))

	// Marshal to JSON
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	// Write to file
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache: %w", err)
	}

	return nil
}

// Clear removes a specific cache entry
func (tc *TarCache) Clear(imageDigest, layerID string) error {
	cacheFile := filepath.Join(tc.cacheDir, tc.GetCacheKey(imageDigest, layerID))

	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	return nil
}

// ClearAll removes all cache entries
func (tc *TarCache) ClearAll() error {
	if err := os.RemoveAll(tc.cacheDir); err != nil {
		return fmt.Errorf("failed to clear all cache: %w", err)
	}

	if err := os.MkdirAll(tc.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to recreate cache directory: %w", err)
	}

	return nil
}

// GetCacheSize returns total cache size in bytes
func (tc *TarCache) GetCacheSize() (int64, error) {
	var totalSize int64

	entries, err := os.ReadDir(tc.cacheDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			totalSize += info.Size()
		}
	}

	return totalSize, nil
}

// GetCacheStats returns cache statistics
func (tc *TarCache) GetCacheStats() map[string]interface{} {
	entries, err := os.ReadDir(tc.cacheDir)
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	count := 0
	var totalSize int64

	for _, entry := range entries {
		if !entry.IsDir() {
			count++
			info, err := entry.Info()
			if err == nil {
				totalSize += info.Size()
			}
		}
	}

	return map[string]interface{}{
		"entries":     count,
		"total_size":  totalSize,
		"cache_dir":   tc.cacheDir,
		"total_mb":    float64(totalSize) / 1024 / 1024,
	}
}

// IsStale checks if a cache entry is older than the given duration
func (tc *TarCache) IsStale(entry *CacheEntry, maxAge time.Duration) bool {
	if entry == nil {
		return true
	}
	return time.Since(entry.Timestamp) > maxAge
}

// CreateCacheEntry creates a new cache entry from analysis results
func CreateCacheEntry(imageDigest, layerID string, tarData *LayerTarData, fileAnalysis *FileAnalysisResult, savings int64) *CacheEntry {
	return &CacheEntry{
		LayerID:          layerID,
		ImageDigest:      imageDigest,
		Timestamp:        time.Now(),
		TarData:          tarData,
		FileAnalysis:     fileAnalysis,
		EstimatedSavings: savings,
		BlotPatternCount: len(fileAnalysis.PotentialBloat),
	}
}

// DefaultCachePath returns the default cache directory path
func DefaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/bonestack-cache"
	}
	return filepath.Join(home, ".bonestack", "cache")
}
