package layers

import (
	"os"
	"testing"
	"time"
)

// TestNewTarCache tests cache creation
func TestNewTarCache(t *testing.T) {
	tmpdir := t.TempDir()

	cache, err := NewTarCache(tmpdir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	if cache == nil {
		t.Errorf("Expected cache instance, got nil")
	}

	// Verify directory was created
	if _, err := os.Stat(tmpdir); os.IsNotExist(err) {
		t.Errorf("Cache directory was not created")
	}
}

// TestGetCacheKey tests cache key generation
func TestGetCacheKey(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	key := cache.GetCacheKey("sha256:abc123def456", "layer123")
	if key == "" {
		t.Errorf("Expected non-empty cache key")
	}

	if len(key) < 10 {
		t.Errorf("Cache key too short: %s", key)
	}
}

// TestCacheSetGet tests cache storage and retrieval
func TestCacheSetGet(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	// Create test entry
	tarData := &LayerTarData{
		LayerID:   "test-layer",
		FileCount: 100,
	}

	fileAnalysis := &FileAnalysisResult{
		LayerID:    "test-layer",
		FileCount:  100,
		TotalSize:  1000000,
		SizeByType: make(map[string]int64),
	}

	entry := CreateCacheEntry("sha256:abc123", "test-layer", tarData, fileAnalysis, 50000)

	// Set cache
	if err := cache.Set(entry); err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Get cache
	retrieved, err := cache.Get("sha256:abc123", "test-layer")
	if err != nil {
		t.Fatalf("Failed to get cache: %v", err)
	}

	if retrieved == nil {
		t.Errorf("Expected cached entry, got nil")
		return
	}

	if retrieved.LayerID != "test-layer" {
		t.Errorf("Expected layer ID 'test-layer', got %s", retrieved.LayerID)
	}
}

// TestCacheMiss tests cache miss behavior
func TestCacheMiss(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	// Try to get non-existent entry
	entry, err := cache.Get("sha256:nonexistent", "no-layer")
	if err != nil {
		t.Fatalf("Cache miss should not error: %v", err)
	}

	if entry != nil {
		t.Errorf("Expected nil for cache miss, got entry")
	}
}

// TestCacheClear tests cache clearing
func TestCacheClear(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	// Set cache
	entry := CreateCacheEntry("sha256:abc123", "test-layer", &LayerTarData{}, &FileAnalysisResult{}, 0)
	cache.Set(entry)

	// Clear
	if err := cache.Clear("sha256:abc123", "test-layer"); err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Verify it's gone
	retrieved, _ := cache.Get("sha256:abc123", "test-layer")
	if retrieved != nil {
		t.Errorf("Expected nil after clear, got entry")
	}
}

// TestCacheClearAll tests clearing all cache entries
func TestCacheClearAll(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	// Set multiple entries
	for i := 0; i < 3; i++ {
		entry := CreateCacheEntry("sha256:abc123", "layer"+string(rune(i)), &LayerTarData{}, &FileAnalysisResult{}, 0)
		cache.Set(entry)
	}

	// Clear all
	if err := cache.ClearAll(); err != nil {
		t.Fatalf("Failed to clear all: %v", err)
	}

	// Verify directory is empty
	entries, err := os.ReadDir(tmpdir)
	if err != nil {
		t.Fatalf("Failed to read cache dir: %v", err)
	}

	if len(entries) > 0 {
		t.Errorf("Expected empty cache, got %d entries", len(entries))
	}
}

// TestGetCacheSize tests cache size calculation
func TestGetCacheSize(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	// Set cache
	entry := CreateCacheEntry("sha256:abc123", "test-layer", &LayerTarData{}, &FileAnalysisResult{}, 0)
	cache.Set(entry)

	// Get size
	size, err := cache.GetCacheSize()
	if err != nil {
		t.Fatalf("Failed to get cache size: %v", err)
	}

	if size <= 0 {
		t.Errorf("Expected positive cache size, got %d", size)
	}
}

// TestGetCacheStats tests cache statistics
func TestGetCacheStats(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	stats := cache.GetCacheStats()

	if stats["entries"] != 0 {
		t.Errorf("Expected 0 entries, got %v", stats["entries"])
	}

	// Set cache
	entry := CreateCacheEntry("sha256:abc123", "test-layer", &LayerTarData{}, &FileAnalysisResult{}, 0)
	cache.Set(entry)

	// Get stats again
	stats = cache.GetCacheStats()

	if stats["entries"] != 1 {
		t.Errorf("Expected 1 entry, got %v", stats["entries"])
	}
}

// TestIsStale tests cache staleness detection
func TestIsStale(t *testing.T) {
	entry := &CacheEntry{
		Timestamp: time.Now(),
	}

	// Should not be stale for recent age
	cache := &TarCache{}
	if cache.IsStale(entry, time.Hour) {
		t.Errorf("Expected recent entry to not be stale")
	}

	// Set timestamp to old date
	entry.Timestamp = time.Now().Add(-2 * time.Hour)

	// Should be stale
	if !cache.IsStale(entry, time.Hour) {
		t.Errorf("Expected old entry to be stale")
	}

	// Nil should be stale
	if !cache.IsStale(nil, time.Hour) {
		t.Errorf("Expected nil entry to be stale")
	}
}

// TestCreateCacheEntry tests cache entry creation
func TestCreateCacheEntry(t *testing.T) {
	tarData := &LayerTarData{FileCount: 100}
	fileAnalysis := &FileAnalysisResult{FileCount: 100}

	entry := CreateCacheEntry("sha256:abc", "layer1", tarData, fileAnalysis, 12345)

	if entry == nil {
		t.Errorf("Expected cache entry, got nil")
	}

	if entry.LayerID != "layer1" {
		t.Errorf("Expected layer1, got %s", entry.LayerID)
	}

	if entry.EstimatedSavings != 12345 {
		t.Errorf("Expected savings 12345, got %d", entry.EstimatedSavings)
	}

	if entry.Timestamp.IsZero() {
		t.Errorf("Expected timestamp to be set")
	}
}

// TestDefaultCachePath tests default cache path generation
func TestDefaultCachePath(t *testing.T) {
	path := DefaultCachePath()
	if path == "" {
		t.Errorf("Expected non-empty cache path")
	}

	if len(path) < 5 {
		t.Errorf("Cache path too short: %s", path)
	}
}

// TestCacheMultipleLayersPerImage tests caching multiple layers from same image
func TestCacheMultipleLayersPerImage(t *testing.T) {
	tmpdir := t.TempDir()
	cache, _ := NewTarCache(tmpdir)

	imageDigest := "sha256:abc123"

	// Cache multiple layers
	for i := 0; i < 3; i++ {
		layerID := "layer_" + string(rune('0'+i))
		entry := CreateCacheEntry(imageDigest, layerID, &LayerTarData{}, &FileAnalysisResult{}, int64(i*1000))
		if err := cache.Set(entry); err != nil {
			t.Fatalf("Failed to set cache for %s: %v", layerID, err)
		}
	}

	// Retrieve each layer
	for i := 0; i < 3; i++ {
		layerID := "layer_" + string(rune('0'+i))
		entry, err := cache.Get(imageDigest, layerID)
		if err != nil {
			t.Fatalf("Failed to get cache for %s: %v", layerID, err)
		}

		if entry == nil {
			t.Errorf("Expected cached entry for %s", layerID)
		}
	}

	// Verify cache size
	size, _ := cache.GetCacheSize()
	if size <= 0 {
		t.Errorf("Expected positive cache size after 3 entries")
	}
}
