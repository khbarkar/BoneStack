package layers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

// TestTarExtractorFileTypes tests file type detection in tar extraction
func TestTarExtractorFileTypes(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "test.txt", Size: 100, IsDir: false, IsLink: false, Type: "file"},
			{Name: "dir/", Size: 0, IsDir: true, IsLink: false, Type: "directory"},
			{Name: "link.lnk", Size: 0, IsDir: false, IsLink: true, Type: "symlink"},
		},
		FileCount: 1,
		DirCount: 1,
		LinkCount: 1,
	}

	if data.FileCount != 1 {
		t.Errorf("Expected 1 file, got %d", data.FileCount)
	}
	if data.DirCount != 1 {
		t.Errorf("Expected 1 dir, got %d", data.DirCount)
	}
	if data.LinkCount != 1 {
		t.Errorf("Expected 1 link, got %d", data.LinkCount)
	}
}

// TestGetFilesOfType tests file filtering by type
func TestGetFilesOfType(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "a.txt", Type: "file"},
			{Name: "dir/", Type: "directory"},
			{Name: "link", Type: "symlink"},
			{Name: "b.txt", Type: "file"},
		},
	}

	files := data.GetFilesOfType("file")
	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}

	dirs := data.GetFilesOfType("directory")
	if len(dirs) != 1 {
		t.Errorf("Expected 1 dir, got %d", len(dirs))
	}
}

// TestGetFilesByPath tests path-based file filtering
func TestGetFilesByPath(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "var/log/app.log"},
			{Name: "var/cache/data.db"},
			{Name: "tmp/file.txt"},
		},
	}

	varFiles := data.GetFilesByPath("var/")
	if len(varFiles) != 2 {
		t.Errorf("Expected 2 var files, got %d", len(varFiles))
	}
}

// TestGetLargestFiles tests largest file detection
func TestGetLargestFiles(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "small.txt", Size: 100},
			{Name: "large.bin", Size: 1000},
			{Name: "medium.txt", Size: 500},
		},
	}

	largest := data.GetLargestFiles(2)
	if len(largest) != 2 {
		t.Errorf("Expected 2 largest files, got %d", len(largest))
	}
	if largest[0].Size != 1000 {
		t.Errorf("Expected largest to be 1000, got %d", largest[0].Size)
	}
}

// TestGetDirectorySize tests directory size calculation
func TestGetDirectorySize(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "var/log/app.log", Size: 200},
			{Name: "var/log/error.log", Size: 300},
			{Name: "var/cache/data.db", Size: 500},
		},
	}

	logSize := data.GetDirectorySize("var/log")
	if logSize != 500 {
		t.Errorf("Expected log size 500, got %d", logSize)
	}

	varSize := data.GetDirectorySize("var")
	if varSize != 1000 {
		t.Errorf("Expected var size 1000, got %d", varSize)
	}
}

// TestCleanPath tests path normalization
func TestCleanPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/etc/config", "etc/config"},
		{"var/log/app.log", "var/log/app.log"},
		{"/var/cache/.wh.apt", "[deleted] var/cache/apt"},
	}

	for _, test := range tests {
		result := cleanPath(test.input)
		if result != test.expected {
			t.Errorf("cleanPath(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

// TestDetermineFileType tests file type classification
func TestDetermineFileType(t *testing.T) {
	tests := []struct {
		typeflag byte
		expected string
	}{
		{tar.TypeReg, "file"},
		{tar.TypeDir, "directory"},
		{tar.TypeSymlink, "symlink"},
		{tar.TypeLink, "hardlink"},
	}

	for _, test := range tests {
		header := &tar.Header{Typeflag: test.typeflag}
		result := determineFileType(header)
		if result != test.expected {
			t.Errorf("determineFileType(%d) = %s, expected %s", test.typeflag, result, test.expected)
		}
	}
}

// TestExtractLayerTarFromFile tests tar file extraction
func TestExtractLayerTarFromFile(t *testing.T) {
	// Create a test tar file in memory
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	// Add test files
	files := map[string]int64{
		"test.txt":   100,
		"dir/file.txt": 200,
		"data.bin":   5000,
	}

	for name, size := range files {
		header := &tar.Header{
			Name: name,
			Size: size,
		}
		tw.WriteHeader(header)
		tw.Write(make([]byte, size))
	}
	tw.Close()

	// Write to temp file
	tmpfile, err := os.CreateTemp("", "test-*.tar")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	tmpfile.Write(buf.Bytes())
	tmpfile.Close()

	// Extract and verify
	extractor := NewTarExtractor(nil)
	data, err := extractor.ExtractLayerTarFromFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to extract tar: %v", err)
	}

	if len(data.Files) != 3 {
		t.Errorf("Expected 3 files, got %d", len(data.Files))
	}

	expectedSize := int64(5300) // 100 + 200 + 5000
	if data.TotalSize != expectedSize {
		t.Errorf("Expected total size %d, got %d", expectedSize, data.TotalSize)
	}
}

// TestExtractLayerTarFromFileGzipped tests gzip-compressed tar extraction
func TestExtractLayerTarFromFileGzipped(t *testing.T) {
	// Create gzipped tar in memory
	buf := new(bytes.Buffer)
	gw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gw)

	header := &tar.Header{Name: "test.txt", Size: 100}
	tw.WriteHeader(header)
	tw.Write(make([]byte, 100))

	tw.Close()
	gw.Close()

	// Write to temp file
	tmpfile, err := os.CreateTemp("", "test-*.tar.gz")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	tmpfile.Write(buf.Bytes())
	tmpfile.Close()

	// Extract and verify
	extractor := NewTarExtractor(nil)
	data, err := extractor.ExtractLayerTarFromFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to extract gzipped tar: %v", err)
	}

	if len(data.Files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(data.Files))
	}
}

func TestExtractImageLayersFromFile(t *testing.T) {
	layerBuf := new(bytes.Buffer)
	layerTar := tar.NewWriter(layerBuf)
	header := &tar.Header{Name: "app/main.py", Size: int64(len("print('ok')"))}
	if err := layerTar.WriteHeader(header); err != nil {
		t.Fatalf("failed to write layer header: %v", err)
	}
	if _, err := layerTar.Write([]byte("print('ok')")); err != nil {
		t.Fatalf("failed to write layer body: %v", err)
	}
	if err := layerTar.Close(); err != nil {
		t.Fatalf("failed to close layer tar: %v", err)
	}

	manifest, err := json.Marshal([]map[string]interface{}{
		{
			"Config":   "config.json",
			"RepoTags": []string{"example:latest"},
			"Layers":   []string{"layer1/layer.tar"},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}

	imageBuf := new(bytes.Buffer)
	imageTar := tar.NewWriter(imageBuf)
	writeEntry := func(name string, data []byte) {
		h := &tar.Header{Name: name, Size: int64(len(data))}
		if err := imageTar.WriteHeader(h); err != nil {
			t.Fatalf("failed to write image header %s: %v", name, err)
		}
		if _, err := imageTar.Write(data); err != nil {
			t.Fatalf("failed to write image entry %s: %v", name, err)
		}
	}
	writeEntry("manifest.json", manifest)
	writeEntry("config.json", []byte(`{}`))
	writeEntry("layer1/layer.tar", layerBuf.Bytes())
	if err := imageTar.Close(); err != nil {
		t.Fatalf("failed to close image tar: %v", err)
	}

	tmpfile, err := os.CreateTemp("", "image-*.tar")
	if err != nil {
		t.Fatalf("failed to create temp image tar: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(imageBuf.Bytes()); err != nil {
		t.Fatalf("failed to write temp image tar: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("failed to close temp image tar: %v", err)
	}

	extractor := NewTarExtractor(nil)
	layersData, err := extractor.ExtractImageLayersFromFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to extract image layers: %v", err)
	}
	if len(layersData) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(layersData))
	}
	if layersData[0].FileCount != 1 {
		t.Fatalf("expected 1 file in layer, got %d", layersData[0].FileCount)
	}
	if layersData[0].LayerID != "layer1" {
		t.Fatalf("expected layer id layer1, got %q", layersData[0].LayerID)
	}
}

func TestFileAnalyzerDetectRustFromCargoFiles(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "Cargo.toml", Size: 120},
			{Name: "Cargo.lock", Size: 400},
		},
		TotalSize: 520,
		FileCount: 2,
	}

	analyzer := NewFileAnalyzer()
	result := analyzer.AnalyzeTarData(data)

	foundRust := false
	for _, lang := range result.LanguageDetected {
		if lang == "Rust" {
			foundRust = true
			break
		}
	}
	if !foundRust {
		t.Fatalf("expected Rust language detection, got %#v", result.LanguageDetected)
	}

	foundCargo := false
	for _, pm := range result.PackageManagers {
		if pm == "cargo" {
			foundCargo = true
			break
		}
	}
	if !foundCargo {
		t.Fatalf("expected cargo package manager detection, got %#v", result.PackageManagers)
	}
}

// TestFileAnalyzerFindLargestFiles tests largest file detection
func TestFileAnalyzerFindLargestFiles(t *testing.T) {
	data := &LayerTarData{
		TotalSize: 6000,
		Files: []FileEntry{
			{Name: "a.txt", Size: 100, IsDir: false},
			{Name: "b.bin", Size: 5000, IsDir: false},
			{Name: "c.txt", Size: 500, IsDir: false},
			{Name: "d.log", Size: 400, IsDir: false},
		},
	}

	analyzer := NewFileAnalyzer()
	largest := analyzer.findLargestFiles(data, 2)

	if len(largest) != 2 {
		t.Errorf("Expected 2 files, got %d", len(largest))
	}

	if largest[0].Size != 5000 {
		t.Errorf("Expected largest 5000, got %d", largest[0].Size)
	}
}

// TestFileAnalyzerAnalyzeExtensions tests file extension analysis
func TestFileAnalyzerAnalyzeExtensions(t *testing.T) {
	data := &LayerTarData{
		TotalSize: 2000,
		Files: []FileEntry{
			{Name: "a.txt", Size: 500, IsDir: false},
			{Name: "b.txt", Size: 600, IsDir: false},
			{Name: "c.bin", Size: 900, IsDir: false},
		},
	}

	analyzer := NewFileAnalyzer()
	exts := analyzer.analyzeExtensions(data)

	if len(exts) != 2 {
		t.Errorf("Expected 2 extensions, got %d", len(exts))
	}

	if exts[".txt"].Count != 2 {
		t.Errorf("Expected 2 .txt files, got %d", exts[".txt"].Count)
	}

	if exts[".txt"].TotalSize != 1100 {
		t.Errorf("Expected .txt total 1100, got %d", exts[".txt"].TotalSize)
	}
}

// TestFileAnalyzerAnalyzeTopDirectories tests top directory detection
func TestFileAnalyzerAnalyzeTopDirectories(t *testing.T) {
	data := &LayerTarData{
		TotalSize: 5000,
		Files: []FileEntry{
			{Name: "var/log/app.log", Size: 2000},
			{Name: "var/log/error.log", Size: 1000},
			{Name: "tmp/file.txt", Size: 1500},
			{Name: "home/user/data", Size: 500},
		},
	}

	analyzer := NewFileAnalyzer()
	topDirs := analyzer.analyzeTopDirectories(data, 2)

	if len(topDirs) != 2 {
		t.Errorf("Expected 2 directories, got %d", len(topDirs))
	}

	if topDirs[0].Size != 3000 {
		t.Errorf("Expected largest dir 3000, got %d", topDirs[0].Size)
	}
}

// TestFileAnalyzerAnalyzePotentialBloat tests bloat detection
func TestFileAnalyzerAnalyzePotentialBloat(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "/var/cache/apt/data.bin", Size: 1000},
			{Name: "/.git/objects/abc123", Size: 500},
			{Name: "README.md", Size: 100},
		},
	}

	analyzer := NewFileAnalyzer()
	bloat := analyzer.analyzePotentialBloat(data)

	if len(bloat) == 0 {
		t.Errorf("Expected bloat findings, got none")
	}

	// Should find cache
	found := false
	for _, b := range bloat {
		if b.Type == "cache" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find cache bloat")
	}
}

// TestFileAnalyzerDetectLanguages tests language detection
func TestFileAnalyzerDetectLanguages(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "app.py", Size: 100},
			{Name: "index.js", Size: 200},
			{Name: "main.go", Size: 300},
		},
	}

	analyzer := NewFileAnalyzer()
	result := analyzer.AnalyzeTarData(data)

	if len(result.LanguageDetected) == 0 {
		t.Errorf("Expected language detection")
	}
}

// TestFileAnalyzerDetectPackageManagers tests package manager detection
func TestFileAnalyzerDetectPackageManagers(t *testing.T) {
	data := &LayerTarData{
		Files: []FileEntry{
			{Name: "/var/lib/apt/status", Size: 100},
			{Name: "/node_modules/react/index.js", Size: 1000},
			{Name: "/site-packages/flask/__init__.py", Size: 200},
		},
	}

	analyzer := NewFileAnalyzer()
	result := analyzer.AnalyzeTarData(data)

	if len(result.PackageManagers) == 0 {
		t.Errorf("Expected package manager detection")
	}
}

// TestLayerTarDataSummary tests summary generation
func TestLayerTarDataSummary(t *testing.T) {
	data := &LayerTarData{
		LayerID:   "abc123def456",
		FileCount: 100,
		DirCount:  10,
		LinkCount: 5,
		TotalSize: 1000000,
	}

	summary := data.Summary()
	if summary == "" {
		t.Errorf("Expected summary, got empty string")
	}
	if len(summary) < 20 {
		t.Errorf("Summary too short: %s", summary)
	}
}

// TestFileAnalysisResultSummary tests analysis summary
func TestFileAnalysisResultSummary(t *testing.T) {
	result := &FileAnalysisResult{
		FileCount:      100,
		DirectoryCount: 10,
		SymlinkCount:   5,
		TotalSize:      1000000,
		FileExtensions: map[string]*ExtensionInfo{".txt": {}, ".bin": {}},
		PotentialBloat: []BloatFinding{{Path: "/var/cache"}},
	}

	summary := result.Summary()
	if summary == "" {
		t.Errorf("Expected summary, got empty string")
	}
	if len(summary) < 20 {
		t.Errorf("Summary too short: %s", summary)
	}
}
