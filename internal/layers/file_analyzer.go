package layers

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// FileAnalyzer performs advanced analysis on extracted layer files
type FileAnalyzer struct {
}

// NewFileAnalyzer creates a new file analyzer
func NewFileAnalyzer() *FileAnalyzer {
	return &FileAnalyzer{}
}

// AnalyzeTarData performs comprehensive analysis on layer tar data
func (fa *FileAnalyzer) AnalyzeTarData(data *LayerTarData) *FileAnalysisResult {
	return &FileAnalysisResult{
		LayerID:           data.LayerID,
		TotalSize:         data.TotalSize,
		FileCount:         data.FileCount,
		DirectoryCount:    data.DirCount,
		SymlinkCount:      data.LinkCount,
		SizeByType:        data.SizeByType,
		LargestFiles:      fa.findLargestFiles(data, 10),
		FileExtensions:    fa.analyzeExtensions(data),
		TopDirectories:    fa.analyzeTopDirectories(data, 10),
		PotentialBloat:    fa.analyzePotentialBloat(data),
		LanguageDetected:  fa.detectLanguages(data),
		PackageManagers:   fa.detectPackageManagers(data),
	}
}

// FileAnalysisResult contains comprehensive analysis of a layer
type FileAnalysisResult struct {
	LayerID         string
	TotalSize       int64
	FileCount       int
	DirectoryCount  int
	SymlinkCount    int
	SizeByType      map[string]int64
	LargestFiles    []FileSizeInfo
	FileExtensions  map[string]*ExtensionInfo
	TopDirectories  []DirectoryInfo
	PotentialBloat  []BloatFinding
	LanguageDetected []string
	PackageManagers []string
}

// FileSizeInfo represents a file and its size
type FileSizeInfo struct {
	Path string
	Size int64
}

// ExtensionInfo contains analysis for a file extension
type ExtensionInfo struct {
	Count      int
	TotalSize  int64
	Percentage float64
}

// DirectoryInfo contains analysis for a directory
type DirectoryInfo struct {
	Path       string
	Size       int64
	FileCount  int
	Percentage float64
}

// BloatFinding represents a potential bloat issue found in the layer
type BloatFinding struct {
	Path        string
	Type        string // cache, build-artifact, documentation, log, etc
	Size        int64
	Severity    string // low, medium, high
	Description string
	Removable   bool
}

// findLargestFiles returns the N largest files in the layer
func (fa *FileAnalyzer) findLargestFiles(data *LayerTarData, limit int) []FileSizeInfo {
	largest := data.GetLargestFiles(limit)
	var result []FileSizeInfo
	for _, f := range largest {
		if !f.IsDir {
			result = append(result, FileSizeInfo{
				Path: f.Name,
				Size: f.Size,
			})
		}
	}
	return result
}

// analyzeExtensions categorizes files by extension
func (fa *FileAnalyzer) analyzeExtensions(data *LayerTarData) map[string]*ExtensionInfo {
	extensions := make(map[string]*ExtensionInfo)

	for _, f := range data.Files {
		if f.IsDir || f.IsLink || f.Size == 0 {
			continue
		}

		ext := filepath.Ext(f.Name)
		if ext == "" {
			ext = "[no extension]"
		}

		if _, exists := extensions[ext]; !exists {
			extensions[ext] = &ExtensionInfo{Count: 0, TotalSize: 0}
		}

		extensions[ext].Count++
		extensions[ext].TotalSize += f.Size
		if data.TotalSize > 0 {
			extensions[ext].Percentage = float64(extensions[ext].TotalSize) / float64(data.TotalSize) * 100
		}
	}

	return extensions
}

// analyzeTopDirectories finds the largest directories
func (fa *FileAnalyzer) analyzeTopDirectories(data *LayerTarData, limit int) []DirectoryInfo {
	dirSizes := make(map[string]int64)
	dirCounts := make(map[string]int)

	// Calculate directory sizes
	for _, f := range data.Files {
		if f.IsDir {
			dirSizes[f.Name] = 0
			dirCounts[f.Name] = 0
		}
	}

	for _, f := range data.Files {
		if f.IsDir || f.Size == 0 {
			continue
		}

		// Find parent directory
		dir := filepath.Dir(f.Name)
		if dir == "." {
			dir = "/"
		}

		dirSizes[dir] += f.Size
		dirCounts[dir]++
	}

	// Convert to slice and sort
	var dirs []DirectoryInfo
	for path, size := range dirSizes {
		if size > 0 {
			dirs = append(dirs, DirectoryInfo{
				Path:       path,
				Size:       size,
				FileCount:  dirCounts[path],
				Percentage: float64(size) / float64(data.TotalSize) * 100,
			})
		}
	}

	// Sort by size descending
	for i := 0; i < len(dirs); i++ {
		for j := i + 1; j < len(dirs); j++ {
			if dirs[j].Size > dirs[i].Size {
				dirs[i], dirs[j] = dirs[j], dirs[i]
			}
		}
	}

	if limit > len(dirs) {
		limit = len(dirs)
	}
	return dirs[:limit]
}

// analyzePotentialBloat identifies bloat items in the layer
func (fa *FileAnalyzer) analyzePotentialBloat(data *LayerTarData) []BloatFinding {
	var findings []BloatFinding

	cachePatterns := map[string]map[string]string{
		"/var/cache/apt":         {"type": "cache", "severity": "high"},
		"/var/lib/apt/lists":     {"type": "cache", "severity": "high"},
		"/.npm":                  {"type": "cache", "severity": "medium"},
		"/root/.npm":             {"type": "cache", "severity": "medium"},
		"/root/.cache":           {"type": "cache", "severity": "medium"},
		"/.cache":                {"type": "cache", "severity": "medium"},
		"/.git":                  {"type": "version-control", "severity": "high"},
		"/node_modules/.bin":     {"type": "symlinks", "severity": "low"},
		"/usr/share/doc":         {"type": "documentation", "severity": "low"},
		"/usr/share/man":         {"type": "documentation", "severity": "low"},
	}

	buildToolPatterns := []string{
		".git",
		"Makefile",
		"*.o",
		"*.a",
		"*.so.debug",
		"CMakeLists.txt",
		".gitignore",
		"README",
		"LICENSE",
	}

	// Check for cache directories
	for _, f := range data.Files {
		// Check cache patterns
		for pattern, meta := range cachePatterns {
			if f.Name == pattern || strings.HasPrefix(f.Name, pattern+"/") {
				findings = append(findings, BloatFinding{
					Path:        f.Name,
					Type:        meta["type"],
					Size:        f.Size,
					Severity:    meta["severity"],
					Description: fmt.Sprintf("%s - %s", meta["type"], f.Name),
					Removable:   true,
				})
				break
			}
		}

		// Check build tool artifacts
		for _, pattern := range buildToolPatterns {
			if strings.Contains(f.Name, pattern) && f.Size > 0 {
				findings = append(findings, BloatFinding{
					Path:        f.Name,
					Type:        "build-artifact",
					Size:        f.Size,
					Severity:    "medium",
					Description: fmt.Sprintf("Build artifact: %s", f.Name),
					Removable:   true,
				})
				break
			}
		}
	}

	return findings
}

// detectLanguages infers programming languages from file extensions
func (fa *FileAnalyzer) detectLanguages(data *LayerTarData) []string {
	detected := make(map[string]bool)

	extensions := fa.analyzeExtensions(data)
	fileNames := make([]string, 0, len(data.Files))
	for _, f := range data.Files {
		fileNames = append(fileNames, strings.ToLower(f.Name))
	}

	if hasExtension(extensions, ".py") || containsAnyPath(fileNames, []string{"/site-packages", "/dist-packages"}) {
		detected["Python"] = true
	}
	if hasExtension(extensions, ".js") || containsAnyPath(fileNames, []string{"node_modules", "package.json"}) {
		detected["JavaScript"] = true
	}
	if hasAnyExtension(extensions, []string{".jar", ".class", ".war"}) || containsAnyPath(fileNames, []string{"/classes"}) {
		detected["Java"] = true
	}
	if hasExtension(extensions, ".go") || containsAnyPath(fileNames, []string{"go.mod", "go.sum"}) {
		detected["Go"] = true
	}
	if hasExtension(extensions, ".rb") || containsAnyPath(fileNames, []string{"/gems", "gemfile"}) {
		detected["Ruby"] = true
	}
	if hasAnyExtension(extensions, []string{".c", ".cpp", ".h", ".o"}) {
		detected["C/C++"] = true
	}
	if hasExtension(extensions, ".php") || containsAnyPath(fileNames, []string{"/vendor"}) {
		detected["PHP"] = true
	}
	if hasExtension(extensions, ".rs") || containsAnyPath(fileNames, []string{"cargo.toml", "cargo.lock"}) {
		detected["Rust"] = true
	}
	if hasExtension(extensions, ".sh") || containsAnyPath(fileNames, []string{"/bin", "/sbin"}) {
		detected["Shell"] = true
	}

	var languages []string
	for lang := range detected {
		languages = append(languages, lang)
	}
	sort.Strings(languages)

	return languages
}

// detectPackageManagers detects which package managers are used
func (fa *FileAnalyzer) detectPackageManagers(data *LayerTarData) []string {
	detected := make(map[string]bool)

	pmPatterns := map[string][]string{
		"apt":  {"/var/lib/apt", "/etc/apt"},
		"yum":  {"/var/lib/yum", "/var/cache/yum"},
		"apk":  {"/var/lib/apk", "/lib/apk"},
		"npm":  {"/node_modules", "package.json", "/usr/lib/node_modules"},
		"pip":  {"/site-packages", "/dist-packages", "requirements.txt"},
		"gem":  {"/gems", "Gemfile", ".gemspec"},
		"cargo": {"Cargo.toml", "Cargo.lock"},
	}

	for _, f := range data.Files {
		for pm, patterns := range pmPatterns {
			for _, pattern := range patterns {
				if f.Name == pattern || strings.Contains(f.Name, pattern) {
					detected[pm] = true
					break
				}
			}
		}
	}

	var managers []string
	for pm := range detected {
		managers = append(managers, pm)
	}
	sort.Strings(managers)

	return managers
}

func hasExtension(extensions map[string]*ExtensionInfo, ext string) bool {
	_, ok := extensions[ext]
	return ok
}

func hasAnyExtension(extensions map[string]*ExtensionInfo, exts []string) bool {
	for _, ext := range exts {
		if hasExtension(extensions, ext) {
			return true
		}
	}
	return false
}

func containsAnyPath(paths []string, patterns []string) bool {
	for _, path := range paths {
		for _, pattern := range patterns {
			if strings.Contains(path, strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

// Summary returns a text summary of the analysis
func (result *FileAnalysisResult) Summary() string {
	return fmt.Sprintf(
		"Analysis: %d files, %d dirs, %d links, %.2f MB | Extensions: %d types | Top dirs: %d | Bloat findings: %d",
		result.FileCount,
		result.DirectoryCount,
		result.SymlinkCount,
		float64(result.TotalSize)/1024/1024,
		len(result.FileExtensions),
		len(result.TopDirectories),
		len(result.PotentialBloat),
	)
}
