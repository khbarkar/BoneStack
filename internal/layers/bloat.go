package layers

import (
	"fmt"
	"strings"
)

// BloatDetector provides bloat analysis for Docker images
type BloatDetector struct{}

// NewBloatDetector creates a new bloat detector
func NewBloatDetector() *BloatDetector {
	return &BloatDetector{}
}

// DetectInImage analyzes all layers of an image for bloat
func (bd *BloatDetector) DetectInImage(imageLayers *ImageLayers) map[int][]BloatItem {
	result := make(map[int][]BloatItem)

	for i, layer := range imageLayers.Layers {
		bloat := bd.detectInLayer(layer)
		if len(bloat) > 0 {
			result[i] = bloat
		}
	}

	return result
}

// detectInLayer identifies bloat patterns in a single layer
func (bd *BloatDetector) detectInLayer(layer Layer) []BloatItem {
	var items []BloatItem

	// Check for package manager caches
	if bd.containsKeywords(layer.Command, []string{"apt", "apt-get"}) {
		items = append(items, BloatItem{
			Pattern:       "apt_cache",
			Description:   "APT cache not cleaned - saves ~80MB on Debian/Ubuntu",
			Paths:         []string{"/var/cache/apt", "/var/lib/apt/lists"},
			EstimatedSize: 80 * 1024 * 1024,
			Removable:     true,
		})
	}

	if bd.containsKeywords(layer.Command, []string{"yum", "dnf"}) {
		items = append(items, BloatItem{
			Pattern:       "yum_cache",
			Description:   "YUM cache not cleaned - saves ~50MB on CentOS/RHEL",
			Paths:         []string{"/var/cache/yum"},
			EstimatedSize: 50 * 1024 * 1024,
			Removable:     true,
		})
	}

	if bd.containsKeywords(layer.Command, []string{"apk"}) {
		items = append(items, BloatItem{
			Pattern:       "apk_cache",
			Description:   "APK cache not cleaned - saves ~20MB on Alpine",
			Paths:         []string{"/var/cache/apk"},
			EstimatedSize: 20 * 1024 * 1024,
			Removable:     true,
		})
	}

	// Check for language package caches
	if bd.containsKeywords(layer.Command, []string{"pip", "python"}) {
		items = append(items, BloatItem{
			Pattern:       "pip_cache",
			Description:   "pip cache not cleaned - saves ~30MB",
			Paths:         []string{"/root/.cache/pip", "/.cache/pip"},
			EstimatedSize: 30 * 1024 * 1024,
			Removable:     true,
		})
	}

	if bd.containsKeywords(layer.Command, []string{"npm", "node"}) {
		items = append(items, BloatItem{
			Pattern:       "npm_cache",
			Description:   "npm cache not cleaned - saves ~50MB",
			Paths:         []string{"/root/.npm", "/.npm"},
			EstimatedSize: 50 * 1024 * 1024,
			Removable:     true,
		})

		items = append(items, BloatItem{
			Pattern:       "node_modules_in_layers",
			Description:   "node_modules in intermediate layers - consider multi-stage build",
			Paths:         []string{"/node_modules", "/app/node_modules"},
			EstimatedSize: 500 * 1024 * 1024, // Typical node_modules size
			Removable:     false,              // Would need multi-stage refactor
		})
	}

	if bd.containsKeywords(layer.Command, []string{"gem", "ruby"}) {
		items = append(items, BloatItem{
			Pattern:       "gem_cache",
			Description:   "gem cache not cleaned - saves ~20MB",
			Paths:         []string{"/usr/local/bundle/cache"},
			EstimatedSize: 20 * 1024 * 1024,
			Removable:     true,
		})
	}

	// Check for development tools left in production
	if bd.containsKeywords(layer.Command, []string{"build-essential", "gcc", "make"}) {
		items = append(items, BloatItem{
			Pattern:       "build_tools",
			Description:   "Build tools left in image - should be in build stage only",
			Paths:         []string{"/usr/bin/gcc", "/usr/bin/make", "/usr/bin/g++"},
			EstimatedSize: 200 * 1024 * 1024,
			Removable:     false, // Requires architectural change
		})
	}

	// Check for documentation and man pages
	if bd.layerHasDocs(layer.Command) {
		items = append(items, BloatItem{
			Pattern:       "documentation",
			Description:   "Documentation and man pages - saves ~50MB",
			Paths:         []string{"/usr/share/doc", "/usr/share/man"},
			EstimatedSize: 50 * 1024 * 1024,
			Removable:     true,
		})
	}

	// Check for version control metadata
	if bd.containsKeywords(layer.Command, []string{"git", "clone", ".git"}) {
		items = append(items, BloatItem{
			Pattern:       "git_metadata",
			Description:   ".git directory left in image - unnecessary in production",
			Paths:         []string{"/.git", "/app/.git"},
			EstimatedSize: 100 * 1024 * 1024,
			Removable:     true,
		})
	}

	return items
}

// containsKeywords checks if a string contains any of the given keywords
func (bd *BloatDetector) containsKeywords(text string, keywords []string) bool {
	lowerText := strings.ToLower(text)
	for _, keyword := range keywords {
		if strings.Contains(lowerText, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// layerHasDocs checks if layer likely contains documentation
func (bd *BloatDetector) layerHasDocs(command string) bool {
	// Heuristic: if it looks like a package install layer
	return bd.containsKeywords(command, []string{"apt", "yum", "apk", "pacman"})
}

// EstimateSavings calculates total potential savings from removing bloat
func (bd *BloatDetector) EstimateSavings(bloatByLayer map[int][]BloatItem) int64 {
	total := int64(0)

	for _, items := range bloatByLayer {
		for _, item := range items {
			if item.Removable {
				total += item.EstimatedSize
			}
		}
	}

	return total
}

// GenerateRecommendations creates optimization suggestions based on bloat analysis
func (bd *BloatDetector) GenerateRecommendations(imageLayers *ImageLayers, bloatByLayer map[int][]BloatItem) []string {
	recommendations := make([]string, 0)

	// Count bloat patterns
	patternCount := make(map[string]int)
	for _, items := range bloatByLayer {
		for _, item := range items {
			patternCount[item.Pattern]++
		}
	}

	// Generate pattern-specific recommendations
	if patternCount["apt_cache"] > 0 {
		recommendations = append(recommendations,
			"Remove APT cache: Use 'apt-get clean && rm -rf /var/lib/apt/lists/*' after installs")
	}

	if patternCount["yum_cache"] > 0 {
		recommendations = append(recommendations,
			"Remove YUM cache: Use 'yum clean all' after installs")
	}

	if patternCount["apk_cache"] > 0 {
		recommendations = append(recommendations,
			"Remove APK cache: Use 'rm -rf /var/cache/apk/*' after installs")
	}

	if patternCount["npm_cache"] > 0 {
		recommendations = append(recommendations,
			"Remove npm cache: Use 'npm cache clean --force' after installs")
	}

	if patternCount["pip_cache"] > 0 {
		recommendations = append(recommendations,
			"Remove pip cache: Use 'rm -rf ~/.cache/pip' after installs")
	}

	if patternCount["node_modules_in_layers"] > 0 {
		recommendations = append(recommendations,
			"Use multi-stage builds to avoid shipping node_modules in final image")
	}

	if patternCount["build_tools"] > 0 {
		recommendations = append(recommendations,
			"Move build tools to separate build stage and don't include in final image")
	}

	if patternCount["git_metadata"] > 0 {
		recommendations = append(recommendations,
			"Use .dockerignore to exclude .git directory from build context")
	}

	// General recommendations
	if len(imageLayers.Layers) > 10 {
		recommendations = append(recommendations,
			fmt.Sprintf("Image has %d layers - consider consolidating to reduce layer count", len(imageLayers.Layers)))
	}

	return recommendations
}

// DetectBloatFromTarAnalysis performs bloat detection using actual tar file analysis
// This uses FileAnalysisResult from real tar extraction instead of pattern matching
func (bd *BloatDetector) DetectBloatFromTarAnalysis(analysis *FileAnalysisResult) []BloatFinding {
	return analysis.PotentialBloat
}

// MergeBloatDetection combines pattern-based and tar-based bloat detection
func (bd *BloatDetector) MergeBloatDetection(patternBased []BloatItem, tarBased []BloatFinding) map[string]interface{} {
	return map[string]interface{}{
		"pattern_based": patternBased,
		"tar_based":     tarBased,
		"total_items":   len(patternBased) + len(tarBased),
	}
}

// EstimateSavingsFromTarAnalysis calculates real savings from tar analysis
func (bd *BloatDetector) EstimateSavingsFromTarAnalysis(findings []BloatFinding) int64 {
	var total int64
	for _, finding := range findings {
		if finding.Removable {
			total += finding.Size
		}
	}
	return total
}

// GenerateOptimizationRecommendationsFromAnalysis creates recommendations based on FileAnalysisResult
func (bd *BloatDetector) GenerateOptimizationRecommendationsFromAnalysis(analysis *FileAnalysisResult) []string {
	var recommendations []string

	// Based on detected languages
	if len(analysis.LanguageDetected) > 0 {
		for _, lang := range analysis.LanguageDetected {
			switch lang {
			case "Python":
				recommendations = append(recommendations,
					"Python project detected: Use .dockerignore to exclude __pycache__, *.pyc files")
				recommendations = append(recommendations,
					"Remove pip cache after installations: 'pip install --no-cache-dir package'")
			case "JavaScript":
				recommendations = append(recommendations,
					"JavaScript/Node.js project detected: Use .dockerignore to exclude node_modules, .npm")
				recommendations = append(recommendations,
					"Consider multi-stage builds: Node builder stage → production stage with only node_modules")
			case "Java":
				recommendations = append(recommendations,
					"Java project detected: Consider jlink for minimal JRE in final image")
			case "Go":
				recommendations = append(recommendations,
					"Go project detected: Excellent! Consider using distroless/scratch base image")
			}
		}
	}

	// Based on detected package managers
	if len(analysis.PackageManagers) > 0 {
		for _, pm := range analysis.PackageManagers {
			switch pm {
			case "apt":
				recommendations = append(recommendations,
					"APT detected: Run 'apt-get clean' and 'rm -rf /var/lib/apt/lists/*' after installs")
			case "yum":
				recommendations = append(recommendations,
					"YUM detected: Run 'yum clean all' after installs to remove cache")
			case "apk":
				recommendations = append(recommendations,
					"APK detected: Use 'apk add --no-cache' flag to skip cache creation")
			case "npm":
				recommendations = append(recommendations,
					"NPM detected: Use 'npm ci --only=production' and 'npm cache clean --force'")
			}
		}
	}

	// Based on bloat findings
	if len(analysis.PotentialBloat) > 0 {
		totalBloat := int64(0)
		for _, bloat := range analysis.PotentialBloat {
			totalBloat += bloat.Size
		}
		
		if totalBloat > 0 {
			recommendations = append(recommendations,
				fmt.Sprintf("Found %.2f MB of potential bloat that could be removed", float64(totalBloat)/1024/1024))
		}
	}

	// Based on top directories
	if len(analysis.TopDirectories) > 0 {
		if analysis.TopDirectories[0].Size > analysis.TotalSize/2 {
			recommendations = append(recommendations,
				fmt.Sprintf("Directory %s contains >50%% of layer - review for optimization", analysis.TopDirectories[0].Path))
		}
	}

	// Multi-stage build recommendations
	if len(analysis.LanguageDetected) > 0 && analysis.FileCount > 1000 {
		recommendations = append(recommendations,
			"Layer has 1000+ files: Multi-stage build could reduce final image size significantly")
	}

	return recommendations
}
