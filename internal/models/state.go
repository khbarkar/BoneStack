package models

import (
	"github.com/kristinb/bonestack/internal/docker"
	"github.com/kristinb/bonestack/internal/forensics"
	"github.com/kristinb/bonestack/internal/layers"
	"github.com/kristinb/bonestack/internal/sde"
)

type AppState struct {
	CurrentScreen     string // "menu", "images", "containers", "image-detail", "container-detail", "layers", "layer-detail", "size-breakdown", "file-browser", "optimization", "scaffold", "forensics-menu", "filesystem", "processes", "volumes", "logs", "environment", "resources"
	SelectedImage     docker.ImageSummary
	SelectedContainer docker.ContainerSummary
	ImageList         []docker.ImageSummary
	ContainerList     []docker.ContainerSummary

	// Layer analysis data
	ImageLayers          *layers.ImageLayers
	LayerAnalyses        []layers.LayerAnalysis
	BloatDetection       map[int][]layers.BloatItem
	LayerRecommendations []string
	OptimizationReport   layers.OptimizationReport
	Scaffold             sde.Scaffold
	SelectedLayerIndex   int

	// Tar-based analysis
	LayerTarData []layers.LayerTarData       // Real tar file data
	FileAnalysis []layers.FileAnalysisResult // File analysis results

	// Forensics data
	FileSystemData  map[string]interface{} // Directory contents
	ProcessList     []forensics.Process
	ProcessStats    *forensics.ProcessStats
	VolumeData      []forensics.VolumeInfo
	ResourceStats   *forensics.ResourceStats
	LogLines        []string
	EnvironmentVars map[string]string
	SecretVars      []string
	ThreatFindings  []map[string]string
	ThreatSummary   map[string]int
	DiffChanges     []map[string]string
	DiffSummary     map[string]int
	TimelineEvents  []map[string]string
	TimelineSummary map[string]int

	// UI state
	ScrollOffset   int
	FilterText     string
	AnalysisStatus string
	AnalysisError  string
	ExportMessage  string
	LastExportPath string

	Error string
}

type MenuItem struct {
	Label  string
	Action string
}
