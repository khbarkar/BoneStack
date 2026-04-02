package models

import (
	"github.com/kristinb/bonestack/internal/docker"
	"github.com/kristinb/bonestack/internal/layers"
)

type AppState struct {
	CurrentScreen string // "menu", "images", "containers", "image-detail", "container-detail", "layers", "layer-detail", "size-breakdown"
	SelectedImage docker.ImageSummary
	SelectedContainer docker.ContainerSummary
	ImageList []docker.ImageSummary
	ContainerList []docker.ContainerSummary
	
	// Layer analysis data
	ImageLayers *layers.ImageLayers
	LayerAnalyses []layers.LayerAnalysis
	BloatDetection map[int][]layers.BloatItem
	LayerRecommendations []string
	SelectedLayerIndex int
	
	Error string
}

type MenuItem struct {
	Label string
	Action string
}
