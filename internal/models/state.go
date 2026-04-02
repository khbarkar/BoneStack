package models

import (
	"github.com/kristinb/bonestack/internal/docker"
)

type AppState struct {
	CurrentScreen string // "menu", "images", "containers", "image-detail", "container-detail"
	SelectedImage docker.ImageSummary
	SelectedContainer docker.ContainerSummary
	ImageList []docker.ImageSummary
	ContainerList []docker.ContainerSummary
	Error string
}

type MenuItem struct {
	Label string
	Action string
}
