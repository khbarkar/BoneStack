package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kristinb/bonestack/internal/docker"
	"github.com/kristinb/bonestack/internal/forensics"
	"github.com/kristinb/bonestack/internal/forensics/containerdiff"
	"github.com/kristinb/bonestack/internal/forensics/threathunt"
	"github.com/kristinb/bonestack/internal/forensics/timeline"
	"github.com/kristinb/bonestack/internal/forensics/yarascan"
	"github.com/kristinb/bonestack/internal/layers"
	"github.com/kristinb/bonestack/internal/models"
	"github.com/kristinb/bonestack/internal/report"
	"github.com/kristinb/bonestack/internal/sde"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("33")).
			Padding(1, 2)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("63")).
			Padding(0, 1)

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Italic(true)
)

type App struct {
	docker             *docker.Client
	layerAnalyzer      *layers.Analyzer
	bloatDetector      *layers.BloatDetector
	diffEngine         *layers.DiffEngine
	tarExtractor       *layers.TarExtractor
	fileAnalyzer       *layers.FileAnalyzer
	containerInspector *forensics.ContainerInspector
	fsInspector        *forensics.FileSystemInspector
	processAnalyzer    *forensics.ProcessAnalyzer
	volumeAnalyzer     *forensics.VolumeAnalyzer
	logAnalyzer        *forensics.LogAnalyzer
	envAnalyzer        *forensics.EnvironmentAnalyzer
	resourceMonitor    *forensics.ResourceMonitor
	diffScanner        *containerdiff.Scanner
	timelineScanner    *timeline.Scanner
	threatScanner      *threathunt.Scanner
	yaraScanner        *yarascan.Scanner
	scaffoldGenerator  *sde.Generator
	state              *models.AppState
	width              int
	height             int
	selectedIndex      int
	ctx                context.Context
}

func NewApp(ctx context.Context, dockerClient *docker.Client) *App {
	containerInspector := forensics.NewContainerInspector(dockerClient.Raw())
	return &App{
		docker:             dockerClient,
		layerAnalyzer:      layers.NewAnalyzer(dockerClient),
		bloatDetector:      layers.NewBloatDetector(),
		diffEngine:         layers.NewDiffEngine(),
		tarExtractor:       layers.NewTarExtractor(dockerClient.Raw()),
		fileAnalyzer:       layers.NewFileAnalyzer(),
		containerInspector: containerInspector,
		fsInspector:        forensics.NewFileSystemInspector(containerInspector),
		processAnalyzer:    forensics.NewProcessAnalyzer(containerInspector),
		volumeAnalyzer:     forensics.NewVolumeAnalyzer(containerInspector),
		logAnalyzer:        forensics.NewLogAnalyzer(containerInspector),
		envAnalyzer:        forensics.NewEnvironmentAnalyzer(containerInspector),
		resourceMonitor:    forensics.NewResourceMonitor(containerInspector),
		diffScanner:        containerdiff.NewScanner(dockerClient.Raw()),
		timelineScanner:    timeline.NewScanner(dockerClient.Raw()),
		threatScanner:      threathunt.NewScanner(containerInspector),
		yaraScanner:        yarascan.NewScanner(containerInspector),
		scaffoldGenerator:  sde.NewGenerator(),
		ctx:                ctx,
		selectedIndex:      0,
		state: &models.AppState{
			CurrentScreen: "menu",
		},
	}
}

func (a *App) Init() tea.Cmd {
	return tea.EnterAltScreen
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return a.handleKeyPress(msg)
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
	case imagesLoadedMsg:
		a.state.ImageList = msg
	case containersLoadedMsg:
		a.state.ContainerList = msg
	case layersLoadedMsg:
		a.state.ImageLayers = msg.layers
		a.state.LayerAnalyses = msg.analyses
		a.state.BloatDetection = msg.bloat
		a.state.LayerRecommendations = msg.recommendations
		a.state.AnalysisStatus = msg.analysisStatus
		a.state.AnalysisError = msg.analysisError
		a.state.CurrentScreen = msg.targetScreen
		a.state.SelectedLayerIndex = 0
	case scaffoldExportedMsg:
		a.state.ExportMessage = msg.message
		a.state.LastExportPath = msg.path
	case optimizationExportedMsg:
		a.state.ExportMessage = msg.message
		a.state.LastExportPath = msg.path
	case threatHuntLoadedMsg:
		a.state.ThreatFindings = msg.findings
		a.state.ThreatSummary = msg.summary
		a.state.AnalysisStatus = msg.status
		a.state.AnalysisError = msg.err
		a.state.CurrentScreen = "threat-hunt"
		a.state.ScrollOffset = 0
	case containerDiffLoadedMsg:
		a.state.DiffChanges = msg.changes
		a.state.DiffSummary = msg.summary
		a.state.AnalysisStatus = msg.status
		a.state.AnalysisError = msg.err
		a.state.CurrentScreen = "container-diff"
		a.state.ScrollOffset = 0
	case timelineLoadedMsg:
		a.state.TimelineEvents = msg.events
		a.state.TimelineSummary = msg.summary
		a.state.AnalysisStatus = msg.status
		a.state.AnalysisError = msg.err
		a.state.CurrentScreen = "timeline"
		a.state.ScrollOffset = 0
	}
	return a, nil
}

func (a *App) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return a, tea.Quit
	}

	switch a.state.CurrentScreen {
	case "menu":
		return a.handleMenuKeys(msg)
	case "images":
		return a.handleImagesKeys(msg)
	case "containers":
		return a.handleContainersKeys(msg)
	case "image-detail":
		return a.handleImageDetailKeys(msg)
	case "container-detail":
		return a.handleContainerDetailKeys(msg)
	case "layers":
		return a.handleLayersKeys(msg)
	case "layer-detail":
		return a.handleLayerDetailKeys(msg)
	case "size-breakdown":
		return a.handleSizeBreakdownKeys(msg)
	case "file-browser":
		return a.handleFileBrowserKeys(msg)
	case "optimization":
		return a.handleOptimizationKeys(msg)
	case "scaffold":
		return a.handleScaffoldKeys(msg)
	case "forensics-menu":
		return a.handleForensicsMenuKeys(msg)
	case "filesystem":
		return a.handleFilesystemKeys(msg)
	case "processes":
		return a.handleProcessesKeys(msg)
	case "volumes":
		return a.handleVolumesKeys(msg)
	case "logs":
		return a.handleLogsKeys(msg)
	case "environment":
		return a.handleEnvironmentKeys(msg)
	case "resources":
		return a.handleResourcesKeys(msg)
	case "container-diff":
		return a.handleContainerDiffKeys(msg)
	case "timeline":
		return a.handleTimelineKeys(msg)
	case "threat-hunt":
		return a.handleThreatHuntKeys(msg)
	}

	return a, nil
}

func (a *App) handleMenuKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	menuItems := []string{"View Images", "View Containers", "Exit"}

	switch msg.String() {
	case "up", "k":
		a.selectedIndex = (a.selectedIndex - 1 + len(menuItems)) % len(menuItems)
	case "down", "j":
		a.selectedIndex = (a.selectedIndex + 1) % len(menuItems)
	case "enter":
		switch menuItems[a.selectedIndex] {
		case "View Images":
			a.state.CurrentScreen = "images"
			a.selectedIndex = 0
			return a, a.loadImages()
		case "View Containers":
			a.state.CurrentScreen = "containers"
			a.selectedIndex = 0
			return a, a.loadContainers()
		case "Exit":
			return a, tea.Quit
		}
	}
	return a, nil
}

func (a *App) handleImagesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		a.selectedIndex = (a.selectedIndex - 1 + len(a.state.ImageList)) % len(a.state.ImageList)
	case "down", "j":
		a.selectedIndex = (a.selectedIndex + 1) % len(a.state.ImageList)
	case "enter":
		if len(a.state.ImageList) > 0 && a.selectedIndex < len(a.state.ImageList) {
			a.state.SelectedImage = a.state.ImageList[a.selectedIndex]
			a.state.CurrentScreen = "image-detail"
			a.selectedIndex = 0
		}
	case "esc", "b":
		a.state.CurrentScreen = "menu"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) handleContainersKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		a.selectedIndex = (a.selectedIndex - 1 + len(a.state.ContainerList)) % len(a.state.ContainerList)
	case "down", "j":
		a.selectedIndex = (a.selectedIndex + 1) % len(a.state.ContainerList)
	case "enter":
		if len(a.state.ContainerList) > 0 && a.selectedIndex < len(a.state.ContainerList) {
			a.state.SelectedContainer = a.state.ContainerList[a.selectedIndex]
			a.state.CurrentScreen = "container-detail"
			a.selectedIndex = 0
		}
	case "esc", "b":
		a.state.CurrentScreen = "menu"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) handleImageDetailKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "l":
		a.state.CurrentScreen = "layers"
		a.state.AnalysisStatus = "Preparing image layer analysis..."
		a.state.AnalysisError = ""
		a.state.ExportMessage = ""
		a.state.LastExportPath = ""
		return a, a.loadLayersFor("layers")
	case "g":
		if a.state.ImageLayers == nil {
			a.state.CurrentScreen = "scaffold"
			a.state.AnalysisStatus = "Preparing image and tar analysis for scaffold generation..."
			a.state.AnalysisError = ""
			a.state.ExportMessage = ""
			a.state.LastExportPath = ""
			return a, a.loadLayersFor("scaffold")
		}
		a.state.ExportMessage = ""
		a.state.LastExportPath = ""
		a.state.CurrentScreen = "scaffold"
	case "o":
		if a.state.ImageLayers == nil {
			a.state.CurrentScreen = "optimization"
			a.state.AnalysisStatus = "Preparing optimization analysis..."
			a.state.AnalysisError = ""
			a.state.ExportMessage = ""
			a.state.LastExportPath = ""
			return a, a.loadLayersFor("optimization")
		}
		a.state.ExportMessage = ""
		a.state.LastExportPath = ""
		a.state.CurrentScreen = "optimization"
	case "esc", "b":
		a.state.CurrentScreen = "images"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) handleContainerDetailKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "f":
		// Open forensics menu
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
	case "esc", "b":
		a.state.CurrentScreen = "containers"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) View() string {
	switch a.state.CurrentScreen {
	case "menu":
		return a.renderMenu()
	case "images":
		return a.renderImageList()
	case "containers":
		return a.renderContainerList()
	case "image-detail":
		return a.renderImageDetail()
	case "container-detail":
		return a.renderContainerDetail()
	case "layers":
		return a.renderLayers()
	case "layer-detail":
		return a.renderLayerDetail()
	case "size-breakdown":
		return a.renderSizeBreakdown()
	case "file-browser":
		return a.renderFileBrowser()
	case "optimization":
		return a.renderOptimization()
	case "scaffold":
		return a.renderScaffold()
	case "forensics-menu":
		return a.renderForensicsMenu()
	case "filesystem":
		return a.renderFilesystem()
	case "processes":
		return a.renderProcesses()
	case "volumes":
		return a.renderVolumes()
	case "logs":
		return a.renderLogs()
	case "environment":
		return a.renderEnvironment()
	case "resources":
		return a.renderResources()
	case "container-diff":
		return a.renderContainerDiff()
	case "timeline":
		return a.renderTimeline()
	case "threat-hunt":
		return a.renderThreatHunt()
	default:
		return "Unknown screen"
	}
}

func (a *App) renderMenu() string {
	title := titleStyle.Render("🐳 BoneStack - Container Operations Inspector")

	menuItems := []string{
		"View Images",
		"View Containers",
		"Exit",
	}

	var menu strings.Builder
	menu.WriteString(title + "\n\n")
	menu.WriteString("Main Menu\n\n")

	for i, item := range menuItems {
		if i == a.selectedIndex {
			menu.WriteString(selectedStyle.Render("→ "+item) + "\n")
		} else {
			menu.WriteString(normalStyle.Render("  "+item) + "\n")
		}
	}

	menu.WriteString("\n" + helpStyle.Render("↑/↓ Navigate | Enter Select | q Quit"))
	return menu.String()
}

func (a *App) renderImageList() string {
	title := titleStyle.Render("🖼️  Docker Images")

	var list strings.Builder
	list.WriteString(title + "\n\n")

	if len(a.state.ImageList) == 0 {
		list.WriteString("No images found.\n")
	} else {
		for i, img := range a.state.ImageList {
			var name string
			if len(img.RepoTags) > 0 {
				name = img.RepoTags[0]
			} else {
				name = safeSlice(img.ID, 12)
			}

			size := fmt.Sprintf("%.2f MB", float64(img.Size)/1024/1024)
			line := fmt.Sprintf("%-40s %s", name, size)

			if i == a.selectedIndex {
				list.WriteString(selectedStyle.Render("→ "+line) + "\n")
			} else {
				list.WriteString(normalStyle.Render("  "+line) + "\n")
			}
		}
	}

	list.WriteString("\n" + helpStyle.Render("↑/↓ Navigate | Enter Inspect | b Back | q Quit"))
	return list.String()
}

func (a *App) renderContainerList() string {
	title := titleStyle.Render("📦 Docker Containers")

	var list strings.Builder
	list.WriteString(title + "\n\n")

	if len(a.state.ContainerList) == 0 {
		list.WriteString("No containers found.\n")
	} else {
		for i, container := range a.state.ContainerList {
			name := strings.TrimPrefix(container.Names[0], "/")
			status := container.Status
			line := fmt.Sprintf("%-30s %s", name, status)

			if i == a.selectedIndex {
				list.WriteString(selectedStyle.Render("→ "+line) + "\n")
			} else {
				list.WriteString(normalStyle.Render("  "+line) + "\n")
			}
		}
	}

	list.WriteString("\n" + helpStyle.Render("↑/↓ Navigate | Enter Inspect | b Back | q Quit"))
	return list.String()
}

func (a *App) renderImageDetail() string {
	inspect, err := a.docker.InspectImage(a.ctx, a.state.SelectedImage.ID)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	// Get history for additional info
	history, histErr := a.docker.GetImageHistory(a.ctx, a.state.SelectedImage.ID)

	var detail strings.Builder
	detail.WriteString(titleStyle.Render("🖼️  Image Details") + "\n\n")

	if len(a.state.SelectedImage.RepoTags) > 0 {
		detail.WriteString(fmt.Sprintf("Name:      %s\n", a.state.SelectedImage.RepoTags[0]))
	}
	detail.WriteString(fmt.Sprintf("ID:        %s\n", safeSlice(a.state.SelectedImage.ID, 12)))
	detail.WriteString(fmt.Sprintf("Size:      %.2f MB\n", float64(a.state.SelectedImage.Size)/1024/1024))
	detail.WriteString(fmt.Sprintf("Created:   %d\n", a.state.SelectedImage.Created))
	detail.WriteString(fmt.Sprintf("OS:        %s\n", inspect.Os))
	detail.WriteString(fmt.Sprintf("Arch:      %s\n", inspect.Architecture))

	if histErr == nil && len(history) > 0 {
		detail.WriteString(fmt.Sprintf("Layers:    %d\n", len(history)))
	}

	if len(inspect.Config.ExposedPorts) > 0 {
		detail.WriteString("\nExposed Ports:\n")
		for port := range inspect.Config.ExposedPorts {
			detail.WriteString(fmt.Sprintf("  - %s\n", port))
		}
	}

	if len(inspect.Config.Volumes) > 0 {
		detail.WriteString("\nVolumes:\n")
		for vol := range inspect.Config.Volumes {
			detail.WriteString(fmt.Sprintf("  - %s\n", vol))
		}
	}

	detail.WriteString("\n" + helpStyle.Render("l Layers | o Optimize | g Generate Dockerfile | b Back | q Quit"))
	return detail.String()
}

func (a *App) renderContainerDetail() string {
	inspect, err := a.docker.InspectContainer(a.ctx, a.state.SelectedContainer.ID)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	var detail strings.Builder
	detail.WriteString(titleStyle.Render("📦 Container Details") + "\n\n")

	detail.WriteString(fmt.Sprintf("Name:     %s\n", strings.TrimPrefix(a.state.SelectedContainer.Names[0], "/")))
	detail.WriteString(fmt.Sprintf("ID:       %s\n", safeSlice(a.state.SelectedContainer.ID, 12)))
	detail.WriteString(fmt.Sprintf("Image:    %s\n", a.state.SelectedContainer.Image))
	detail.WriteString(fmt.Sprintf("Status:   %s\n", a.state.SelectedContainer.Status))
	detail.WriteString(fmt.Sprintf("State:    %s\n", inspect.State.Status))

	if len(inspect.NetworkSettings.Ports) > 0 {
		detail.WriteString("\nPort Mappings:\n")
		for port, bindings := range inspect.NetworkSettings.Ports {
			for _, binding := range bindings {
				detail.WriteString(fmt.Sprintf("  - %s:%s → %s\n", binding.HostIP, binding.HostPort, port))
			}
		}
	}

	if len(inspect.Mounts) > 0 {
		detail.WriteString("\nMounts:\n")
		for _, mount := range inspect.Mounts {
			detail.WriteString(fmt.Sprintf("  - %s → %s\n", mount.Source, mount.Destination))
		}
	}

	detail.WriteString("\n" + helpStyle.Render("f Forensics | b Back | q Quit"))
	return detail.String()
}

func (a *App) handleLayersKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.state.ImageLayers == nil || len(a.state.ImageLayers.Layers) == 0 {
		return a, nil
	}

	switch msg.String() {
	case "up", "k":
		a.state.SelectedLayerIndex = (a.state.SelectedLayerIndex - 1 + len(a.state.ImageLayers.Layers)) % len(a.state.ImageLayers.Layers)
	case "down", "j":
		a.state.SelectedLayerIndex = (a.state.SelectedLayerIndex + 1) % len(a.state.ImageLayers.Layers)
	case "enter":
		a.state.CurrentScreen = "layer-detail"
	case "s":
		// Show size breakdown
		a.state.CurrentScreen = "size-breakdown"
	case "o":
		if a.state.ImageLayers == nil {
			return a, a.loadLayersFor("optimization")
		}
		a.state.CurrentScreen = "optimization"
	case "esc", "b":
		a.state.CurrentScreen = "image-detail"
		a.state.SelectedLayerIndex = 0
	}
	return a, nil
}

func (a *App) handleLayerDetailKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "layers"
	case "f":
		// Browse files in this layer
		a.state.CurrentScreen = "file-browser"
	}
	return a, nil
}

func (a *App) handleSizeBreakdownKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "layers"
	}
	return a, nil
}

func (a *App) handleFileBrowserKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "layer-detail"
	}
	return a, nil
}

func (a *App) handleOptimizationKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "w":
		return a, a.exportOptimizationReport()
	case "esc", "b":
		a.state.CurrentScreen = "image-detail"
	}
	return a, nil
}

func (a *App) handleScaffoldKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "w":
		return a, a.exportScaffold()
	case "esc", "b":
		a.state.CurrentScreen = "image-detail"
	}
	return a, nil
}

func (a *App) renderLayers() string {
	if a.state.ImageLayers == nil || len(a.state.ImageLayers.Layers) == 0 {
		return titleStyle.Render("🔍 Image Layers") + "\n\nLoading layers...\n\n" + helpStyle.Render("b Back | q Quit")
	}

	var output strings.Builder
	output.WriteString(titleStyle.Render("🔍 Image Layers") + "\n\n")

	totalSize := int64(0)
	for _, layer := range a.state.ImageLayers.Layers {
		totalSize += layer.Size
	}

	// Display summary
	output.WriteString(fmt.Sprintf("Total Layers: %d | Total Size: %s\n\n",
		len(a.state.ImageLayers.Layers), layers.SizeFormatter(totalSize)))

	// List layers
	for i, layer := range a.state.ImageLayers.Layers {
		pct := layers.PercentageOfTotal(layer.Size, totalSize)
		sizeStr := layers.SizeFormatter(layer.Size)

		line := fmt.Sprintf("[%d] %8s (%.1f%%) │ %s",
			i, sizeStr, pct, layer.Command[:minInt(50, len(layer.Command))])

		if i == a.state.SelectedLayerIndex {
			output.WriteString(selectedStyle.Render("→ "+line) + "\n")
		} else {
			output.WriteString(normalStyle.Render("  "+line) + "\n")
		}
	}

	output.WriteString("\n" + helpStyle.Render("↑/↓ Navigate | Enter Details | s Size Breakdown | o Optimize | b Back | q Quit"))
	return output.String()
}

func (a *App) renderLayerDetail() string {
	if a.state.ImageLayers == nil || a.state.SelectedLayerIndex >= len(a.state.ImageLayers.Layers) {
		return "Error: Invalid layer index\n" + helpStyle.Render("b Back | q Quit")
	}

	layer := a.state.ImageLayers.Layers[a.state.SelectedLayerIndex]
	analysis := a.state.LayerAnalyses[a.state.SelectedLayerIndex]
	bloat := a.state.BloatDetection[a.state.SelectedLayerIndex]

	var detail strings.Builder
	detail.WriteString(titleStyle.Render(fmt.Sprintf("🔍 Layer %d Details", a.state.SelectedLayerIndex)) + "\n\n")

	detail.WriteString(fmt.Sprintf("ID:           %s\n", safeSlice(layer.ID, 12)))
	detail.WriteString(fmt.Sprintf("Size:         %s\n", layers.SizeFormatter(layer.Size)))
	detail.WriteString(fmt.Sprintf("Created:      %d\n", layer.Created))
	detail.WriteString(fmt.Sprintf("Command:      %s\n\n", layer.Command))

	detail.WriteString(fmt.Sprintf("Files Added:  ~%d\n", analysis.FilesAdded))
	detail.WriteString(fmt.Sprintf("Dirs Added:   ~%d\n", analysis.DirsAdded))
	detail.WriteString(fmt.Sprintf("Confidence:   %.0f%%\n\n", analysis.ConfidenceScore*100))

	if len(bloat) > 0 {
		detail.WriteString("⚠️  BLOAT DETECTED:\n")
		for _, item := range bloat {
			detail.WriteString(fmt.Sprintf("  • %s - %s\n", item.Pattern, item.Description))
			if item.Removable {
				detail.WriteString(fmt.Sprintf("    Removable: Yes (~%s)\n", layers.SizeFormatter(item.EstimatedSize)))
			}
		}
	} else {
		detail.WriteString("✅ No bloat detected\n")
	}

	detail.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
	return detail.String()
}

func (a *App) renderSizeBreakdown() string {
	if a.state.ImageLayers == nil || len(a.state.ImageLayers.Layers) == 0 {
		return "No layers to analyze\n" + helpStyle.Render("b Back | q Quit")
	}

	var output strings.Builder
	output.WriteString(titleStyle.Render("📊 Size Breakdown") + "\n\n")

	totalSize := int64(0)
	for _, layer := range a.state.ImageLayers.Layers {
		totalSize += layer.Size
	}

	// Calculate cumulative sizes
	type layerInfo struct {
		index   int
		size    int64
		cumSize int64
		pct     float64
		command string
	}

	var infos []layerInfo
	cumSize := int64(0)
	for i, layer := range a.state.ImageLayers.Layers {
		cumSize += layer.Size
		pct := layers.PercentageOfTotal(layer.Size, totalSize)
		infos = append(infos, layerInfo{
			index:   i,
			size:    layer.Size,
			cumSize: cumSize,
			pct:     pct,
			command: layer.Command,
		})
	}

	// Display top layers by size
	output.WriteString(fmt.Sprintf("Total Size: %s\n\n", layers.SizeFormatter(totalSize)))
	output.WriteString("Layer Size Breakdown:\n")
	output.WriteString("─────────────────────────────────────────────────────\n")

	for _, info := range infos {
		bar := generateBar(int(info.pct), 20)
		output.WriteString(fmt.Sprintf("L%-2d │ %7s │ %s │ %.1f%%\n",
			info.index,
			layers.SizeFormatter(info.size),
			bar,
			info.pct))
	}

	// Show cumulative sizes
	output.WriteString("\nCumulative Size:\n")
	output.WriteString("─────────────────────────────────────────────────────\n")
	for _, info := range infos {
		cumPct := layers.PercentageOfTotal(info.cumSize, totalSize)
		bar := generateBar(int(cumPct), 20)
		output.WriteString(fmt.Sprintf("→ L%-2d │ %7s │ %s │ %.1f%%\n",
			info.index,
			layers.SizeFormatter(info.cumSize),
			bar,
			cumPct))
	}

	// Show largest layers
	output.WriteString("\n⭐ Largest Layers:\n")
	output.WriteString("─────────────────────────────────────────────────────\n")

	// Simple sort to find top 3
	for i := 0; i < len(infos) && i < 3; i++ {
		maxIdx := i
		for j := i + 1; j < len(infos); j++ {
			if infos[j].size > infos[maxIdx].size {
				maxIdx = j
			}
		}
		infos[i], infos[maxIdx] = infos[maxIdx], infos[i]

		info := infos[i]
		output.WriteString(fmt.Sprintf("%d. Layer %d: %s (%.1f%%)\n   %s\n",
			i+1, info.index, layers.SizeFormatter(info.size), info.pct,
			info.command[:minInt(60, len(info.command))]))
	}

	output.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
	return output.String()
}

func generateBar(percentage int, width int) string {
	if percentage > 100 {
		percentage = 100
	}
	filled := (percentage * width) / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return bar
}

func safeSlice(s string, length int) string {
	if len(s) < length {
		return s
	}
	return s[:length]
}

func (a *App) loadLayersFor(targetScreen string) tea.Cmd {
	return func() tea.Msg {
		imageLayers, err := a.layerAnalyzer.AnalyzeImage(a.ctx, a.state.SelectedImage.ID)
		if err != nil {
			a.state.Error = err.Error()
			return nil
		}

		// Perform analysis
		analyses, _ := a.layerAnalyzer.AnalyzeLayerSequence(imageLayers)
		bloatMap := a.bloatDetector.DetectInImage(imageLayers)
		recommendations := a.bloatDetector.GenerateRecommendations(imageLayers, bloatMap)
		layerTarData, fileAnalyses, tarErr := a.loadLayerTarAnalysis(a.state.SelectedImage.ID)
		a.state.LayerTarData = layerTarData
		a.state.FileAnalysis = fileAnalyses
		a.state.OptimizationReport = a.bloatDetector.BuildOptimizationReport(imageLayers, bloatMap)
		analysisStatus := fmt.Sprintf("Layer analysis ready. Tar analysis processed %d layers.", len(fileAnalyses))
		analysisError := ""
		if tarErr != nil {
			analysisStatus = "Layer analysis ready. Tar analysis unavailable."
			analysisError = tarErr.Error()
		}

		return layersLoadedMsg{
			layers:          imageLayers,
			analyses:        analyses,
			bloat:           bloatMap,
			recommendations: recommendations,
			analysisStatus:  analysisStatus,
			analysisError:   analysisError,
			targetScreen:    targetScreen,
		}
	}
}

func (a *App) loadLayerTarAnalysis(imageID string) ([]layers.LayerTarData, []layers.FileAnalysisResult, error) {
	if a.tarExtractor == nil || a.fileAnalyzer == nil {
		return nil, nil, fmt.Errorf("tar analysis helpers not initialized")
	}

	layerData, err := a.tarExtractor.ExtractImageLayers(a.ctx, imageID)
	if err != nil {
		return nil, nil, err
	}

	analyses := make([]layers.FileAnalysisResult, 0, len(layerData))
	for _, tarData := range layerData {
		analysis := a.fileAnalyzer.AnalyzeTarData(&tarData)
		if analysis != nil {
			analyses = append(analyses, *analysis)
		}
	}

	return layerData, analyses, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (a *App) loadImages() tea.Cmd {
	return func() tea.Msg {
		images, err := a.docker.ListImages(a.ctx)
		if err != nil {
			a.state.Error = err.Error()
			return nil
		}
		return imagesLoadedMsg(images)
	}
}

func (a *App) loadContainers() tea.Cmd {
	return func() tea.Msg {
		containers, err := a.docker.ListContainers(a.ctx)
		if err != nil {
			a.state.Error = err.Error()
			return nil
		}
		return containersLoadedMsg(containers)
	}
}

func (a *App) loadThreatHunt() tea.Cmd {
	return func() tea.Msg {
		if a.threatScanner == nil {
			return threatHuntLoadedMsg{
				status: "Threat hunt unavailable.",
				err:    "threat scanner not initialized",
			}
		}

		result, err := a.threatScanner.HuntLive(a.ctx, a.state.SelectedContainer.ID)
		if err != nil {
			return threatHuntLoadedMsg{
				status: "Threat hunt failed.",
				err:    err.Error(),
			}
		}

		findings := make([]map[string]string, 0, len(result.Findings))
		for _, finding := range result.Findings {
			findings = append(findings, map[string]string{
				"category": finding.Category,
				"path":     finding.Path,
				"severity": finding.Severity,
				"detail":   finding.Detail,
			})
		}

		status := fmt.Sprintf("Threat hunt completed. %d findings across %d categories.", len(result.Findings), len(result.Summary))
		summary := result.Summary
		if a.yaraScanner != nil {
			yaraFindings, yaraErr := a.yaraScanner.ScanLive(a.ctx, a.state.SelectedContainer.ID)
			switch {
			case yaraErr == nil:
				for _, finding := range yaraFindings {
					category := "yara:" + finding.Rule
					findings = append(findings, map[string]string{
						"category": category,
						"path":     finding.Path,
						"severity": finding.Severity,
						"detail":   finding.Detail,
					})
					summary[category]++
				}
				if len(yaraFindings) > 0 {
					status = fmt.Sprintf("%s YARA matched %d files.", status, len(yaraFindings))
				} else {
					status = status + " YARA found no additional matches."
				}
			case yaraErr == yarascan.ErrYARANotInstalled:
				status = status + " YARA unavailable on host."
			default:
				status = status + " YARA scan failed: " + yaraErr.Error()
			}
		}

		return threatHuntLoadedMsg{
			findings: findings,
			summary:  summary,
			status:   status,
		}
	}
}

func (a *App) loadContainerDiff() tea.Cmd {
	return func() tea.Msg {
		if a.diffScanner == nil {
			return containerDiffLoadedMsg{
				status: "Container diff unavailable.",
				err:    "container diff scanner not initialized",
			}
		}

		result, err := a.diffScanner.Diff(a.ctx, a.state.SelectedContainer.ID)
		if err != nil {
			return containerDiffLoadedMsg{
				status: "Container diff failed.",
				err:    err.Error(),
			}
		}

		changes := make([]map[string]string, 0, len(result.Changes))
		for _, change := range result.Changes {
			changes = append(changes, map[string]string{
				"path":       change.Path,
				"kind":       change.Kind,
				"suspicious": fmt.Sprintf("%t", change.Suspicious),
				"detail":     change.Detail,
			})
		}

		status := fmt.Sprintf("Container diff loaded. %d filesystem changes.", len(result.Changes))
		return containerDiffLoadedMsg{
			changes: changes,
			summary: result.Summary,
			status:  status,
		}
	}
}

func (a *App) loadTimeline() tea.Cmd {
	return func() tea.Msg {
		if a.timelineScanner == nil {
			return timelineLoadedMsg{
				status: "Timeline unavailable.",
				err:    "timeline scanner not initialized",
			}
		}

		result, err := a.timelineScanner.RecentContainerEvents(a.ctx, a.state.SelectedContainer.ID, time.Hour)
		if err != nil {
			return timelineLoadedMsg{
				status: "Timeline load failed.",
				err:    err.Error(),
			}
		}

		events := make([]map[string]string, 0, len(result.Events))
		for _, event := range result.Events {
			events = append(events, map[string]string{
				"time":    event.Time,
				"action":  event.Action,
				"type":    event.Type,
				"actor":   event.Actor,
				"details": event.Details,
			})
		}

		status := fmt.Sprintf("Timeline loaded. %d recent events.", len(result.Events))
		return timelineLoadedMsg{
			events:  events,
			summary: result.Summary,
			status:  status,
		}
	}
}

type imagesLoadedMsg []docker.ImageSummary
type containersLoadedMsg []docker.ContainerSummary

type layersLoadedMsg struct {
	layers          *layers.ImageLayers
	analyses        []layers.LayerAnalysis
	bloat           map[int][]layers.BloatItem
	recommendations []string
	analysisStatus  string
	analysisError   string
	targetScreen    string
}

type scaffoldExportedMsg struct {
	message string
	path    string
}

type optimizationExportedMsg struct {
	message string
	path    string
}

type threatHuntLoadedMsg struct {
	findings []map[string]string
	summary  map[string]int
	status   string
	err      string
}

type containerDiffLoadedMsg struct {
	changes []map[string]string
	summary map[string]int
	status  string
	err     string
}

type timelineLoadedMsg struct {
	events  []map[string]string
	summary map[string]int
	status  string
	err     string
}

// renderFileBrowser displays file information for a layer
func (a *App) renderFileBrowser() string {
	if a.state.SelectedLayerIndex >= len(a.state.ImageLayers.Layers) {
		return titleStyle.Render("📁 File Browser") + "\n\nNo layer selected.\n\n" + helpStyle.Render("b Back | q Quit")
	}

	layer := a.state.ImageLayers.Layers[a.state.SelectedLayerIndex]

	var output strings.Builder
	output.WriteString(titleStyle.Render("📁 File Browser") + "\n\n")
	output.WriteString(fmt.Sprintf("Layer: %s\n", safeSlice(layer.ID, 12)))
	output.WriteString(fmt.Sprintf("Command: %s\n", layer.Command))
	output.WriteString(fmt.Sprintf("Size: %.2f MB\n\n", float64(layer.Size)/1024/1024))

	analysis := a.state.LayerAnalyses[a.state.SelectedLayerIndex]

	output.WriteString("📊 Layer Analysis:\n\n")

	// Show file stats
	output.WriteString(fmt.Sprintf("  Files Added: %d\n", analysis.FilesAdded))
	output.WriteString(fmt.Sprintf("  Directories Added: %d\n", analysis.DirsAdded))
	output.WriteString(fmt.Sprintf("  Confidence: %.0f%%\n\n", analysis.ConfidenceScore*100))

	// Show large files
	if len(analysis.LargeFiles) > 0 {
		output.WriteString("📦 Large Files:\n")
		for i, file := range analysis.LargeFiles {
			if i >= 10 {
				output.WriteString(fmt.Sprintf("   ... and %d more\n", len(analysis.LargeFiles)-i))
				break
			}
			path := file
			if len(path) > 60 {
				path = "..." + path[len(path)-57:]
			}
			output.WriteString(fmt.Sprintf("   • %s\n", path))
		}
		output.WriteString("\n")
	}

	// Show bloat indicators
	if len(analysis.BloatIndicators) > 0 {
		output.WriteString("⚠️  Bloat Detected:\n")
		for i, bloat := range analysis.BloatIndicators {
			if i >= 5 {
				output.WriteString(fmt.Sprintf("   ... and %d more\n", len(analysis.BloatIndicators)-i))
				break
			}
			output.WriteString(fmt.Sprintf("   • %s (%s)\n", bloat.Pattern, bloat.Description[:min(40, len(bloat.Description))]))
		}
		output.WriteString("\n")
	}

	// Show packages
	if len(analysis.InstalledPackages) > 0 {
		output.WriteString("📦 Packages Detected:\n")
		for i, pkg := range analysis.InstalledPackages {
			if i >= 5 {
				output.WriteString(fmt.Sprintf("   ... and %d more\n", len(analysis.InstalledPackages)-i))
				break
			}
			output.WriteString(fmt.Sprintf("   • %s\n", pkg))
		}
	}

	output.WriteString("\n" + helpStyle.Render("b Back | q Quit"))

	return output.String()
}

// Forensics handlers and renderers

func (a *App) handleForensicsMenuKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	menuItems := []string{"Filesystem", "Processes", "Volumes", "Logs", "Environment", "Resources", "Container Diff", "Timeline", "Threat Hunt"}

	switch msg.String() {
	case "up", "k":
		a.selectedIndex = (a.selectedIndex - 1 + len(menuItems)) % len(menuItems)
	case "down", "j":
		a.selectedIndex = (a.selectedIndex + 1) % len(menuItems)
	case "enter":
		switch menuItems[a.selectedIndex] {
		case "Filesystem":
			a.state.CurrentScreen = "filesystem"
		case "Processes":
			a.state.CurrentScreen = "processes"
		case "Volumes":
			a.state.CurrentScreen = "volumes"
		case "Logs":
			a.state.CurrentScreen = "logs"
		case "Environment":
			a.state.CurrentScreen = "environment"
		case "Resources":
			a.state.CurrentScreen = "resources"
		case "Container Diff":
			a.state.CurrentScreen = "container-diff"
			a.state.AnalysisStatus = "Loading container filesystem changes..."
			a.state.AnalysisError = ""
			a.state.ExportMessage = ""
			a.state.LastExportPath = ""
			return a, a.loadContainerDiff()
		case "Timeline":
			a.state.CurrentScreen = "timeline"
			a.state.AnalysisStatus = "Loading recent Docker events..."
			a.state.AnalysisError = ""
			a.state.ExportMessage = ""
			a.state.LastExportPath = ""
			return a, a.loadTimeline()
		case "Threat Hunt":
			a.state.CurrentScreen = "threat-hunt"
			a.state.AnalysisStatus = "Scanning container for persistence and shell IOCs..."
			a.state.AnalysisError = ""
			a.state.ExportMessage = ""
			a.state.LastExportPath = ""
			return a, a.loadThreatHunt()
		}
		a.selectedIndex = 0
	case "esc", "b":
		a.state.CurrentScreen = "container-detail"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) renderForensicsMenu() string {
	name := strings.TrimPrefix(a.state.SelectedContainer.Names[0], "/")
	title := titleStyle.Render(fmt.Sprintf("🔍 Forensics - %s", name))

	menuItems := []string{
		"Filesystem",
		"Processes",
		"Volumes",
		"Logs",
		"Environment",
		"Resources",
		"Container Diff",
		"Timeline",
		"Threat Hunt",
	}

	var menu strings.Builder
	menu.WriteString(title + "\n\n")

	for i, item := range menuItems {
		if i == a.selectedIndex {
			menu.WriteString(selectedStyle.Render("→ "+item) + "\n")
		} else {
			menu.WriteString(normalStyle.Render("  "+item) + "\n")
		}
	}

	menu.WriteString("\n" + helpStyle.Render("↑/↓ Navigate | Enter Select | b Back | q Quit"))
	return menu.String()
}

func (a *App) handleFilesystemKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.state.ScrollOffset > 0 {
			a.state.ScrollOffset--
		}
	case "down", "j":
		a.state.ScrollOffset++
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
		a.state.ScrollOffset = 0
	}
	return a, nil
}

func (a *App) renderFilesystem() string {
	var fs strings.Builder
	fs.WriteString(titleStyle.Render("📁 Filesystem") + "\n\n")

	fsInspector := a.fsInspector
	if fsInspector == nil {
		fs.WriteString("Error: Filesystem inspector not initialized\n")
		return fs.String()
	}

	files, err := fsInspector.ListDirectory(a.ctx, a.state.SelectedContainer.ID, "/")
	if err != nil {
		fs.WriteString(fmt.Sprintf("Error listing directory: %v\n", err))
	} else {
		fs.WriteString(fmt.Sprintf("Root Directory Contents: %d entries\n\n", len(files)))

		start := a.state.ScrollOffset
		if start < 0 {
			start = 0
		}
		if start > len(files)-1 && len(files) > 0 {
			start = len(files) - 1
		}

		visibleRows := 15
		if a.height > 12 {
			visibleRows = a.height - 10
		}
		end := start + visibleRows
		if end > len(files) {
			end = len(files)
		}

		for i := start; i < end; i++ {
			file := files[i]
			kind := "file"
			if file.IsDir {
				kind = "dir"
			}
			fs.WriteString(fmt.Sprintf("  %-4s %s\n", kind, file.Path))
		}

		if len(files) > visibleRows {
			fs.WriteString(fmt.Sprintf("\n(Showing entries %d-%d of %d)\n", start+1, end, len(files)))
		}
	}

	fs.WriteString("\n" + helpStyle.Render("↑/↓ Scroll | b Back | q Quit"))
	return fs.String()
}

func (a *App) handleProcessesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) renderProcesses() string {
	var ps strings.Builder
	ps.WriteString(titleStyle.Render("⚙️  Processes") + "\n\n")

	processAnalyzer := a.processAnalyzer
	if processAnalyzer == nil {
		ps.WriteString("Error: Process analyzer not initialized\n")
		return ps.String()
	}

	processes, err := processAnalyzer.ListProcesses(a.ctx, a.state.SelectedContainer.ID)
	if err != nil {
		ps.WriteString(fmt.Sprintf("Error listing processes: %v\n", err))
	} else {
		ps.WriteString(fmt.Sprintf("Total processes: %d\n\n", len(processes)))
		ps.WriteString("PID      CMD\n")
		ps.WriteString("────────────────────────────────────\n")

		for i, proc := range processes {
			if i >= 15 {
				ps.WriteString(fmt.Sprintf("... and %d more processes\n", len(processes)-i))
				break
			}
			ps.WriteString(fmt.Sprintf("%-8d %s\n", proc.PID, proc.Command))
		}
	}

	ps.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
	return ps.String()
}

func (a *App) handleVolumesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) renderVolumes() string {
	var vols strings.Builder
	vols.WriteString(titleStyle.Render("💾 Volumes") + "\n\n")

	volumeAnalyzer := a.volumeAnalyzer
	if volumeAnalyzer == nil {
		vols.WriteString("Error: Volume analyzer not initialized\n")
		return vols.String()
	}

	volumes, err := volumeAnalyzer.GetMountPoints(a.ctx, a.state.SelectedContainer.ID)
	if err != nil {
		vols.WriteString(fmt.Sprintf("Error getting mount points: %v\n", err))
	} else {
		if len(volumes) == 0 {
			vols.WriteString("No mounted volumes\n")
		} else {
			vols.WriteString(fmt.Sprintf("Total mounts: %d\n\n", len(volumes)))
			vols.WriteString("Source                    Destination              Mode\n")
			vols.WriteString("─────────────────────────────────────────────────────────────\n")

			for i, vol := range volumes {
				if i >= 12 {
					vols.WriteString(fmt.Sprintf("... and %d more volumes\n", len(volumes)-i))
					break
				}
				mode := "rw"
				if vol.ReadOnly {
					mode = "ro"
				}
				source := vol.Source
				if len(source) > 25 {
					source = "..." + source[len(source)-22:]
				}
				dest := vol.Destination
				if len(dest) > 25 {
					dest = "..." + dest[len(dest)-22:]
				}
				vols.WriteString(fmt.Sprintf("%-25s %-25s %s\n", source, dest, mode))
			}
		}
	}

	vols.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
	return vols.String()
}

func (a *App) handleLogsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.state.ScrollOffset > 0 {
			a.state.ScrollOffset--
		}
	case "down", "j":
		if len(a.state.LogLines) > 20 {
			a.state.ScrollOffset++
		}
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
		a.state.ScrollOffset = 0
	}
	return a, nil
}

func (a *App) renderLogs() string {
	var logs strings.Builder
	logs.WriteString(titleStyle.Render("📋 Container Logs") + "\n\n")

	logAnalyzer := a.logAnalyzer
	if logAnalyzer == nil {
		logs.WriteString("Error: Log analyzer not initialized\n")
		return logs.String()
	}

	rawLogs, err := logAnalyzer.GetLogs(a.ctx, a.state.SelectedContainer.ID, 50)
	if err != nil {
		logs.WriteString(fmt.Sprintf("Error getting logs: %v\n", err))
	} else {
		logLines := []string{}
		if rawLogs != "" {
			logLines = strings.Split(strings.TrimRight(rawLogs, "\n"), "\n")
		}
		a.state.LogLines = logLines

		if len(logLines) == 0 {
			logs.WriteString("No logs available\n")
		} else {
			logs.WriteString(fmt.Sprintf("Last %d log lines:\n\n", len(logLines)))

			start := a.state.ScrollOffset
			if start > len(logLines)-1 {
				start = len(logLines) - 1
			}

			end := start + 15
			if end > len(logLines) {
				end = len(logLines)
			}

			for i := start; i < end; i++ {
				line := logLines[i]
				if len(line) > a.width-4 {
					line = line[:a.width-7] + "..."
				}
				logs.WriteString(fmt.Sprintf("  %s\n", line))
			}

			if len(logLines) > 15 {
				logs.WriteString(fmt.Sprintf("\n(Showing lines %d-%d of %d)\n", start+1, end, len(logLines)))
			}
		}
	}

	logs.WriteString("\n" + helpStyle.Render("↑/↓ Scroll | b Back | q Quit"))
	return logs.String()
}

func (a *App) handleEnvironmentKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) renderEnvironment() string {
	var env strings.Builder
	env.WriteString(titleStyle.Render("🌿 Environment") + "\n\n")

	if a.envAnalyzer == nil {
		env.WriteString("Error: Environment analyzer not initialized\n")
		return env.String()
	}

	envVars, err := a.envAnalyzer.GetEnvironmentVariables(a.ctx, a.state.SelectedContainer.ID)
	if err != nil {
		env.WriteString(fmt.Sprintf("Error getting environment variables: %v\n", err))
		env.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
		return env.String()
	}

	summary, _ := a.envAnalyzer.GetEnvironmentSummary(a.ctx, a.state.SelectedContainer.ID)
	secrets, secretNames, _ := a.envAnalyzer.FindSecrets(a.ctx, a.state.SelectedContainer.ID)
	a.state.EnvironmentVars = envVars
	a.state.SecretVars = secretNames

	env.WriteString(fmt.Sprintf("Variables: %d\n", len(envVars)))
	if secretCount, ok := summary["secret_count"].(int); ok {
		env.WriteString(fmt.Sprintf("Potential Secrets: %d\n", secretCount))
	}

	if categories, ok := summary["categories"].(map[string]int); ok && len(categories) > 0 {
		env.WriteString("\nCategories:\n")
		for _, line := range sortedIntMapLines(categories) {
			env.WriteString("  " + line + "\n")
		}
	}

	if len(secrets) > 0 {
		env.WriteString("\nPotential Secrets:\n")
		for _, line := range sortedStringMapLines(secrets, 8) {
			env.WriteString("  " + line + "\n")
		}
	} else {
		env.WriteString("\nPotential Secrets:\n  none detected\n")
	}

	env.WriteString("\nSample Variables:\n")
	for _, line := range sortedStringMapLines(envVars, 12) {
		env.WriteString("  " + line + "\n")
	}

	env.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
	return env.String()
}

func (a *App) handleResourcesKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) handleContainerDiffKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.state.ScrollOffset > 0 {
			a.state.ScrollOffset--
		}
	case "down", "j":
		a.state.ScrollOffset++
	case "r":
		a.state.AnalysisStatus = "Loading container filesystem changes..."
		a.state.AnalysisError = ""
		return a, a.loadContainerDiff()
	case "w":
		return a, a.exportContainerForensicsReport()
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
		a.state.ScrollOffset = 0
	}
	return a, nil
}

func (a *App) handleTimelineKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.state.ScrollOffset > 0 {
			a.state.ScrollOffset--
		}
	case "down", "j":
		a.state.ScrollOffset++
	case "r":
		a.state.AnalysisStatus = "Loading recent Docker events..."
		a.state.AnalysisError = ""
		return a, a.loadTimeline()
	case "w":
		return a, a.exportContainerForensicsReport()
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
		a.state.ScrollOffset = 0
	}
	return a, nil
}

func (a *App) handleThreatHuntKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.state.ScrollOffset > 0 {
			a.state.ScrollOffset--
		}
	case "down", "j":
		a.state.ScrollOffset++
	case "r":
		a.state.AnalysisStatus = "Scanning container for persistence and shell IOCs..."
		a.state.AnalysisError = ""
		return a, a.loadThreatHunt()
	case "w":
		return a, a.exportContainerForensicsReport()
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
		a.state.ScrollOffset = 0
	}
	return a, nil
}

func (a *App) renderResources() string {
	var res strings.Builder
	res.WriteString(titleStyle.Render("📈 Resources") + "\n\n")

	if a.resourceMonitor == nil {
		res.WriteString("Error: Resource monitor not initialized\n")
		return res.String()
	}

	stats, err := a.resourceMonitor.GetStats(a.ctx, a.state.SelectedContainer.ID)
	if err != nil {
		res.WriteString(fmt.Sprintf("Error getting resource stats: %v\n", err))
		res.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
		return res.String()
	}

	a.state.ResourceStats = stats
	res.WriteString(fmt.Sprintf("Resource Status:    %s\n", resourceHealth(stats)))
	res.WriteString(fmt.Sprintf("CPU Load Estimate: %.2f%%\n", stats.CPUPercent))
	res.WriteString(fmt.Sprintf("Memory Used:       %.2f MB\n", stats.MemoryUsageMB))
	res.WriteString(fmt.Sprintf("Memory Limit:      %.2f MB\n", stats.MemoryLimitMB))
	res.WriteString(fmt.Sprintf("Memory Percent:    %.1f%%\n", stats.MemoryPercent))
	res.WriteString(fmt.Sprintf("Process Count:     %d\n", stats.ProcessCount))

	if stats.MemoryLimitMB > 0 {
		res.WriteString("\nMemory Usage:\n")
		res.WriteString(fmt.Sprintf("  %s %.1f%%\n", generateBar(int(stats.MemoryPercent), 20), stats.MemoryPercent))
	}

	res.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
	return res.String()
}

func (a *App) renderContainerDiff() string {
	var out strings.Builder
	out.WriteString(titleStyle.Render("🧬 Container Diff") + "\n\n")

	if a.state.AnalysisStatus != "" {
		out.WriteString("Status: " + a.state.AnalysisStatus + "\n")
	}
	if a.state.AnalysisError != "" {
		out.WriteString("Error:  " + a.state.AnalysisError + "\n\n")
		out.WriteString(helpStyle.Render("r Retry | b Back | q Quit"))
		return out.String()
	}
	if a.state.ExportMessage != "" {
		out.WriteString("Export: " + a.state.ExportMessage + "\n")
	}

	if len(a.state.DiffSummary) > 0 {
		out.WriteString("\nSummary:\n")
		for _, line := range sortedIntMapLines(a.state.DiffSummary) {
			out.WriteString("  " + line + "\n")
		}
	}

	if len(a.state.DiffChanges) == 0 {
		out.WriteString("\nNo container diff changes loaded.\n\n")
		out.WriteString(helpStyle.Render("r Reload | b Back | q Quit"))
		return out.String()
	}

	out.WriteString("\nChanges:\n")
	start := a.state.ScrollOffset
	if start < 0 {
		start = 0
	}
	if start > len(a.state.DiffChanges)-1 && len(a.state.DiffChanges) > 0 {
		start = len(a.state.DiffChanges) - 1
	}

	visibleRows := 10
	if a.height > 16 {
		visibleRows = a.height - 12
	}
	end := start + visibleRows
	if end > len(a.state.DiffChanges) {
		end = len(a.state.DiffChanges)
	}

	for i := start; i < end; i++ {
		change := a.state.DiffChanges[i]
		flag := " "
		if change["suspicious"] == "true" {
			flag = "!"
		}
		out.WriteString(fmt.Sprintf("  [%s] %s %s\n", strings.ToUpper(change["kind"]), flag, change["path"]))
		out.WriteString(fmt.Sprintf("      %s\n", change["detail"]))
	}

	if len(a.state.DiffChanges) > visibleRows {
		out.WriteString(fmt.Sprintf("\n(Showing changes %d-%d of %d)\n", start+1, end, len(a.state.DiffChanges)))
	}

	out.WriteString("\n" + helpStyle.Render("↑/↓ Scroll | r Reload | w Write Report | b Back | q Quit"))
	return out.String()
}

func (a *App) renderTimeline() string {
	var out strings.Builder
	out.WriteString(titleStyle.Render("🕒 Timeline") + "\n\n")

	if a.state.AnalysisStatus != "" {
		out.WriteString("Status: " + a.state.AnalysisStatus + "\n")
	}
	if a.state.AnalysisError != "" {
		out.WriteString("Error:  " + a.state.AnalysisError + "\n\n")
		out.WriteString(helpStyle.Render("r Retry | b Back | q Quit"))
		return out.String()
	}
	if a.state.ExportMessage != "" {
		out.WriteString("Export: " + a.state.ExportMessage + "\n")
	}

	if len(a.state.TimelineSummary) > 0 {
		out.WriteString("\nSummary:\n")
		for _, line := range sortedIntMapLines(a.state.TimelineSummary) {
			out.WriteString("  " + line + "\n")
		}
	}

	if len(a.state.TimelineEvents) == 0 {
		out.WriteString("\nNo timeline events loaded.\n\n")
		out.WriteString(helpStyle.Render("r Reload | w Write Report | b Back | q Quit"))
		return out.String()
	}

	out.WriteString("\nEvents:\n")
	start := a.state.ScrollOffset
	if start < 0 {
		start = 0
	}
	if start > len(a.state.TimelineEvents)-1 && len(a.state.TimelineEvents) > 0 {
		start = len(a.state.TimelineEvents) - 1
	}
	visibleRows := 10
	if a.height > 16 {
		visibleRows = a.height - 12
	}
	end := start + visibleRows
	if end > len(a.state.TimelineEvents) {
		end = len(a.state.TimelineEvents)
	}
	for i := start; i < end; i++ {
		event := a.state.TimelineEvents[i]
		out.WriteString(fmt.Sprintf("  %s  %s\n", event["time"], event["action"]))
		out.WriteString(fmt.Sprintf("      %s\n", event["actor"]))
		if event["details"] != "" {
			out.WriteString(fmt.Sprintf("      %s\n", event["details"]))
		}
	}
	if len(a.state.TimelineEvents) > visibleRows {
		out.WriteString(fmt.Sprintf("\n(Showing events %d-%d of %d)\n", start+1, end, len(a.state.TimelineEvents)))
	}
	out.WriteString("\n" + helpStyle.Render("↑/↓ Scroll | r Reload | w Write Report | b Back | q Quit"))
	return out.String()
}

func (a *App) renderThreatHunt() string {
	var out strings.Builder
	out.WriteString(titleStyle.Render("🎯 Threat Hunt") + "\n\n")

	if a.state.AnalysisStatus != "" {
		out.WriteString("Status: " + a.state.AnalysisStatus + "\n")
	}
	if a.state.AnalysisError != "" {
		out.WriteString("Error:  " + a.state.AnalysisError + "\n\n")
		out.WriteString(helpStyle.Render("r Retry | b Back | q Quit"))
		return out.String()
	}
	if a.state.ExportMessage != "" {
		out.WriteString("Export: " + a.state.ExportMessage + "\n")
	}

	if len(a.state.ThreatSummary) > 0 {
		out.WriteString("\nSummary:\n")
		for _, line := range sortedIntMapLines(a.state.ThreatSummary) {
			out.WriteString("  " + line + "\n")
		}
	}

	if len(a.state.ThreatFindings) == 0 {
		out.WriteString("\nNo threat-hunt findings loaded.\n\n")
		out.WriteString(helpStyle.Render("r Rescan | w Write Report | b Back | q Quit"))
		return out.String()
	}

	out.WriteString("\nFindings:\n")
	start := a.state.ScrollOffset
	if start < 0 {
		start = 0
	}
	if start > len(a.state.ThreatFindings)-1 && len(a.state.ThreatFindings) > 0 {
		start = len(a.state.ThreatFindings) - 1
	}

	visibleRows := 8
	if a.height > 14 {
		visibleRows = a.height - 12
	}
	end := start + visibleRows
	if end > len(a.state.ThreatFindings) {
		end = len(a.state.ThreatFindings)
	}

	for i := start; i < end; i++ {
		finding := a.state.ThreatFindings[i]
		out.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(finding["severity"]), finding["category"]))
		out.WriteString(fmt.Sprintf("      %s\n", finding["path"]))
		out.WriteString(fmt.Sprintf("      %s\n", finding["detail"]))
	}

	if len(a.state.ThreatFindings) > visibleRows {
		out.WriteString(fmt.Sprintf("\n(Showing findings %d-%d of %d)\n", start+1, end, len(a.state.ThreatFindings)))
	}

	out.WriteString("\n" + helpStyle.Render("↑/↓ Scroll | r Rescan | w Write Report | b Back | q Quit"))
	return out.String()
}

func (a *App) renderOptimization() string {
	var output strings.Builder
	output.WriteString(titleStyle.Render("⚡ Optimization Suggestions") + "\n\n")

	if a.state.ImageLayers == nil {
		if a.state.AnalysisStatus != "" {
			output.WriteString(a.state.AnalysisStatus + "\n")
		} else {
			output.WriteString("Load layer analysis first from image details.\n")
		}
		if a.state.AnalysisError != "" {
			output.WriteString("\nTar Analysis Error: " + a.state.AnalysisError + "\n")
		}
		output.WriteString("\n" + helpStyle.Render("Open an image and press l before viewing optimization advice."))
		output.WriteString("\n\n" + helpStyle.Render("b Back | q Quit"))
		return output.String()
	}

	report := a.bloatDetector.BuildOptimizationReport(a.state.ImageLayers, a.state.BloatDetection)
	a.state.OptimizationReport = report

	output.WriteString(fmt.Sprintf("Layers:             %d\n", report.LayerCount))
	output.WriteString(fmt.Sprintf("Bloat Findings:     %d\n", report.BloatItemCount))
	output.WriteString(fmt.Sprintf("Estimated Savings:  %s\n", layers.SizeFormatter(report.EstimatedSavings)))
	output.WriteString(fmt.Sprintf("Largest Layer Share: %.1f%%\n", largestLayerPercent(a.state.ImageLayers)))
	if a.state.AnalysisStatus != "" {
		output.WriteString(fmt.Sprintf("Analysis Status:    %s\n", a.state.AnalysisStatus))
	}
	if a.state.AnalysisError != "" {
		output.WriteString(fmt.Sprintf("Tar Analysis Error: %s\n", a.state.AnalysisError))
	}
	if a.state.ExportMessage != "" {
		output.WriteString(fmt.Sprintf("Export:             %s\n", a.state.ExportMessage))
	}

	output.WriteString("\nRecommendations:\n")
	if len(report.Recommendations) == 0 {
		output.WriteString("  No obvious optimizations detected from current heuristics.\n")
	} else {
		for i, rec := range report.Recommendations {
			output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
	}

	layerLines := optimizationLayerFindingLines(a.state.ImageLayers, a.state.BloatDetection)
	if len(layerLines) > 0 {
		output.WriteString("\nLayers With Findings:\n")
		for _, line := range layerLines {
			output.WriteString("  " + line + "\n")
		}
	}

	output.WriteString("\n" + helpStyle.Render("w Write Report | b Back | q Quit"))
	return output.String()
}

func (a *App) renderScaffold() string {
	var output strings.Builder
	output.WriteString(titleStyle.Render("🧱 SDE Scaffold") + "\n\n")

	if a.docker == nil {
		output.WriteString("Error inspecting image: Docker client not initialized\n")
		output.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
		return output.String()
	}

	inspect, err := a.docker.InspectImage(a.ctx, a.state.SelectedImage.ID)
	if err != nil {
		output.WriteString(fmt.Sprintf("Error inspecting image: %v\n", err))
		output.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
		return output.String()
	}

	imageName := safeSlice(a.state.SelectedImage.ID, 12)
	if len(a.state.SelectedImage.RepoTags) > 0 {
		imageName = a.state.SelectedImage.RepoTags[0]
	}

	scaffold := a.scaffoldGenerator.GenerateWithAnalysis(imageName, inspect, a.state.FileAnalysis)
	a.state.Scaffold = scaffold

	output.WriteString(fmt.Sprintf("Base Image:   %s\n", scaffold.Profile.BaseImage))
	output.WriteString(fmt.Sprintf("Runtime:      %s\n", scaffold.Profile.Runtime))
	output.WriteString(fmt.Sprintf("Workdir:      %s\n", scaffold.Profile.Workdir))
	if len(scaffold.Profile.ExposedPorts) > 0 {
		output.WriteString(fmt.Sprintf("Exposed:      %s\n", strings.Join(scaffold.Profile.ExposedPorts, ", ")))
	}
	if len(scaffold.Profile.DetectedLanguages) > 0 {
		output.WriteString(fmt.Sprintf("Languages:    %s\n", strings.Join(scaffold.Profile.DetectedLanguages, ", ")))
	}
	if len(scaffold.Profile.PackageManagers) > 0 {
		output.WriteString(fmt.Sprintf("Pkg Managers: %s\n", strings.Join(scaffold.Profile.PackageManagers, ", ")))
	}
	if a.state.AnalysisStatus != "" {
		output.WriteString(fmt.Sprintf("Analysis:     %s\n", a.state.AnalysisStatus))
	}
	if a.state.AnalysisError != "" {
		output.WriteString(fmt.Sprintf("Tar Error:    %s\n", a.state.AnalysisError))
	}
	if a.state.ExportMessage != "" {
		output.WriteString(fmt.Sprintf("Export:       %s\n", a.state.ExportMessage))
	}

	output.WriteString("\nPolicy Checklist:\n")
	for _, item := range scaffold.PolicyChecklist {
		output.WriteString(fmt.Sprintf("  - %s\n", item))
	}

	if len(scaffold.SecurityArtifacts) > 0 {
		output.WriteString("\nGenerated Policy Templates:\n")
		for _, artifact := range scaffold.SecurityArtifacts {
			output.WriteString(fmt.Sprintf("\n[%s]\n", artifact.Name))
			output.WriteString("─────────────────────────────────────────────────────\n")
			output.WriteString(artifact.Content)
			output.WriteString("\n")
		}
	}

	analysisLines := scaffoldAnalysisFindingLines(a.state.FileAnalysis)
	if len(analysisLines) > 0 {
		output.WriteString("\nTar Analysis Highlights:\n")
		for _, line := range analysisLines {
			output.WriteString("  - " + line + "\n")
		}
	}

	output.WriteString("\nGenerated Dockerfile:\n")
	output.WriteString("─────────────────────────────────────────────────────\n")
	output.WriteString(scaffold.Dockerfile)
	output.WriteString("\n\n" + helpStyle.Render("w Write Files | b Back | q Quit"))
	return output.String()
}

func (a *App) exportScaffold() tea.Cmd {
	return func() tea.Msg {
		scaffold := a.state.Scaffold
		if scaffold.Dockerfile == "" {
			return scaffoldExportedMsg{message: "nothing to export yet"}
		}

		imageName := safeSlice(a.state.SelectedImage.ID, 12)
		if len(a.state.SelectedImage.RepoTags) > 0 {
			imageName = a.state.SelectedImage.RepoTags[0]
		}
		dirName := sanitizeFilename(imageName)
		exportDir := filepath.Join(".bonestack", "scaffolds", dirName)
		if err := os.MkdirAll(exportDir, 0755); err != nil {
			return scaffoldExportedMsg{message: "export failed: " + err.Error()}
		}

		files := map[string]string{
			"Dockerfile.generated": scaffold.Dockerfile,
		}
		for _, artifact := range scaffold.SecurityArtifacts {
			files[artifact.Name] = artifact.Content
		}

		for relPath, content := range files {
			fullPath := filepath.Join(exportDir, relPath)
			if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
				return scaffoldExportedMsg{message: "export failed: " + err.Error()}
			}
			if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
				return scaffoldExportedMsg{message: "export failed: " + err.Error()}
			}
		}

		return scaffoldExportedMsg{message: "wrote scaffold files to " + exportDir, path: exportDir}
	}
}

func (a *App) exportOptimizationReport() tea.Cmd {
	return func() tea.Msg {
		if a.state.ImageLayers == nil {
			return optimizationExportedMsg{message: "load image analysis before exporting"}
		}

		imageName := safeSlice(a.state.SelectedImage.ID, 12)
		if len(a.state.SelectedImage.RepoTags) > 0 {
			imageName = a.state.SelectedImage.RepoTags[0]
		}

		exportDir, err := report.ExportOptimizationReport(".", imageName, a.state.OptimizationReport, a.state.ImageLayers, a.state.BloatDetection, a.state.FileAnalysis)
		if err != nil {
			return optimizationExportedMsg{message: "report export failed: " + err.Error()}
		}

		return optimizationExportedMsg{
			message: "wrote JSON/CSV/HTML reports to " + exportDir,
			path:    exportDir,
		}
	}
}

func (a *App) exportContainerForensicsReport() tea.Cmd {
	return func() tea.Msg {
		containerName := safeSlice(a.state.SelectedContainer.ID, 12)
		if len(a.state.SelectedContainer.Names) > 0 {
			containerName = strings.TrimPrefix(a.state.SelectedContainer.Names[0], "/")
		}

		exportDir, err := report.ExportContainerForensicsReport(".", containerName, a.state.ThreatFindings, a.state.ThreatSummary, a.state.DiffChanges, a.state.DiffSummary, a.state.TimelineEvents, a.state.TimelineSummary)
		if err != nil {
			return optimizationExportedMsg{message: "report export failed: " + err.Error()}
		}

		return optimizationExportedMsg{
			message: "wrote container forensics reports to " + exportDir,
			path:    exportDir,
		}
	}
}

func resourceHealth(stats *forensics.ResourceStats) string {
	if stats == nil {
		return "unknown"
	}
	switch {
	case stats.MemoryPercent >= 90 || stats.CPUPercent >= 90:
		return "critical"
	case stats.MemoryPercent >= 75 || stats.CPUPercent >= 75:
		return "elevated"
	default:
		return "normal"
	}
}

func largestLayerPercent(imageLayers *layers.ImageLayers) float64 {
	if imageLayers == nil || len(imageLayers.Layers) == 0 {
		return 0
	}

	var total int64
	var largest int64
	for _, layer := range imageLayers.Layers {
		total += layer.Size
		if layer.Size > largest {
			largest = layer.Size
		}
	}

	return layers.PercentageOfTotal(largest, total)
}

func optimizationLayerFindingLines(imageLayers *layers.ImageLayers, bloat map[int][]layers.BloatItem) []string {
	if imageLayers == nil {
		return nil
	}

	lines := []string{}
	for i, items := range bloat {
		if len(items) == 0 || i >= len(imageLayers.Layers) {
			continue
		}
		layer := imageLayers.Layers[i]
		lines = append(lines, fmt.Sprintf("Layer %d: %d findings, %s, %s", i, len(items), layers.SizeFormatter(layer.Size), safeSlice(layer.Command, minInt(60, len(layer.Command)))))
	}
	sort.Strings(lines)
	if len(lines) > 6 {
		lines = lines[:6]
	}
	return lines
}

func scaffoldAnalysisFindingLines(analyses []layers.FileAnalysisResult) []string {
	lines := []string{}
	for _, analysis := range analyses {
		for _, finding := range analysis.PotentialBloat {
			lines = append(lines, fmt.Sprintf("%s (%s, %s)", finding.Path, finding.Type, finding.Severity))
			if len(lines) >= 6 {
				return lines
			}
		}
	}
	return lines
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", "@", "_", " ", "_")
	return replacer.Replace(name)
}

func sortedIntMapLines(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%-12s %d", key+":", values[key]))
	}
	return lines
}

func sortedStringMapLines(values map[string]string, limit int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", key, values[key]))
	}
	return lines
}
