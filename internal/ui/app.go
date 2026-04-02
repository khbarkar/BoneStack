package ui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kristinb/bonestack/internal/docker"
	"github.com/kristinb/bonestack/internal/forensics"
	"github.com/kristinb/bonestack/internal/layers"
	"github.com/kristinb/bonestack/internal/models"
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
	docker              *docker.Client
	layerAnalyzer       *layers.Analyzer
	bloatDetector       *layers.BloatDetector
	diffEngine          *layers.DiffEngine
	containerInspector  *forensics.ContainerInspector
	fsInspector         *forensics.FileSystemInspector
	processAnalyzer     *forensics.ProcessAnalyzer
	volumeAnalyzer      *forensics.VolumeAnalyzer
	logAnalyzer         *forensics.LogAnalyzer
	envAnalyzer         *forensics.EnvironmentAnalyzer
	resourceMonitor     *forensics.ResourceMonitor
	state               *models.AppState
	width               int
	height              int
	selectedIndex        int
	ctx                 context.Context
}

func NewApp(ctx context.Context, dockerClient *docker.Client) *App {
	containerInspector := forensics.NewContainerInspector(dockerClient.Raw())
	return &App{
		docker:             dockerClient,
		layerAnalyzer:      layers.NewAnalyzer(dockerClient),
		bloatDetector:      layers.NewBloatDetector(),
		diffEngine:         layers.NewDiffEngine(),
		containerInspector: containerInspector,
		fsInspector:        forensics.NewFileSystemInspector(containerInspector),
		processAnalyzer:    forensics.NewProcessAnalyzer(containerInspector),
		volumeAnalyzer:     forensics.NewVolumeAnalyzer(containerInspector),
		logAnalyzer:        forensics.NewLogAnalyzer(containerInspector),
		envAnalyzer:        forensics.NewEnvironmentAnalyzer(containerInspector),
		resourceMonitor:    forensics.NewResourceMonitor(containerInspector),
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
		a.state.CurrentScreen = "layers"
		a.state.SelectedLayerIndex = 0
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
		// Load and analyze layers
		return a, a.loadLayers()
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
			menu.WriteString(selectedStyle.Render("→ " + item) + "\n")
		} else {
			menu.WriteString(normalStyle.Render("  " + item) + "\n")
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
				list.WriteString(selectedStyle.Render("→ " + line) + "\n")
			} else {
				list.WriteString(normalStyle.Render("  " + line) + "\n")
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
				list.WriteString(selectedStyle.Render("→ " + line) + "\n")
			} else {
				list.WriteString(normalStyle.Render("  " + line) + "\n")
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

	detail.WriteString("\n" + helpStyle.Render("l Layers | b Back | q Quit"))
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
			output.WriteString(selectedStyle.Render("→ " + line) + "\n")
		} else {
			output.WriteString(normalStyle.Render("  " + line) + "\n")
		}
	}

	output.WriteString("\n" + helpStyle.Render("↑/↓ Navigate | Enter Details | s Size Breakdown | b Back | q Quit"))
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
		index    int
		size     int64
		cumSize  int64
		pct      float64
		command  string
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

func (a *App) loadLayers() tea.Cmd {
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

		return layersLoadedMsg{
			layers:          imageLayers,
			analyses:        analyses,
			bloat:           bloatMap,
			recommendations: recommendations,
		}
	}
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

type imagesLoadedMsg []docker.ImageSummary
type containersLoadedMsg []docker.ContainerSummary

type layersLoadedMsg struct {
	layers          *layers.ImageLayers
	analyses        []layers.LayerAnalysis
	bloat           map[int][]layers.BloatItem
	recommendations []string
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
	menuItems := []string{"Filesystem", "Processes", "Volumes", "Logs", "Environment", "Resources"}

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
			// TODO: Add environment screen
		case "Resources":
			// TODO: Add resources screen
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
	}

	var menu strings.Builder
	menu.WriteString(title + "\n\n")

	for i, item := range menuItems {
		if i == a.selectedIndex {
			menu.WriteString(selectedStyle.Render("→ " + item) + "\n")
		} else {
			menu.WriteString(normalStyle.Render("  " + item) + "\n")
		}
	}

	menu.WriteString("\n" + helpStyle.Render("↑/↓ Navigate | Enter Select | b Back | q Quit"))
	return menu.String()
}

func (a *App) handleFilesystemKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		a.state.CurrentScreen = "forensics-menu"
		a.selectedIndex = 0
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
		fs.WriteString("Root Directory Contents:\n\n")
		for i, file := range files {
			if i >= 20 {
				fs.WriteString(fmt.Sprintf("... and %d more files\n", len(files)-i))
				break
			}
			kind := "file"
			if file.IsDir {
				kind = "dir"
			}
			fs.WriteString(fmt.Sprintf("  %-4s %s\n", kind, file.Path))
		}
	}

	fs.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
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
