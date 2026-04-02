package ui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kristinb/bonestack/internal/docker"
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
	docker        *docker.Client
	state         *models.AppState
	width         int
	height        int
	selectedIndex int
	ctx           context.Context
}

func NewApp(ctx context.Context, dockerClient *docker.Client) *App {
	return &App{
		docker:        dockerClient,
		ctx:           ctx,
		selectedIndex: 0,
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
	case "esc", "b":
		a.state.CurrentScreen = "images"
		a.selectedIndex = 0
	}
	return a, nil
}

func (a *App) handleContainerDetailKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
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
				name = img.ID[:12]
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

	var detail strings.Builder
	detail.WriteString(titleStyle.Render("🖼️  Image Details") + "\n\n")

	if len(a.state.SelectedImage.RepoTags) > 0 {
		detail.WriteString(fmt.Sprintf("Name:      %s\n", a.state.SelectedImage.RepoTags[0]))
	}
	detail.WriteString(fmt.Sprintf("ID:        %s\n", a.state.SelectedImage.ID[:12]))
	detail.WriteString(fmt.Sprintf("Size:      %.2f MB\n", float64(a.state.SelectedImage.Size)/1024/1024))
	detail.WriteString(fmt.Sprintf("Created:   %d\n", a.state.SelectedImage.Created))
	detail.WriteString(fmt.Sprintf("OS:        %s\n", inspect.Os))
	detail.WriteString(fmt.Sprintf("Arch:      %s\n", inspect.Architecture))
	
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

	detail.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
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
	detail.WriteString(fmt.Sprintf("ID:       %s\n", a.state.SelectedContainer.ID[:12]))
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

	detail.WriteString("\n" + helpStyle.Render("b Back | q Quit"))
	return detail.String()
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
