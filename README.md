<p align="center">
  <img src="img/logo.png" alt="VIC logo" width="717">
</p>

  <p align="center">
    <a href="https://github.com/khbarkar/VIC/tags">
      <img src="https://img.shields.io/github/v/tag/khbarkar/VIC?label=tag" alt="Latest Tag">
    </a>
    <a href="https://github.com/khbarkar/VIC/blob/main/LICENSE">
      <img src="https://img.shields.io/github/license/khbarkar/VIC" alt="License">
    </a>
    <a href="https://go.dev/">
      <img src="https://img.shields.io/badge/go-1.25.7-00ADD8?logo=go" alt="Go Version">
    </a>
  </p>

# 🔮 BoneStack - Container Operations Inspector

A tool for advanced Docker image and container diagnostics, forensics, and optimization.

## Features (Phase 1 - Complete ✅)

### Current Capabilities
- **Interactive Menu System** - Navigate with arrow keys, inspired by Smitty/AIX
- **Image Listing** - Browse all Docker images with metadata (name, tag, size, created date)
- **Container Listing** - View all containers (running and stopped) with status
- **Image Inspection** - View detailed image metadata:
  - Image ID, size, creation time
  - OS and architecture
  - Exposed ports and volumes
- **Container Inspection** - View detailed container metadata:
  - Container ID and image
  - Current status and state
  - Port mappings
  - Volume mounts

## Installation

### Prerequisites
- Go 1.21+
- Docker daemon running
- Unix-like system (macOS, Linux)

### Build from Source
```bash
cd bonestack
go build -o bonestack ./cmd/bonestack/main.go
./bonestack
```

## Usage

```bash
./bonestack
```

### Navigation
- `↑/↓` or `j/k` - Navigate menu items
- `Enter` - Select/inspect item
- `b` - Go back to previous menu
- `q` or `Ctrl+C` - Quit

### Screens
1. **Main Menu** - Choose what to inspect
2. **Images** - List all Docker images
3. **Containers** - List all Docker containers
4. **Image Details** - Detailed view of selected image
5. **Container Details** - Detailed view of selected container

## Planned Features (Phase 2-6)

### Phase 2: Layer Analysis
- [ ] View image layers individually
- [ ] Layer size breakdown
- [ ] Diff analysis between consecutive layers
- [ ] Dockerfile instruction reconstruction

### Phase 3: Forensics Engine
- [ ] Container filesystem inspection
- [ ] Process introspection (PIDs, environment variables)
- [ ] Volume and network analysis
- [ ] Log streaming and filtering

### Phase 4: Optimization & Suggestions
- [ ] Bloat detection algorithms
- [ ] Multi-stage build recommendations
- [ ] Base image optimization suggestions
- [ ] Cache efficiency analysis

### Phase 5: SDE Construction
- [ ] Template-based Dockerfile generation
- [ ] Best-practice scaffolding
- [ ] Security policy templates
- [ ] Automated dependency optimization

### Phase 6: Advanced Features
- [ ] Image comparison tools
- [ ] Batch processing
- [ ] Report generation (JSON, HTML, CSV)
- [ ] Custom policy rules
- [ ] Performance profiling

## Architecture

```
bonestack/
├── cmd/bonestack/
│   └── main.go              # Entry point
├── internal/
│   ├── docker/
│   │   └── client.go        # Docker API wrapper
│   ├── ui/
│   │   └── app.go           # Bubble Tea TUI application
│   └── models/
│       └── state.go         # Application state models
└── README.md
```

## Technology Stack

- **Language**: Go 1.21+
- **TUI Framework**: Bubble Tea (Charmbracelet)
- **Container API**: Docker SDK (moby)
- **Styling**: Lipgloss (Charmbracelet)

## Project Goals

Build an interactive, menu-driven container diagnostics tool that goes beyond simple inspection:

1. **Comprehensive Layer Forensics** - Deep-dive into image layer composition and changes
2. **Advanced Optimization Engine** - Intelligent suggestions for image size reduction and build efficiency
3. **Container Forensics** - Live inspection of container filesystems, processes, and networks
4. **SDE Construction** - Automated generation of optimized Dockerfiles from templates
5. **Interactive First** - Smitty-style menu navigation instead of command-line arguments

## Development Status

✅ **Phase 1 Complete**: Foundation with TUI and basic inspection  
🚧 **Phase 2 In Progress**: Layer analysis and advanced image inspection  
⏱️ **Phase 3 Planned**: Container forensics engine  
⏱️ **Phase 4 Planned**: Optimization suggestions  
⏱️ **Phase 5 Planned**: SDE construction  
⏱️ **Phase 6 Planned**: Advanced features and polish  

## License

TBD
