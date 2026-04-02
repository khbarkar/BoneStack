<p align="center">
  <img src="img/logo.png" alt="VIC logo" width="717">
</p>

[![Go](https://github.com/khbarkar/BoneStack/actions/workflows/go.yml/badge.svg)](https://github.com/khbarkar/BoneStack/actions/workflows/go.yml) 

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

## Features (Phases 1-5)

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
- **Layer Analysis** - Inspect image layers, size breakdowns, and bloat indicators
  - Layer-by-layer image history
  - Size breakdown view
  - Layer detail and basic file/bloat analysis
- **Container Forensics** - Inspect live container runtime data
  - Root filesystem listing
  - Process listing
  - Volume mount inspection
  - Container log viewer
- **Environment & Resource Views** - Dedicated forensics screens for runtime insight
  - Environment summaries with secret redaction
  - Resource health, memory usage, and process counts
- **Optimization Suggestions** - Image-level heuristics for size and build-efficiency improvements
  - Estimated removable bloat
  - Multi-layer cache/install recommendations
  - Base image and layer-count suggestions
- **SDE Scaffold Generation** - Generate a starter Dockerfile and policy checklist from image metadata
  - Runtime profile inference
  - Best-practice Dockerfile templates
  - Basic security and build-policy guidance

## Installation

### Prerequisites
- Go 1.21+
- Docker daemon running
- Unix-like system (macOS, Linux)

### Build from Source
```bash
cd sosmity
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

## Roadmap

### Phase 2: Layer Analysis
- [x] View image layers individually
- [x] Layer size breakdown
- [x] Diff analysis between consecutive layers
- [x] Dockerfile instruction reconstruction

### Phase 3: Forensics Engine
- [x] Container filesystem inspection
- [x] Process introspection
- [x] Volume analysis
- [x] Log inspection
- [x] Dedicated environment screen
- [x] Dedicated resource screen

### Phase 4: Optimization & Suggestions
- [x] Bloat detection algorithms
- [x] Multi-stage build recommendations
- [x] Base image optimization suggestions
- [x] Cache efficiency analysis

### Phase 5: SDE Construction
- [x] Template-based Dockerfile generation
- [x] Best-practice scaffolding
- [x] Security policy templates
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
│   ├── forensics/           # Runtime container inspection
│   ├── layers/              # Layer analysis and bloat detection
│   ├── sde/                 # Dockerfile and scaffold generation
│   ├── ui/
│   │   └── app.go           # Bubble Tea TUI application
│   └── models/
│       └── state.go         # Application state models
├── img/
│   └── logo.png
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
✅ **Phase 2 Complete**: Layer analysis and advanced image inspection  
✅ **Phase 3 Complete**: Forensics screens now cover filesystem, processes, volumes, logs, environment, and resources  
✅ **Phase 4 Initial Implementation**: Optimization suggestions are available from analyzed images  
🚧 **Phase 5 In Progress**: SDE scaffold generation is available; dependency-optimization output still needs deeper project analysis  
⏱️ **Phase 6 Planned**: Advanced features and polish

## Next Step

The immediate next milestone is to deepen Phase 5 and begin Phase 6:

- Improve generated Dockerfiles using tar-analysis/project-language signals
- Add dependency-optimization guidance directly into scaffold output
- Start report export and image-comparison workflows

## License

TBD
