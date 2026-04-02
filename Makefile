# BoneStack - Container Operations Inspector Makefile
# Build, install, and run commands for BoneStack

.PHONY: help build install uninstall run clean test

# Default target
help:
	@echo "BoneStack - Container Operations Inspector"
	@echo ""
	@echo "Available commands:"
	@echo "  make build       Build the bonestack binary"
	@echo "  make install     Build and install to /usr/local/bin"
	@echo "  make uninstall   Remove bonestack from /usr/local/bin"
	@echo "  make run         Build and run bonestack"
	@echo "  make clean       Remove build artifacts"
	@echo "  make test        Run test suite"
	@echo "  make help        Show this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make build       # Compile binary to ./bonestack"
	@echo "  make install     # Install to /usr/local/bin/bonestack"
	@echo "  bonestack        # Run if installed"
	@echo "./bonestack          # Run from current directory"

# Build the binary
build:
	@echo "Building BoneStack..."
	@go build -v -o bonestack ./cmd/bonestack/main.go
	@echo "✓ Build complete: ./bonestack"

# Install to /usr/local/bin
install: build
	@echo "Installing BoneStack to /usr/local/bin..."
	@mkdir -p /usr/local/bin
	@cp bonestack /usr/local/bin/bonestack
	@chmod +x /usr/local/bin/bonestack
	@echo "✓ Installation complete"
	@echo "You can now run: bonestack"

# Uninstall from /usr/local/bin
uninstall:
	@echo "Uninstalling BoneStack..."
	@rm -f /usr/local/bin/bonestack
	@echo "✓ Uninstallation complete"

# Run the binary
run: build
	@echo "Running BoneStack..."
	@./bonestack

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f bonestack
	@rm -f main
	@go clean
	@echo "✓ Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...
	@echo "✓ Tests complete"

# Development build with race detection
dev:
	@echo "Building with race detection..."
	@go build -race -v -o bonestack ./cmd/bonestack/main.go
	@echo "✓ Development build complete"

# Show version info
version:
	@echo "BoneStack v0.2.0 - Layer Analysis Engine"
	@echo "Go version: $$(go version)"
	@echo "Platform: $$(go env GOOS)/$$(go env GOARCH)"
