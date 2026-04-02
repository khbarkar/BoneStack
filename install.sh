#!/bin/bash
# BoneStack Installation Script
# Install BoneStack to /usr/local/bin for system-wide access

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="bonestack"
FULL_PATH="$INSTALL_DIR/$BINARY_NAME"

# Helper functions
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       BoneStack Installation          ║${NC}"
    echo -e "${BLUE}║  Container Operations Inspector       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if Go is installed
check_go() {
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed"
        echo "Please install Go from https://golang.org/dl/"
        exit 1
    fi
    print_success "Go is installed: $(go version)"
}

# Check if script is in BoneStack directory
check_directory() {
    if [ ! -f "go.mod" ] || [ ! -f "cmd/bonestack/main.go" ]; then
        print_error "Not in BoneStack directory"
        echo "Please run this script from the BoneStack repository root"
        exit 1
    fi
    print_success "Found BoneStack repository"
}

# Build the binary
build_binary() {
    print_info "Building BoneStack..."
    if go build -v -o bonestack ./cmd/bonestack/main.go; then
        print_success "Build completed successfully"
    else
        print_error "Build failed"
        exit 1
    fi
}

# Check install permissions
check_permissions() {
    if [ ! -w "$INSTALL_DIR" ]; then
        print_error "No write permissions to $INSTALL_DIR"
        print_info "You may need to use 'sudo' or have the directory writable"
        exit 1
    fi
    print_success "Write permissions verified for $INSTALL_DIR"
}

# Install the binary
install_binary() {
    print_info "Installing to $FULL_PATH..."
    
    # Backup existing binary if it exists
    if [ -f "$FULL_PATH" ]; then
        BACKUP_PATH="$FULL_PATH.backup.$(date +%s)"
        print_info "Backing up existing binary to $BACKUP_PATH"
        cp "$FULL_PATH" "$BACKUP_PATH"
    fi
    
    # Copy new binary
    cp bonestack "$FULL_PATH"
    chmod +x "$FULL_PATH"
    
    print_success "Installed to $FULL_PATH"
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    if [ ! -f "$FULL_PATH" ]; then
        print_error "Binary not found after installation"
        exit 1
    fi
    
    if [ ! -x "$FULL_PATH" ]; then
        print_error "Binary is not executable"
        exit 1
    fi
    
    print_success "Installation verified"
}

# Show usage
show_usage() {
    echo ""
    echo "Installation Summary:"
    echo "  Binary:    $FULL_PATH"
    echo "  Size:      $(ls -lh $FULL_PATH | awk '{print $5}')"
    echo "  Version:   v0.2.0 (Layer Analysis Engine)"
    echo ""
    echo "You can now run BoneStack from anywhere:"
    echo ""
    print_info "bonestack"
    echo ""
    echo "BoneStack is ready to use!"
}

# Main installation flow
main() {
    print_header
    
    # Run checks and installation
    check_go
    check_directory
    check_permissions
    build_binary
    install_binary
    verify_installation
    show_usage
    
    print_success "Installation complete!"
}

# Run main function
main
