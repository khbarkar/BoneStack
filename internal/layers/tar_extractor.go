package layers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
)

// FileEntry represents a single file extracted from a tar archive
type FileEntry struct {
	Name    string // Full path within layer
	Size    int64  // File size in bytes
	Mode    int64  // File mode/permissions
	IsDir   bool   // Is directory
	IsLink  bool   // Is symlink
	Type    string // File type (file, dir, link, etc)
}

// LayerTarData contains extracted metadata from a single layer tar
type LayerTarData struct {
	LayerID    string
	Files      []FileEntry
	TotalSize  int64
	FileCount  int
	DirCount   int
	LinkCount  int
	SizeByType map[string]int64 // Size breakdown by file type
}

// TarExtractor manages extraction and parsing of Docker layer tars
type TarExtractor struct {
	client *client.Client
}

type imageSaveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// NewTarExtractor creates a new tar extractor
func NewTarExtractor(dockerClient *client.Client) *TarExtractor {
	return &TarExtractor{
		client: dockerClient,
	}
}

// ExtractLayerTar extracts and parses a single layer tar from Docker
func (te *TarExtractor) ExtractLayerTar(ctx context.Context, imageID, layerID string) (*LayerTarData, error) {
	// Note: Full Docker layer extraction requires accessing the OCI image config
	// which contains layer digests. This foundation supports both direct tar files
	// and future integration with Docker's image export functionality.
	// For now, this returns a placeholder - actual use will be with ExtractLayerTarFromFile

	return &LayerTarData{
		LayerID:    layerID,
		Files:      []FileEntry{},
		TotalSize:  0,
		FileCount:  0,
		DirCount:   0,
		LinkCount:  0,
		SizeByType: make(map[string]int64),
	}, nil
}

// ExtractImageLayers exports a Docker image tarball and extracts layer tar data in order.
func (te *TarExtractor) ExtractImageLayers(ctx context.Context, imageID string) ([]LayerTarData, error) {
	if te.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	reader, err := te.client.ImageSave(ctx, []string{imageID})
	if err != nil {
		return nil, fmt.Errorf("failed to save image: %w", err)
	}
	defer reader.Close()

	tmpFile, err := os.CreateTemp("", "bonestack-image-*.tar")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp image tar: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, reader); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write image tar: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize image tar: %w", err)
	}

	return te.ExtractImageLayersFromFile(tmpPath)
}

// ExtractImageLayersFromFile parses a docker image archive and extracts all embedded layer tars.
func (te *TarExtractor) ExtractImageLayersFromFile(imageTarPath string) ([]LayerTarData, error) {
	file, err := os.Open(imageTarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open image tar: %w", err)
	}
	defer file.Close()

	return te.extractImageLayersFromReader(file)
}

// ExtractLayerTarFromFile extracts and parses a tar file from disk
func (te *TarExtractor) ExtractLayerTarFromFile(tarPath string) (*LayerTarData, error) {
	file, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	defer file.Close()

	data := &LayerTarData{
		Files:      []FileEntry{},
		TotalSize:  0,
		FileCount:  0,
		DirCount:   0,
		LinkCount:  0,
		SizeByType: make(map[string]int64),
	}

	// Try to decompress with gzip
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		// Not gzip, reset and use raw tar
		file.Seek(0, 0)
		return te.parseTarStream(file, data)
	}
	defer gzipReader.Close()

	return te.parseTarStream(gzipReader, data)
}

func (te *TarExtractor) extractImageLayersFromReader(reader io.Reader) ([]LayerTarData, error) {
	tr := tar.NewReader(reader)
	layerContents := make(map[string][]byte)
	var manifest []imageSaveManifest

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading image tar: %w", err)
		}

		switch {
		case header.Name == "manifest.json":
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("failed to read manifest.json: %w", err)
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return nil, fmt.Errorf("failed to parse manifest.json: %w", err)
			}
		case strings.HasSuffix(header.Name, "/layer.tar"):
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("failed to read layer tar %s: %w", header.Name, err)
			}
			layerContents[header.Name] = data
		}
	}

	if len(manifest) == 0 {
		return nil, fmt.Errorf("manifest.json not found in image tar")
	}

	var layersData []LayerTarData
	for _, layerPath := range manifest[0].Layers {
		content, ok := layerContents[layerPath]
		if !ok {
			continue
		}
		data := &LayerTarData{
			LayerID:    filepath.Base(filepath.Dir(layerPath)),
			Files:      []FileEntry{},
			TotalSize:  0,
			FileCount:  0,
			DirCount:   0,
			LinkCount:  0,
			SizeByType: make(map[string]int64),
		}

		parsed, err := te.parseTarStream(bytes.NewReader(content), data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse layer %s: %w", layerPath, err)
		}
		if parsed.LayerID == "" {
			parsed.LayerID = layerPath
		}
		layersData = append(layersData, *parsed)
	}

	return layersData, nil
}

// parseTarStream reads and parses a tar stream
func (te *TarExtractor) parseTarStream(reader io.Reader, data *LayerTarData) (*LayerTarData, error) {
	tr := tar.NewReader(reader)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar: %w", err)
		}

		// Determine file type
		fileType := determineFileType(header)

		// Create file entry
		entry := FileEntry{
			Name:   cleanPath(header.Name),
			Size:   header.Size,
			Mode:   header.Mode,
			IsDir:  header.Typeflag == tar.TypeDir,
			IsLink: header.Typeflag == tar.TypeLink || header.Typeflag == tar.TypeSymlink,
			Type:   fileType,
		}

		data.Files = append(data.Files, entry)
		data.TotalSize += entry.Size

		// Update counters
		if entry.IsDir {
			data.DirCount++
		} else if entry.IsLink {
			data.LinkCount++
		} else {
			data.FileCount++
		}

		// Track size by type
		data.SizeByType[fileType] += entry.Size
	}

	return data, nil
}

// determineFileType classifies a file based on header type and name
func determineFileType(header *tar.Header) string {
	switch header.Typeflag {
	case tar.TypeReg:
		return "file"
	case tar.TypeDir:
		return "directory"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hardlink"
	case tar.TypeChar:
		return "char device"
	case tar.TypeBlock:
		return "block device"
	case tar.TypeFifo:
		return "fifo"
	default:
		return "other"
	}
}

// cleanPath removes leading slashes and whiteout prefixes from tar paths
func cleanPath(p string) string {
	// Remove leading slashes
	p = strings.TrimLeft(p, "/")

	// Handle Docker whiteout files (.wh.filename)
	if strings.Contains(p, ".wh.") {
		parts := strings.Split(p, "/")
		if len(parts) > 0 {
			last := parts[len(parts)-1]
			if strings.HasPrefix(last, ".wh.") {
				// This is a deletion marker
				deletedName := strings.TrimPrefix(last, ".wh.")
				parts[len(parts)-1] = deletedName
				p = strings.Join(parts, "/")
				p = "[deleted] " + p
			}
		}
	}

	return p
}

// GetFilesOfType returns all files of a specific type
func (data *LayerTarData) GetFilesOfType(fileType string) []FileEntry {
	var filtered []FileEntry
	for _, f := range data.Files {
		if f.Type == fileType {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetFilesByPath returns files matching a path pattern
func (data *LayerTarData) GetFilesByPath(pathPattern string) []FileEntry {
	var filtered []FileEntry
	for _, f := range data.Files {
		if strings.Contains(f.Name, pathPattern) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetLargestFiles returns the N largest files
func (data *LayerTarData) GetLargestFiles(limit int) []FileEntry {
	if limit > len(data.Files) {
		limit = len(data.Files)
	}

	// Simple bubble sort for small lists
	sorted := make([]FileEntry, len(data.Files))
	copy(sorted, data.Files)

	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Size > sorted[i].Size {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted[:limit]
}

// GetDirectorySize calculates total size of a directory and its contents
func (data *LayerTarData) GetDirectorySize(dirPath string) int64 {
	if !strings.HasSuffix(dirPath, "/") {
		dirPath = dirPath + "/"
	}

	var size int64
	for _, f := range data.Files {
		if strings.HasPrefix(f.Name, dirPath) {
			size += f.Size
		}
	}
	return size
}

// GetDirectoryStructure returns nested directory structure as a tree
func (data *LayerTarData) GetDirectoryStructure(rootPath string) map[string]interface{} {
	if !strings.HasSuffix(rootPath, "/") && rootPath != "" {
		rootPath = rootPath + "/"
	}

	tree := make(map[string]interface{})

	for _, f := range data.Files {
		name := f.Name

		// Filter by root path
		if rootPath != "" && !strings.HasPrefix(name, rootPath) {
			continue
		}

		// Remove root prefix
		if rootPath != "" {
			name = strings.TrimPrefix(name, rootPath)
		}

		// Add to tree
		parts := strings.Split(strings.TrimSuffix(name, "/"), "/")
		current := tree

		for i, part := range parts {
			if part == "" {
				continue
			}

			if i == len(parts)-1 {
				// Leaf node
				current[part] = map[string]interface{}{
					"size": f.Size,
					"type": f.Type,
				}
			} else {
				// Intermediate directory
				if _, exists := current[part]; !exists {
					current[part] = make(map[string]interface{})
				}
				if m, ok := current[part].(map[string]interface{}); ok {
					current = m
				}
			}
		}
	}

	return tree
}

// Summary returns a text summary of the layer tar
func (data *LayerTarData) Summary() string {
	return fmt.Sprintf(
		"Layer %s: %d files, %d dirs, %d links, %.2f MB total",
		data.LayerID[:12],
		data.FileCount,
		data.DirCount,
		data.LinkCount,
		float64(data.TotalSize)/1024/1024,
	)
}
