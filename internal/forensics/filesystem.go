package forensics

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// FileSystemInspector inspects container filesystems
type FileSystemInspector struct {
	inspector *ContainerInspector
}

// FileInfo represents a file in the container filesystem
type FileInfo struct {
	Name     string // File name
	Path     string // Full path
	Size     int64  // File size in bytes
	IsDir    bool   // Is directory
	Modified string // Last modified time
	Perms    string // File permissions
}

// DirectoryStats contains statistics about a directory
type DirectoryStats struct {
	Path      string
	FileCount int
	DirCount  int
	TotalSize int64
	Files     []FileInfo
	LargestFiles []FileInfo
}

// NewFileSystemInspector creates a new filesystem inspector
func NewFileSystemInspector(inspector *ContainerInspector) *FileSystemInspector {
	return &FileSystemInspector{
		inspector: inspector,
	}
}

// ListDirectory lists files and directories in a container path
func (fi *FileSystemInspector) ListDirectory(ctx context.Context, containerID, path string) ([]FileInfo, error) {
	if path == "" {
		path = "/"
	}

	// Use 'ls -la' command to list files
	cmd := []string{"sh", "-c", fmt.Sprintf("ls -la %s 2>/dev/null | awk 'NR>1 {print $9, $5, $6, $7, $8, $1}'", path)}
	output, err := fi.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var files []FileInfo
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}

		name := parts[0]
		sizeStr := parts[1]
		perms := parts[5]

		// Parse size
		var size int64
		fmt.Sscanf(sizeStr, "%d", &size)

		// Determine if directory
		isDir := strings.HasPrefix(perms, "d")

		file := FileInfo{
			Name:  name,
			Path:  filepath.Join(path, name),
			Size:  size,
			IsDir: isDir,
			Perms: perms,
		}

		files = append(files, file)
	}

	return files, nil
}

// CalculateDirectorySize recursively calculates directory size
func (fi *FileSystemInspector) CalculateDirectorySize(ctx context.Context, containerID, path string) (int64, error) {
	if path == "" {
		path = "/"
	}

	// Use 'du -sb' to calculate size
	cmd := []string{"sh", "-c", fmt.Sprintf("du -sb %s 2>/dev/null | awk '{print $1}'", path)}
	output, err := fi.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate directory size: %w", err)
	}

	var size int64
	fmt.Sscanf(strings.TrimSpace(output), "%d", &size)

	return size, nil
}

// GetDirectoryStats returns detailed directory statistics
func (fi *FileSystemInspector) GetDirectoryStats(ctx context.Context, containerID, path string) (*DirectoryStats, error) {
	if path == "" {
		path = "/"
	}

	// List files
	files, err := fi.ListDirectory(ctx, containerID, path)
	if err != nil {
		return nil, err
	}

	// Calculate totals
	stats := &DirectoryStats{
		Path: path,
	}

	var largestFiles []FileInfo

	for _, f := range files {
		if f.IsDir {
			stats.DirCount++
		} else {
			stats.FileCount++
			stats.TotalSize += f.Size
			largestFiles = append(largestFiles, f)
		}
	}

	// Sort and keep top 10 largest files
	sort.Slice(largestFiles, func(i, j int) bool {
		return largestFiles[i].Size > largestFiles[j].Size
	})

	if len(largestFiles) > 10 {
		stats.LargestFiles = largestFiles[:10]
	} else {
		stats.LargestFiles = largestFiles
	}

	stats.Files = files
	return stats, nil
}

// FindLargeFiles finds files larger than threshold in a directory
func (fi *FileSystemInspector) FindLargeFiles(ctx context.Context, containerID, path string, minSize int64) ([]FileInfo, error) {
	if path == "" {
		path = "/"
	}

	// Use 'find' to locate large files
	cmd := []string{"sh", "-c", fmt.Sprintf("find %s -type f -size +%dc -printf '%%s %%p\\n' 2>/dev/null | sort -rn", path, minSize)}
	output, err := fi.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to find large files: %w", err)
	}

	var files []FileInfo
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}

		var size int64
		fmt.Sscanf(parts[0], "%d", &size)

		file := FileInfo{
			Name: filepath.Base(parts[1]),
			Path: parts[1],
			Size: size,
		}

		files = append(files, file)
	}

	return files, nil
}

// SearchFiles searches for files matching a pattern
func (fi *FileSystemInspector) SearchFiles(ctx context.Context, containerID, path, pattern string) ([]FileInfo, error) {
	if path == "" {
		path = "/"
	}

	// Use 'find' with pattern matching
	cmd := []string{"sh", "-c", fmt.Sprintf("find %s -type f -name '*%s*' 2>/dev/null", path, pattern)}
	output, err := fi.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to search files: %w", err)
	}

	var files []FileInfo
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}

		file := FileInfo{
			Name: filepath.Base(line),
			Path: line,
		}

		files = append(files, file)
	}

	return files, nil
}

// GetFileContent reads file content from container
func (fi *FileSystemInspector) GetFileContent(ctx context.Context, containerID, filePath string, maxLines int) (string, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("head -n %d %s 2>/dev/null", maxLines, filePath)}
	output, err := fi.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return output, nil
}

// AnalyzeFileTypes categorizes files by extension
func (fi *FileSystemInspector) AnalyzeFileTypes(ctx context.Context, containerID, path string) (map[string]int, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("find %s -type f 2>/dev/null | sed 's/.*\\.//' | sort | uniq -c", path)}
	output, err := fi.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze file types: %w", err)
	}

	types := make(map[string]int)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			var count int
			fmt.Sscanf(parts[0], "%d", &count)
			ext := parts[1]
			types[ext] = count
		}
	}

	return types, nil
}

// GetDiskUsage returns disk usage information
func (fi *FileSystemInspector) GetDiskUsage(ctx context.Context, containerID string) (map[string]string, error) {
	cmd := []string{"sh", "-c", "df -h / | awk 'NR==2 {print $1, $2, $3, $4, $5}'"}
	output, err := fi.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}

	parts := strings.Fields(strings.TrimSpace(output))
	usage := make(map[string]string)

	if len(parts) >= 5 {
		usage["filesystem"] = parts[0]
		usage["total"] = parts[1]
		usage["used"] = parts[2]
		usage["available"] = parts[3]
		usage["percent"] = parts[4]
	}

	return usage, nil
}
