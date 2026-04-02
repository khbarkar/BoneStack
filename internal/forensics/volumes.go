package forensics

import (
	"context"
	"fmt"
	"strings"
)

// VolumeAnalyzer analyzes container volumes and mounts
type VolumeAnalyzer struct {
	inspector *ContainerInspector
}

// VolumeInfo represents information about a mounted volume
type VolumeInfo struct {
	Source      string // Source path (host or volume name)
	Destination string // Destination path in container
	ReadOnly    bool   // Is read-only
	Type        string // mount, volume, tmpfs, etc
	Size        int64  // Volume size in bytes (if available)
	Driver      string // Driver name for named volumes
	Labels      map[string]string
}

// VolumeStats contains volume usage statistics
type VolumeStats struct {
	Volumes              []VolumeInfo
	TotalMounted         int
	ReadOnlyMounts       int
	ReadWriteMounts      int
	PotentiallyUnused    []VolumeInfo
}

// NewVolumeAnalyzer creates a new volume analyzer
func NewVolumeAnalyzer(inspector *ContainerInspector) *VolumeAnalyzer {
	return &VolumeAnalyzer{
		inspector: inspector,
	}
}

// GetMountPoints retrieves mount point information
func (va *VolumeAnalyzer) GetMountPoints(ctx context.Context, containerID string) ([]VolumeInfo, error) {
	mounts, err := va.inspector.GetMountPoints(ctx, containerID)
	if err != nil {
		return nil, err
	}

	var volumes []VolumeInfo

	for _, mount := range mounts {
		vol := VolumeInfo{
			Source:      mount.Source,
			Destination: mount.Destination,
			ReadOnly:    mount.RW == false,
			Type:        string(mount.Type),
		}

		// Try to determine driver for named volumes
		if mount.Driver != "" {
			vol.Driver = mount.Driver
		}

		volumes = append(volumes, vol)
	}

	return volumes, nil
}

// AnalyzeVolumes performs comprehensive volume analysis
func (va *VolumeAnalyzer) AnalyzeVolumes(ctx context.Context, containerID string) (*VolumeStats, error) {
	volumes, err := va.GetMountPoints(ctx, containerID)
	if err != nil {
		return nil, err
	}

	stats := &VolumeStats{
		Volumes:      volumes,
		TotalMounted: len(volumes),
	}

	// Count access modes
	for _, vol := range volumes {
		if vol.ReadOnly {
			stats.ReadOnlyMounts++
		} else {
			stats.ReadWriteMounts++
		}
	}

	// Analyze volumes for usage
	for _, vol := range volumes {
		if err := va.analyzeVolumeUsage(ctx, containerID, &vol); err != nil {
			// If we can't analyze, mark as potentially unused
			stats.PotentiallyUnused = append(stats.PotentiallyUnused, vol)
		}
	}

	return stats, nil
}

// GetVolumeSize returns the size of a mounted volume
func (va *VolumeAnalyzer) GetVolumeSize(ctx context.Context, containerID, path string) (int64, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("du -sb %s 2>/dev/null | awk '{print $1}'", path)}
	output, err := va.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate volume size: %w", err)
	}

	var size int64
	fmt.Sscanf(strings.TrimSpace(output), "%d", &size)

	return size, nil
}

// DetectUnusedVolumes identifies potentially unused volumes
func (va *VolumeAnalyzer) DetectUnusedVolumes(ctx context.Context, containerID string) ([]VolumeInfo, error) {
	volumes, err := va.GetMountPoints(ctx, containerID)
	if err != nil {
		return nil, err
	}

	var unused []VolumeInfo

	for _, vol := range volumes {
		// Skip read-only mounts and system paths
		if vol.ReadOnly || strings.HasPrefix(vol.Destination, "/proc") || strings.HasPrefix(vol.Destination, "/sys") {
			continue
		}

		// Check if volume has recent access
		cmd := []string{"sh", "-c", fmt.Sprintf("find %s -type f -mmin -60 2>/dev/null | wc -l", vol.Destination)}
		output, err := va.inspector.ExecCommand(ctx, containerID, cmd)
		if err != nil {
			unused = append(unused, vol)
			continue
		}

		var count int
		fmt.Sscanf(strings.TrimSpace(output), "%d", &count)

		// If no files modified in last 60 minutes, mark as potentially unused
		if count == 0 {
			unused = append(unused, vol)
		}
	}

	return unused, nil
}

// ListVolumeContents lists files in a mounted volume
func (va *VolumeAnalyzer) ListVolumeContents(ctx context.Context, containerID, path string) ([]FileInfo, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("ls -la %s 2>/dev/null", path)}
	output, err := va.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to list volume contents: %w", err)
	}

	var files []FileInfo
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" || strings.HasPrefix(line, "total") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 9 {
			continue
		}

		file := FileInfo{
			Name:  parts[8],
			Path:  fmt.Sprintf("%s/%s", path, parts[8]),
			Perms: parts[0],
		}

		files = append(files, file)
	}

	return files, nil
}

// CheckMountPermissions checks if a volume is readable/writable
func (va *VolumeAnalyzer) CheckMountPermissions(ctx context.Context, containerID, path string) (map[string]bool, error) {
	perms := make(map[string]bool)

	// Check read permission
	cmd := []string{"sh", "-c", fmt.Sprintf("test -r %s && echo 1 || echo 0", path)}
	output, err := va.inspector.ExecCommand(ctx, containerID, cmd)
	if err == nil {
		perms["readable"] = strings.TrimSpace(output) == "1"
	}

	// Check write permission
	cmd = []string{"sh", "-c", fmt.Sprintf("test -w %s && echo 1 || echo 0", path)}
	output, err = va.inspector.ExecCommand(ctx, containerID, cmd)
	if err == nil {
		perms["writable"] = strings.TrimSpace(output) == "1"
	}

	// Check execute permission
	cmd = []string{"sh", "-c", fmt.Sprintf("test -x %s && echo 1 || echo 0", path)}
	output, err = va.inspector.ExecCommand(ctx, containerID, cmd)
	if err == nil {
		perms["executable"] = strings.TrimSpace(output) == "1"
	}

	return perms, nil
}

// GetVolumeInode returns inode information for a volume
func (va *VolumeAnalyzer) GetVolumeInode(ctx context.Context, containerID, path string) (map[string]string, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("df -i %s | awk 'NR==2 {print $1, $2, $3, $4, $5}'", path)}
	output, err := va.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get inode info: %w", err)
	}

	parts := strings.Fields(strings.TrimSpace(output))
	inode := make(map[string]string)

	if len(parts) >= 5 {
		inode["filesystem"] = parts[0]
		inode["total"] = parts[1]
		inode["used"] = parts[2]
		inode["available"] = parts[3]
		inode["percent"] = parts[4]
	}

	return inode, nil
}

// Helper function to analyze volume usage
func (va *VolumeAnalyzer) analyzeVolumeUsage(ctx context.Context, containerID string, vol *VolumeInfo) error {
	size, err := va.GetVolumeSize(ctx, containerID, vol.Destination)
	if err != nil {
		return err
	}

	vol.Size = size
	return nil
}
