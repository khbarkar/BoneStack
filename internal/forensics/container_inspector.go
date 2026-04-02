package forensics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ContainerInspector provides live container inspection capabilities
type ContainerInspector struct {
	client *client.Client
}

// ContainerInfo contains detailed container information
type ContainerInfo struct {
	ID            string                      // Container ID
	Name          string                      // Container name
	State         *types.ContainerState       // Container state
	Config        *container.Config           // Container config
	HostConfig    *container.HostConfig       // Host config
	NetworkSettings *types.NetworkSettings    // Network info
	Mounts        []types.MountPoint          // Mount points
	Image         string                      // Image ID
	Created       string                      // Creation time
	Running       bool                        // Is running
	Paused        bool                        // Is paused
	Restarting    bool                        // Is restarting
	RestartCount  int32                       // Restart count
}

// ProcessInfo represents a running process in container
type ProcessInfo struct {
	PID        int    // Process ID
	User       string // User running process
	Command    string // Command line
	Name       string // Process name
	CPUPercent float64
	MemoryMB   float64
}

// NewContainerInspector creates a new container inspector
func NewContainerInspector(dockerClient *client.Client) *ContainerInspector {
	return &ContainerInspector{
		client: dockerClient,
	}
}

// InspectContainer retrieves detailed information about a container
func (ci *ContainerInspector) InspectContainer(ctx context.Context, containerID string) (*ContainerInfo, error) {
	inspect, err := ci.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	return &ContainerInfo{
		ID:              inspect.ID,
		Name:            inspect.Name,
		State:           inspect.State,
		Config:          inspect.Config,
		HostConfig:      inspect.HostConfig,
		NetworkSettings: inspect.NetworkSettings,
		Mounts:          inspect.Mounts,
		Image:           inspect.Image,
		Created:         inspect.Created.String(),
		Running:         inspect.State.Running,
		Paused:          inspect.State.Paused,
		Restarting:      inspect.State.Restarting,
		RestartCount:    inspect.RestartCount,
	}, nil
}

// GetContainerStats retrieves real-time container statistics
func (ci *ContainerInspector) GetContainerStats(ctx context.Context, containerID string) (*types.StatsJSON, error) {
	stats, err := ci.client.ContainerStats(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer stats.Body.Close()

	// Read the stats data
	var result types.StatsJSON
	decoder := json.NewDecoder(stats.Body)
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}

	return &result, nil
}

// ExecCommand runs a command inside a container and returns output
func (ci *ContainerInspector) ExecCommand(ctx context.Context, containerID string, cmd []string) (string, error) {
	// Create exec config
	execConfig := types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}

	// Create exec
	execID, err := ci.client.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	// Start exec
	attachConfig := types.ExecStartCheck{
		Detach: false,
		Tty:    false,
	}

	response, err := ci.client.ContainerExecAttach(ctx, execID.ID, attachConfig)
	if err != nil {
		return "", fmt.Errorf("failed to attach exec: %w", err)
	}
	defer response.Close()

	// Read output
	output, err := io.ReadAll(response.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to read exec output: %w", err)
	}

	return string(output), nil
}

// GetContainerLogs retrieves container logs
func (ci *ContainerInspector) GetContainerLogs(ctx context.Context, containerID string, tail string, follow bool) (io.ReadCloser, error) {
	options := types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Tail:       tail,
		Timestamps: true,
	}

	logs, err := ci.client.ContainerLogs(ctx, containerID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	return logs, nil
}

// ListContainers lists all containers (running and stopped)
func (ci *ContainerInspector) ListContainers(ctx context.Context, running bool) ([]types.Container, error) {
	options := types.ContainerListOptions{
		All: !running,
	}

	containers, err := ci.client.ContainerList(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return containers, nil
}

// GetContainerFS gets filesystem information for a container
func (ci *ContainerInspector) GetContainerFS(ctx context.Context, containerID string) (*types.ContainerFileInfo, error) {
	info, _, err := ci.client.CopyFromContainer(ctx, containerID, "/")
	if err != nil {
		return nil, fmt.Errorf("failed to get filesystem info: %w", err)
	}
	defer info.Close()

	// Note: Actual filesystem exploration requires diving into tar archives
	// This is a placeholder for the API
	return nil, nil
}

// CalculateStats calculates CPU and memory statistics from raw stats
func CalculateStats(stats *types.StatsJSON) (cpuPercent float64, memoryMB float64) {
	// CPU calculation
	if stats.CPUStats.CPUUsage.TotalUsage > 0 && stats.PreCPUStats.CPUUsage.TotalUsage > 0 {
		cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
		systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
		if systemDelta > 0 {
			cpuPercent = (cpuDelta / systemDelta) * float64(len(stats.CPUStats.CPUUsage.PercpuUsage)) * 100
		}
	}

	// Memory calculation
	memoryBytes := stats.MemoryStats.Usage
	memoryMB = float64(memoryBytes) / 1024 / 1024

	return cpuPercent, memoryMB
}

// GetEnvironmentVariables extracts environment variables from container
func (ci *ContainerInspector) GetEnvironmentVariables(ctx context.Context, containerID string) (map[string]string, error) {
	inspect, err := ci.InspectContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	envVars := make(map[string]string)
	for _, env := range inspect.Config.Env {
		// Parse KEY=VALUE format
		parts := bytes.SplitN([]byte(env), []byte("="), 2)
		if len(parts) == 2 {
			envVars[string(parts[0])] = string(parts[1])
		}
	}

	return envVars, nil
}

// IsContainerRunning checks if a container is running
func (ci *ContainerInspector) IsContainerRunning(ctx context.Context, containerID string) (bool, error) {
	inspect, err := ci.InspectContainer(ctx, containerID)
	if err != nil {
		return false, err
	}

	return inspect.Running, nil
}

// GetContainerUptime returns container uptime in seconds
func (ci *ContainerInspector) GetContainerUptime(ctx context.Context, containerID string) (int64, error) {
	inspect, err := ci.InspectContainer(ctx, containerID)
	if err != nil {
		return 0, err
	}

	if !inspect.Running {
		return 0, fmt.Errorf("container is not running")
	}

	// Calculate uptime: current time - start time
	now := time.Now()
	startedAt := inspect.State.StartedAt
	return int64(now.Sub(startedAt).Seconds()), nil
}

// GetMountPoints returns detailed mount point information
func (ci *ContainerInspector) GetMountPoints(ctx context.Context, containerID string) ([]types.MountPoint, error) {
	inspect, err := ci.InspectContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	return inspect.Mounts, nil
}
