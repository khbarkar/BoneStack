package forensics

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
)

// ResourceMonitor monitors container resource usage
type ResourceMonitor struct {
	inspector *ContainerInspector
}

// ResourceStats contains resource usage information
type ResourceStats struct {
	CPUPercent    float64
	MemoryUsage   int64 // In bytes
	MemoryMB      float64
	MemoryLimit   int64
	MemoryPercent float64
	NetRxBytes    uint64
	NetTxBytes    uint64
	BlockRead     uint64
	BlockWrite    uint64
	PIDsCount     uint64
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(inspector *ContainerInspector) *ResourceMonitor {
	return &ResourceMonitor{
		inspector: inspector,
	}
}

// GetResourceStats retrieves current resource usage statistics
func (rm *ResourceMonitor) GetResourceStats(ctx context.Context, containerID string) (*ResourceStats, error) {
	stats, err := rm.inspector.GetContainerStats(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}

	return parseStats(stats), nil
}

// GetCPUUsage returns CPU usage percentage
func (rm *ResourceMonitor) GetCPUUsage(ctx context.Context, containerID string) (float64, error) {
	stats, err := rm.GetResourceStats(ctx, containerID)
	if err != nil {
		return 0, err
	}

	return stats.CPUPercent, nil
}

// GetMemoryUsage returns memory usage in MB
func (rm *ResourceMonitor) GetMemoryUsage(ctx context.Context, containerID string) (float64, error) {
	stats, err := rm.GetResourceStats(ctx, containerID)
	if err != nil {
		return 0, err
	}

	return stats.MemoryMB, nil
}

// GetNetworkStats returns network I/O statistics
func (rm *ResourceMonitor) GetNetworkStats(ctx context.Context, containerID string) (map[string]interface{}, error) {
	stats, err := rm.GetResourceStats(ctx, containerID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"rx_bytes": stats.NetRxBytes,
		"tx_bytes": stats.NetTxBytes,
		"rx_mb":    float64(stats.NetRxBytes) / 1024 / 1024,
		"tx_mb":    float64(stats.NetTxBytes) / 1024 / 1024,
	}, nil
}

// GetBlockIOStats returns block I/O statistics
func (rm *ResourceMonitor) GetBlockIOStats(ctx context.Context, containerID string) (map[string]interface{}, error) {
	stats, err := rm.GetResourceStats(ctx, containerID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"read_bytes":  stats.BlockRead,
		"write_bytes": stats.BlockWrite,
		"read_mb":     float64(stats.BlockRead) / 1024 / 1024,
		"write_mb":    float64(stats.BlockWrite) / 1024 / 1024,
	}, nil
}

// GetMemoryLimit returns memory limit in MB
func (rm *ResourceMonitor) GetMemoryLimit(ctx context.Context, containerID string) (float64, error) {
	stats, err := rm.GetResourceStats(ctx, containerID)
	if err != nil {
		return 0, err
	}

	return float64(stats.MemoryLimit) / 1024 / 1024, nil
}

// GetProcessCount returns number of processes in container
func (rm *ResourceMonitor) GetProcessCount(ctx context.Context, containerID string) (uint64, error) {
	stats, err := rm.GetResourceStats(ctx, containerID)
	if err != nil {
		return 0, err
	}

	return stats.PIDsCount, nil
}

// Helper function to parse Docker stats
func parseStats(rawStats *types.StatsJSON) *ResourceStats {
	stats := &ResourceStats{}

	// CPU calculation
	if rawStats.CPUStats.CPUUsage.TotalUsage > 0 && rawStats.PreCPUStats.CPUUsage.TotalUsage > 0 {
		cpuDelta := float64(rawStats.CPUStats.CPUUsage.TotalUsage - rawStats.PreCPUStats.CPUUsage.TotalUsage)
		systemDelta := float64(rawStats.CPUStats.SystemUsage - rawStats.PreCPUStats.SystemUsage)
		if systemDelta > 0 {
			stats.CPUPercent = (cpuDelta / systemDelta) * float64(len(rawStats.CPUStats.CPUUsage.PercpuUsage)) * 100.0
		}
	}

	// Memory calculation
	stats.MemoryUsage = int64(rawStats.MemoryStats.Usage)
	stats.MemoryMB = float64(stats.MemoryUsage) / 1024 / 1024

	if rawStats.MemoryStats.Limit > 0 {
		stats.MemoryLimit = int64(rawStats.MemoryStats.Limit)
		stats.MemoryPercent = (float64(stats.MemoryUsage) / float64(stats.MemoryLimit)) * 100.0
	}

	// Network I/O
	if rawStats.Networks != nil {
		for _, network := range rawStats.Networks {
			stats.NetRxBytes += network.RxBytes
			stats.NetTxBytes += network.TxBytes
		}
	}

	// Block I/O
	if rawStats.BlkioStats.IoServiceBytesRecursive != nil {
		for _, entry := range rawStats.BlkioStats.IoServiceBytesRecursive {
			switch entry.Op {
			case "Read":
				stats.BlockRead += entry.Value
			case "Write":
				stats.BlockWrite += entry.Value
			}
		}
	}

	// Process count
	if rawStats.PidsStats != nil {
		stats.PIDsCount = rawStats.PidsStats.Current
	}

	return stats
}
