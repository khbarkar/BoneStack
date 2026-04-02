package forensics

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ResourceStats captures a lightweight snapshot of runtime resource usage.
type ResourceStats struct {
	MemoryUsageMB float64
	MemoryLimitMB float64
	MemoryPercent float64
	CPUPercent    float64
	ProcessCount  int
}

// ResourceMonitor collects resource data from a running container.
type ResourceMonitor struct {
	inspector *ContainerInspector
}

// NewResourceMonitor creates a new resource monitor.
func NewResourceMonitor(inspector *ContainerInspector) *ResourceMonitor {
	return &ResourceMonitor{inspector: inspector}
}

// GetStats returns a best-effort runtime snapshot using procfs inside the container.
func (rm *ResourceMonitor) GetStats(ctx context.Context, containerID string) (*ResourceStats, error) {
	memInfo, err := rm.inspector.ExecCommand(ctx, containerID, []string{"sh", "-c", "cat /proc/meminfo 2>/dev/null"})
	if err != nil {
		return nil, fmt.Errorf("failed to read meminfo: %w", err)
	}

	loadAvg, _ := rm.inspector.ExecCommand(ctx, containerID, []string{"sh", "-c", "cat /proc/loadavg 2>/dev/null"})
	procCountOut, _ := rm.inspector.ExecCommand(ctx, containerID, []string{"sh", "-c", "ps aux 2>/dev/null | tail -n +2 | wc -l"})

	stats := &ResourceStats{}
	parseMemInfo(memInfo, stats)

	if fields := strings.Fields(loadAvg); len(fields) > 0 {
		if cpu, err := strconv.ParseFloat(fields[0], 64); err == nil {
			stats.CPUPercent = cpu * 100
		}
	}

	if count, err := strconv.Atoi(strings.TrimSpace(procCountOut)); err == nil {
		stats.ProcessCount = count
	}

	return stats, nil
}

func parseMemInfo(memInfo string, stats *ResourceStats) {
	var totalKB float64
	var availableKB float64

	for _, line := range strings.Split(memInfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			totalKB, _ = strconv.ParseFloat(fields[1], 64)
		case "MemAvailable":
			availableKB, _ = strconv.ParseFloat(fields[1], 64)
		}
	}

	if totalKB <= 0 {
		return
	}

	usedKB := totalKB - availableKB
	stats.MemoryUsageMB = usedKB / 1024
	stats.MemoryLimitMB = totalKB / 1024
	stats.MemoryPercent = (usedKB / totalKB) * 100
}
