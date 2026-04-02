package forensics

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ProcessAnalyzer analyzes processes running in containers
type ProcessAnalyzer struct {
	inspector *ContainerInspector
}

// Process represents a running process in a container
type Process struct {
	PID       int      // Process ID
	User      string   // User running process
	Command   string   // Full command line
	Name      string   // Process name (executable)
	CPU       float64  // CPU usage %
	Memory    float64  // Memory usage MB
	VSZ       int64    // Virtual memory size KB
	RSS       int64    // Resident set size KB
	State     string   // Process state (R, S, Z, D, T, W, X, x, K, W, P)
	Nice      int      // Nice level
	Threads   int      // Number of threads
}

// ProcessStats contains overall process statistics
type ProcessStats struct {
	TotalProcesses int
	RunningProcs   int
	SleepingProcs  int
	ZombieProcs    int
	StoppedProcs   int
	Processes      []Process
	TopByMemory    []Process
	TopByCPU       []Process
}

// NewProcessAnalyzer creates a new process analyzer
func NewProcessAnalyzer(inspector *ContainerInspector) *ProcessAnalyzer {
	return &ProcessAnalyzer{
		inspector: inspector,
	}
}

// ListProcesses lists all running processes in container
func (pa *ProcessAnalyzer) ListProcesses(ctx context.Context, containerID string) ([]Process, error) {
	// Use ps command to list processes
	cmd := []string{"sh", "-c", "ps aux"}
	output, err := pa.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}

	var processes []Process
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Skip header
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}

		proc, err := parseProcessLine(line)
		if err != nil {
			continue
		}

		processes = append(processes, proc)
	}

	return processes, nil
}

// GetProcessInfo retrieves detailed information about a specific process
func (pa *ProcessAnalyzer) GetProcessInfo(ctx context.Context, containerID string, pid int) (*Process, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("ps aux | grep %d | grep -v grep", pid)}
	output, err := pa.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get process info: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("process not found")
	}

	proc, err := parseProcessLine(lines[0])
	if err != nil {
		return nil, err
	}

	return &proc, nil
}

// GetProcessStats returns comprehensive process statistics
func (pa *ProcessAnalyzer) GetProcessStats(ctx context.Context, containerID string) (*ProcessStats, error) {
	processes, err := pa.ListProcesses(ctx, containerID)
	if err != nil {
		return nil, err
	}

	stats := &ProcessStats{
		Processes:      processes,
		TotalProcesses: len(processes),
	}

	// Count states and find top processes
	var topMemory []Process
	var topCPU []Process

	for _, p := range processes {
		// Count states
		switch p.State {
		case "R":
			stats.RunningProcs++
		case "S":
			stats.SleepingProcs++
		case "Z":
			stats.ZombieProcs++
		case "T":
			stats.StoppedProcs++
		}

		// Track top memory users
		topMemory = append(topMemory, p)

		// Track top CPU users
		topCPU = append(topCPU, p)
	}

	// Sort and get top 10
	sortByMemory(topMemory)
	sortByCPU(topCPU)

	if len(topMemory) > 10 {
		stats.TopByMemory = topMemory[:10]
	} else {
		stats.TopByMemory = topMemory
	}

	if len(topCPU) > 10 {
		stats.TopByCPU = topCPU[:10]
	} else {
		stats.TopByCPU = topCPU
	}

	return stats, nil
}

// GetProcessTree returns process hierarchy
func (pa *ProcessAnalyzer) GetProcessTree(ctx context.Context, containerID string) (string, error) {
	cmd := []string{"sh", "-c", "ps auxf"}
	output, err := pa.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get process tree: %w", err)
	}

	return output, nil
}

// GetOpenFiles lists files open by a process
func (pa *ProcessAnalyzer) GetOpenFiles(ctx context.Context, containerID string, pid int) ([]string, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("lsof -p %d 2>/dev/null | tail -n +2 | awk '{print $NF}'", pid)}
	output, err := pa.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		// lsof might not be installed
		return nil, fmt.Errorf("failed to get open files (lsof not available): %w", err)
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}

	return files, nil
}

// GetEnvironmentVariables gets environment variables for a process
func (pa *ProcessAnalyzer) GetEnvironmentVariables(ctx context.Context, containerID string, pid int) (map[string]string, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("cat /proc/%d/environ 2>/dev/null | tr '\\0' '\\n'", pid)}
	output, err := pa.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment variables: %w", err)
	}

	envVars := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}

	return envVars, nil
}

// GetSystemLoad returns system load average
func (pa *ProcessAnalyzer) GetSystemLoad(ctx context.Context, containerID string) (map[string]string, error) {
	cmd := []string{"sh", "-c", "cat /proc/loadavg"}
	output, err := pa.inspector.ExecCommand(ctx, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get system load: %w", err)
	}

	parts := strings.Fields(strings.TrimSpace(output))
	load := make(map[string]string)

	if len(parts) >= 3 {
		load["1_min"] = parts[0]
		load["5_min"] = parts[1]
		load["15_min"] = parts[2]
	}

	return load, nil
}

// Helper function to parse ps aux output line
func parseProcessLine(line string) (Process, error) {
	fields := strings.Fields(line)
	if len(fields) < 11 {
		return Process{}, fmt.Errorf("invalid process line")
	}

	proc := Process{
		User:    fields[0],
		Command: strings.Join(fields[10:], " "),
		Name:    extractProcessName(fields[10]),
	}

	// Parse numeric fields
	if pid, err := strconv.Atoi(fields[1]); err == nil {
		proc.PID = pid
	}

	if cpu, err := strconv.ParseFloat(fields[2], 64); err == nil {
		proc.CPU = cpu
	}

	if mem, err := strconv.ParseFloat(fields[3], 64); err == nil {
		proc.Memory = mem
	}

	if vsz, err := strconv.ParseInt(fields[4], 10, 64); err == nil {
		proc.VSZ = vsz
	}

	if rss, err := strconv.ParseInt(fields[5], 10, 64); err == nil {
		proc.RSS = rss
	}

	if len(fields) > 7 {
		proc.State = fields[7]
	}

	return proc, nil
}

// Helper function to extract process name from command
func extractProcessName(command string) string {
	parts := strings.Split(command, "/")
	return parts[len(parts)-1]
}

// Helper function to sort processes by memory
func sortByMemory(procs []Process) {
	for i := 0; i < len(procs); i++ {
		for j := i + 1; j < len(procs); j++ {
			if procs[j].Memory > procs[i].Memory {
				procs[i], procs[j] = procs[j], procs[i]
			}
		}
	}
}

// Helper function to sort processes by CPU
func sortByCPU(procs []Process) {
	for i := 0; i < len(procs); i++ {
		for j := i + 1; j < len(procs); j++ {
			if procs[j].CPU > procs[i].CPU {
				procs[i], procs[j] = procs[j], procs[i]
			}
		}
	}
}
