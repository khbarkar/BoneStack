package forensics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// ContainerInspector provides basic container inspection.
type ContainerInspector struct {
	client *client.Client
}

// NewContainerInspector creates a new container inspector.
func NewContainerInspector(cli *client.Client) *ContainerInspector {
	return &ContainerInspector{client: cli}
}

// GetEnvironmentVariables retrieves container env vars from inspect.
func (ci *ContainerInspector) GetEnvironmentVariables(ctx context.Context, containerID string) (map[string]string, error) {
	inspect, _, err := ci.client.ContainerInspectWithRaw(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	envVars := make(map[string]string)
	for _, env := range inspect.Config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}
	return envVars, nil
}

// GetContainerInfo returns basic container info.
func (ci *ContainerInspector) GetContainerInfo(ctx context.Context, containerID string) (map[string]string, error) {
	inspect, _, err := ci.client.ContainerInspectWithRaw(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	info := map[string]string{
		"id":    inspect.ID,
		"name":  strings.TrimPrefix(inspect.Name, "/"),
		"state": inspect.State.Status,
		"image": inspect.Image,
	}
	if len(inspect.Mounts) > 0 {
		info["mounts"] = fmt.Sprintf("%d", len(inspect.Mounts))
	}
	return info, nil
}

// GetMountPoints returns the container's mounts from inspect output.
func (ci *ContainerInspector) GetMountPoints(ctx context.Context, containerID string) ([]container.MountPoint, error) {
	inspect, _, err := ci.client.ContainerInspectWithRaw(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect mounts: %w", err)
	}
	return inspect.Mounts, nil
}

// ExecCommand runs a command inside the target container and returns combined output.
func (ci *ContainerInspector) ExecCommand(ctx context.Context, containerID string, cmd []string) (string, error) {
	created, err := ci.client.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := ci.client.ContainerExecAttach(ctx, created.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to attach exec: %w", err)
	}
	defer resp.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, resp.Reader); err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read exec output: %w", err)
	}

	inspect, err := ci.client.ContainerExecInspect(ctx, created.ID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect exec: %w", err)
	}
	if inspect.ExitCode != 0 {
		errOutput := strings.TrimSpace(stderr.String())
		if errOutput == "" {
			errOutput = strings.TrimSpace(stdout.String())
		}
		if errOutput == "" {
			errOutput = fmt.Sprintf("command exited with status %d", inspect.ExitCode)
		}
		return "", errors.New(errOutput)
	}

	if stderr.Len() > 0 && stdout.Len() == 0 {
		return strings.TrimSpace(stderr.String()), nil
	}
	return strings.TrimSpace(stdout.String()), nil
}

// GetContainerLogs returns container logs as a stream.
func (ci *ContainerInspector) GetContainerLogs(ctx context.Context, containerID, tail string, follow bool) (io.ReadCloser, error) {
	return ci.client.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
		Follow:     follow,
		Timestamps: false,
	})
}
