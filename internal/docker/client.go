package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type Client struct {
	docker *client.Client
}

func NewClient(ctx context.Context) (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping Docker daemon: %w", err)
	}

	return &Client{docker: cli}, nil
}

type ImageSummary struct {
	ID        string
	RepoTags  []string
	Size      int64
	Created   int64
	Inspect   types.ImageInspect
}

type ContainerSummary struct {
	ID      string
	Names   []string
	Image   string
	Status  string
	Inspect types.ContainerJSON
}

func (c *Client) ListImages(ctx context.Context) ([]ImageSummary, error) {
	imageList, err := c.docker.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	var results []ImageSummary
	for _, img := range imageList {
		results = append(results, ImageSummary{
			ID:       img.ID,
			RepoTags: img.RepoTags,
			Size:     img.Size,
			Created:  img.Created,
		})
	}
	return results, nil
}

func (c *Client) ListContainers(ctx context.Context) ([]ContainerSummary, error) {
	containerList, err := c.docker.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var results []ContainerSummary
	for _, cont := range containerList {
		results = append(results, ContainerSummary{
			ID:     cont.ID,
			Names:  cont.Names,
			Image:  cont.Image,
			Status: cont.Status,
		})
	}
	return results, nil
}

func (c *Client) InspectImage(ctx context.Context, imageID string) (types.ImageInspect, error) {
	inspect, _, err := c.docker.ImageInspectWithRaw(ctx, imageID)
	if err != nil {
		return types.ImageInspect{}, fmt.Errorf("failed to inspect image: %w", err)
	}
	return inspect, nil
}

func (c *Client) InspectContainer(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	inspect, err := c.docker.ContainerInspect(ctx, containerID)
	if err != nil {
		return types.ContainerJSON{}, fmt.Errorf("failed to inspect container: %w", err)
	}
	return inspect, nil
}

func (c *Client) GetImageHistory(ctx context.Context, imageID string) ([]image.HistoryResponseItem, error) {
	history, err := c.docker.ImageHistory(ctx, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to get image history: %w", err)
	}
	return history, nil
}

func (c *Client) Close() error {
	return c.docker.Close()
}
