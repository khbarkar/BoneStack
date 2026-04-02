# Training Containers

BoneStack includes safe training containers under [training/containers](../training/containers).

These are not malicious. They are intentionally noisy, suspicious, or poorly built so you can practice using:

- `Threat Hunt`
- `Container Diff`
- `Timeline`
- YARA-backed scanning
- optimization and scaffold generation

## Included Scenarios

### `cron-shadow`

Safe demo container with:

- a cron entry
- a shell script in `/opt/demo`
- a suspicious-looking note in `/tmp`

Use it to practice:

- cron persistence detection
- container diff on changed files
- YARA matching for shell/download-style patterns

### `ssh-drop-demo`

Safe demo container with:

- an `authorized_keys` file
- shell history content
- a service file and preload marker file

Use it to practice:

- SSH persistence findings
- shell history findings
- suspicious path flags in `Container Diff`

### `bloaty-node-demo`

Intentionally poor image build with:

- many layers
- package-manager cache patterns
- a large fake artifact

Use it to practice:

- optimization suggestions
- layer analysis
- scaffold generation from bad images

## Build Examples

From the repo root:

```bash
docker build -t bonestack-training:cron-shadow training/containers/cron-shadow
docker build -t bonestack-training:ssh-drop training/containers/ssh-drop-demo
docker build -t bonestack-training:bloaty-node training/containers/bloaty-node-demo
```

## Run Examples

```bash
docker run -d --name cron-shadow-demo bonestack-training:cron-shadow
docker run -d --name ssh-drop-demo bonestack-training:ssh-drop
docker run -d --name bloaty-node-demo bonestack-training:bloaty-node
```

Then open BoneStack and inspect those containers.

## Cleanup

```bash
docker rm -f cron-shadow-demo ssh-drop-demo bloaty-node-demo
```
