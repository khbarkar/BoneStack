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

### `ai-followup-demo`

Safe demo container with:

- a cron artifact
- shell history
- a harmless script containing suspicious-looking reverse-shell and download strings
- explicit log messages that tell you to inspect logs and timeline before deciding what happened

Use it to practice:

- `Threat Hunt` followed by AI analysis
- agentic AI follow-up requests for `logs` and `timeline`
- the `x` flow in `AI Analysis` to fetch requested context automatically

## Build Examples

From the repo root:

```bash
docker build -t bonestack-training:cron-shadow training/containers/cron-shadow
docker build -t bonestack-training:ssh-drop training/containers/ssh-drop-demo
docker build -t bonestack-training:bloaty-node training/containers/bloaty-node-demo
docker build -t bonestack-training:ai-followup training/containers/ai-followup-demo
```

## Run Examples

```bash
docker run -d --name cron-shadow-demo bonestack-training:cron-shadow
docker run -d --name ssh-drop-demo bonestack-training:ssh-drop
docker run -d --name bloaty-node-demo bonestack-training:bloaty-node
docker run -d --name ai-followup-demo bonestack-training:ai-followup
```

Then open BoneStack and inspect those containers.

Suggested AI walkthrough for `ai-followup-demo`:

1. Open `View Containers`
2. Pick `ai-followup-demo`
3. Press `f`
4. Open `Threat Hunt`
5. Press `a`
6. If the model requests extra context, press `x`
7. BoneStack will fetch the requested evidence and rerun the analysis

## Cleanup

```bash
docker rm -f cron-shadow-demo ssh-drop-demo bloaty-node-demo ai-followup-demo
```
