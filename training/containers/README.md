# Training Containers

These container examples are intentionally suspicious-looking or badly built, but not malicious.

They are meant for practicing BoneStack workflows:

- forensics
- YARA-backed threat hunting
- container diff
- timeline
- optimization
- scaffold generation

Build examples:

```bash
docker build -t bonestack-training:cron-shadow training/containers/cron-shadow
docker build -t bonestack-training:ssh-drop training/containers/ssh-drop-demo
docker build -t bonestack-training:bloaty-node training/containers/bloaty-node-demo
docker build -t bonestack-training:ai-followup training/containers/ai-followup-demo
```

Run examples:

```bash
docker run -d --name cron-shadow-demo bonestack-training:cron-shadow
docker run -d --name ssh-drop-demo bonestack-training:ssh-drop
docker run -d --name bloaty-node-demo bonestack-training:bloaty-node
docker run -d --name ai-followup-demo bonestack-training:ai-followup
```

Recommended for the AI-assisted workflow:

- `ai-followup-demo`
  - includes a cron artifact, shell history, a harmless script with suspicious-looking strings, and clear log lines telling you to inspect logs and timeline
  - use `Threat Hunt` first, then press `a`
  - if the model asks for more context, press `x` in `AI Analysis` to let BoneStack fetch the requested evidence
