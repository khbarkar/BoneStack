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
```

Run examples:

```bash
docker run -d --name cron-shadow-demo bonestack-training:cron-shadow
docker run -d --name ssh-drop-demo bonestack-training:ssh-drop
docker run -d --name bloaty-node-demo bonestack-training:bloaty-node
```
