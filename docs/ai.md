# AI Guide

BoneStack can use an LLM inside the TUI to help investigate the currently selected forensic view.

## What It Does

- explains suspicious indicators in plain language
- separates likely benign noise from stronger signals
- suggests concrete next investigation steps
- can request more BoneStack context such as:
  - `logs`
  - `timeline`
  - `environment`
  - `resources`
  - `processes`
  - `filesystem`
  - `threat-hunt`
  - `container-diff`

## Configure AI In The TUI

From the main menu:

1. Open `AI Settings`
2. Choose a provider
3. Set model, base URL, and API key if needed
4. Press `s` to save

Supported providers:

- `ollama`
- `openai`
- `claude`
- `grok`
- `gemini`
- `openai-compatible`

## Use AI During Forensics

1. Open `View Containers`
2. Pick a container
3. Press `Enter`
4. Press `f`
5. Open `Threat Hunt`, `Container Diff`, or `Timeline`
6. Press `a`

BoneStack will:

- test AI connectivity
- show a loading screen while it waits
- display the analysis in `AI Analysis`

## Agentic Follow-Up

If the model wants more evidence, it can ask BoneStack for more context.

The `AI Analysis` screen will show `Requested Context`.

Press:

- `x` to fetch the requested context and rerun the analysis

This keeps the user in control. BoneStack does not silently collect extra evidence without approval.

## Good First Demo

Use the safe training container:

```bash
docker build -t bonestack-training:ai-followup training/containers/ai-followup-demo
docker run -d --name ai-followup-demo bonestack-training:ai-followup
```

Then in BoneStack:

1. Open `View Containers`
2. Select `ai-followup-demo`
3. Press `f`
4. Open `Threat Hunt`
5. Press `a`
6. If the AI asks for more context, press `x`

## Notes

- local `ollama` is the easiest way to try the feature without a hosted API key
- some providers respond slowly; BoneStack now shows a live loading screen while waiting
- the AI feature is meant to guide investigation, not replace the raw forensic views
