# Forensics Guide

BoneStack now has three container-focused forensic views that work together:

- `Threat Hunt`
- `Container Diff`
- `Timeline`

The intended workflow is:

1. Open a container.
2. Enter the forensics menu with `f`.
3. Review `Threat Hunt` for suspicious artifacts and content matches.
4. Review `Container Diff` for filesystem changes since container start.
5. Review `Timeline` for recent Docker lifecycle events.
6. Export a combined report with `w`.

## Quick Walkthrough

Start BoneStack:

```bash
go build -o bonestack ./cmd/bonestack/main.go
./bonestack
```

Then in the TUI:

1. Select `View Containers`
2. Pick a container
3. Press `f`
4. Choose one of:
   - `Threat Hunt`
   - `Container Diff`
   - `Timeline`

## Threat Hunt

`Threat Hunt` looks for suspicious container artifacts and suspicious content in files such as:

- cron entries
- `authorized_keys`
- shell history files
- service files
- shell scripts
- base64 payload hints
- reverse shell strings such as `nc -e`, `/dev/tcp`, `bash -i`
- download-and-exec patterns such as `curl ... | sh`
- `LD_PRELOAD`

### Keys

- `r` rescan
- `w` write report
- `↑/↓` scroll
- `b` back

## Container Diff

`Container Diff` uses Docker's container diff API to show filesystem changes since the container started.

It groups changes as:

- `added`
- `modified`
- `deleted`

It also flags suspicious paths such as:

- cron locations
- SSH key locations
- shell history files
- `.service` units
- `ld.so.preload`
- payloads in `/tmp` or `/dev/shm`

### Keys

- `r` reload
- `w` write report
- `↑/↓` scroll
- `b` back

## Timeline

`Timeline` reads recent Docker events for the selected container.

Typical event actions include:

- `create`
- `start`
- `die`
- `kill`
- `restart`
- `rename`

This is useful when you want to answer:

- Did the container restart unexpectedly?
- Was it killed recently?
- Was it recreated from a different image?

### Keys

- `r` reload
- `w` write report
- `↑/↓` scroll
- `b` back

## Combined Report Export

From `Threat Hunt`, `Container Diff`, or `Timeline`, press `w`.

BoneStack writes a combined container forensics report under:

```text
.bonestack/reports/<container>/
```

Files written:

- `forensics.json`
- `forensics.csv`
- `forensics.html`

The report includes:

- threat-hunt findings
- container diff changes
- timeline events

## Example Session

Example:

1. Open container `suspicious-web`
2. Press `f`
3. Open `Threat Hunt`
4. See:
   - `reverse-shell`
   - `cron-persistence`
   - `yara:BoneStackReverseShell`
5. Press `b`
6. Open `Container Diff`
7. See changes such as:
   - `/tmp/revshell.sh`
   - `/root/.ssh/authorized_keys`
8. Press `b`
9. Open `Timeline`
10. See:
   - `start`
   - `die`
   - `restart`
11. Press `w`

You now have one exported report with all three views combined.
