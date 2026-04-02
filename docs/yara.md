# YARA Guide

## What YARA Is

YARA is a pattern-matching tool commonly used in malware analysis and threat hunting.

The short version:

- antivirus products often look for signatures
- YARA lets you define your own signatures as rules
- those rules match text or binary patterns in files

In BoneStack, YARA is used only as a defensive scanner.

BoneStack does not use YARA to attack anything. It uses YARA to scan suspicious files collected from a running container and add those matches to the `Threat Hunt` results.

## What BoneStack Uses YARA For

BoneStack currently ships with built-in defensive YARA rules for:

- reverse shell strings
- download-and-exec patterns
- `LD_PRELOAD`
- encoded payload hints
- SSH key drops
- cron persistence

If the `yara` binary exists on your machine, BoneStack will try to run those rules automatically during `Threat Hunt`.

If `yara` is not installed, BoneStack still works. The threat hunt just falls back to the built-in heuristic scan and shows that YARA is unavailable.

## Install YARA

Examples:

### macOS with Homebrew

```bash
brew install yara
```

### Debian or Ubuntu

```bash
sudo apt-get update
sudo apt-get install yara
```

### Verify

```bash
yara --version
```

## How BoneStack Runs YARA

BoneStack does this at a high level:

1. identify suspicious files in the container
2. read a limited amount of content from those files
3. write temporary local copies
4. run bundled YARA rules on those temporary files
5. map the YARA matches back to the original container paths

That means the output you see in the TUI still points to container paths such as:

```text
/tmp/revshell.sh
/root/.ssh/authorized_keys
/etc/cron.d/backdoor
```

## Example: Using Threat Hunt With YARA

Build and run:

```bash
go build -o bonestack ./cmd/bonestack/main.go
./bonestack
```

Then:

1. Open `View Containers`
2. Select a container
3. Press `f`
4. Select `Threat Hunt`

If YARA is installed, the status line may look like:

```text
Threat hunt completed. 4 findings across 3 categories. YARA matched 2 files.
```

You may then see findings such as:

```text
[HIGH] yara:BoneStackReverseShell
    /tmp/revshell.sh
    YARA rule matched: BoneStackReverseShell

[MEDIUM] yara:BoneStackSSHKeyDrop
    /root/.ssh/authorized_keys
    YARA rule matched: BoneStackSSHKeyDrop
```

## Example: Running YARA Yourself

If you want to understand YARA outside BoneStack, this is a minimal example.

Create a rule file:

```yar
rule ReverseShellExample {
  strings:
    $a = "nc -e"
    $b = "/dev/tcp/"
    $c = "bash -i"
  condition:
    any of them
}
```

Scan a file:

```bash
yara reverse-shell.yar suspicious.sh
```

If the file matches, YARA prints the rule name and file path:

```text
ReverseShellExample suspicious.sh
```

## What To Look For In Results

Useful YARA matches are usually:

- high-confidence strings that should not exist in a normal app container
- repeated matches across temp files, cron files, or startup scripts
- matches that agree with `Threat Hunt` or `Container Diff`

Example of a strong signal:

- `Threat Hunt` shows `reverse-shell`
- `Container Diff` shows `/tmp/revshell.sh`
- YARA matches `BoneStackReverseShell`
- `Timeline` shows a restart shortly before the file appeared

That combination is much more useful than a single match by itself.

## Current Limitation

BoneStack currently uses bundled built-in YARA rules only.

The next improvement would be support for:

- user-supplied YARA rule files
- per-project rule sets
- report output that shows exact matched rule names more prominently
