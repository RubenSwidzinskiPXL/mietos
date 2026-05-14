# mietos

Mietos is a local-first desktop operator for authorized cybersecurity labs, internal audits, OSINT triage, and defensive investigation workflows.

It pairs a lightweight Rust/egui interface with a local OpenAI-compatible model endpoint and a Kali WSL command runner. The goal is not to make a large local model magically omniscient. The goal is to keep the model on a tight evidence loop: structured challenge intake, bounded tool execution, compact context, RAG memory, workflow lessons, and clear answer/finding cards.

## Intended Use

Use mietos only for systems you own, labs you are enrolled in, internal company audits you are explicitly authorized to perform, or defensive analysis of data you are allowed to inspect.

Do not use it to scan, exploit, brute force, persist on, disrupt, or exfiltrate from third-party systems without written authorization. The operator can run intrusive tools when configured by the user, so scope and consent are part of the workflow, not paperwork after the fact.

## What It Does

- Runs as a native Rust desktop app.
- Connects to a local OpenAI-compatible chat endpoint such as llama.cpp, Ollama-compatible proxies, LM Studio, or another local server.
- Streams Kali WSL command output into the app instead of opening random terminals.
- Provides structured workflows for recon, web assessment, SIEM/log investigation, OSINT, code audit, exploit-development labs, and defensive notes.
- Stores local memory in SQLite outside the repository by default.
- Uses compact context engineering so small-context local models can still work through longer investigations.
- Extracts answers, flags, findings, evidence, and lessons into separate views.

## Requirements

- Windows 10/11.
- Rust toolchain.
- WSL with a Kali Linux distro, default name `kali-linux`.
- A local OpenAI-compatible model server.
- Authorization for every target you run tools against.

## Quick Start

```powershell
git clone https://github.com/RubenSwidzinskiPXL/mietos.git
cd mietos
cargo run --release
```

Start your model server separately, then configure the endpoint in the Setup page.

Default endpoint:

```text
http://127.0.0.1:18080/v1/chat/completions
```

Default model name:

```text
local-cyber-model
```

For local llama.cpp, any OpenAI-compatible `/v1/chat/completions` server is fine. For Ollama, use a compatible endpoint or proxy that exposes chat completions.

## Basic Flow

1. Open Setup and confirm the model endpoint, model name, and Kali distro.
2. Use Check Kali to verify core tools.
3. Paste the authorized target, task text, and notes in Challenge.
4. Choose a bounded workflow such as Web Assessment, SIEM Investigation, OSINT Domain, or Smart Full Run.
5. Watch Operator for live command output and model trace.
6. Open Results for answer cards, flags, findings, and evidence.
7. Save useful lessons or documents to Memory when they should help future runs.

## TryHackMe And Lab Flow

Normal personal TryHackMe accounts usually do not have an API key. Paste the visible room/task text manually.

When using a VPN config from Windows inside Kali WSL, use a WSL path, for example:

```bash
openvpn /mnt/c/Users/Example/Downloads/lab-config.ovpn
```

Use this notes pattern:

```text
Authorized lab target only.
VPN connected: yes
Credentials found so far:
- none
Flags found so far:
- none
Useful paths/ports found so far:
- none
Do not assume answers without terminal evidence.
```

## Safety Model

Mietos is dual-use software. It is designed for authorized work and local labs.

Default public documentation treats the app as an operator assistant, not a permission slip. The app can execute commands as root inside Kali WSL because many lab tools require it. That also means the user is responsible for the target scope, network impact, and legal authority.

Recommended release posture:

- Start with passive or low-noise workflows.
- Prefer code audit, OSINT, SIEM/log analysis, and web assessment before exploit-oriented workflows.
- Use brute force, exploit, and privilege-escalation workflows only in lab or explicitly approved audit scopes.
- Keep runtime memory and evidence local. Do not publish `*.sqlite3`, runtime state files, scan logs, captures, or target notes.

## Memory And Data

Mietos stores memory in a local SQLite database. On Windows, the default path is under `%LOCALAPPDATA%\mietos\operator_memory.sqlite3`.

The repository ignores local databases, runtime state, generated evidence, and build outputs. Treat terminal output, flags, credentials, scan results, and customer notes as sensitive.

## Development

```powershell
cargo test -- --nocapture
cargo build --release
```

Before opening a pull request or publishing a release:

```powershell
git status --short
cargo test -- --nocapture
cargo build --release
```

## Documentation

- [Setup Guide](docs/SETUP.md)
- [Workflow Packs](docs/WORKFLOW_PACKS.md)
- [CI And Release Builds](docs/ci.md)
- [Release Builds](docs/RELEASES.md)
- [Sanitized UI Previews](docs/SCREENSHOTS.md)
- [Public Hardening Roadmap](docs/ROADMAP.md)

## UI Previews

These are sanitized mock screenshots for documentation only, not real target
evidence or captures from an assessment.

![Mock UI preview of the Setup page](docs/images/setup-preview.svg)
![Mock UI preview of the Challenge page](docs/images/challenge-preview.svg)
![Mock UI preview of the Operator page](docs/images/operator-preview.svg)
![Mock UI preview of the Results page](docs/images/results-preview.svg)
![Mock UI preview of the OSINT page](docs/images/osint-preview.svg)

## CI And Release Builds

GitHub Actions runs Rust formatting, tests, and a release build on pushes and pull requests. A separate manual Windows release workflow builds `mietos.exe`, zips it, and uploads the zip as a workflow artifact.

Release artifacts should contain only the built executable. Do not publish local memory databases, runtime state, scan logs, captures, credentials, flags, customer notes, or other investigation evidence.

See [docs/ci.md](docs/ci.md) for the workflow details and local preflight commands.

## Project Name

The project name is `mietos`.

Suggested GitHub repository name:

```text
mietos
```

Suggested tagline:

```text
Local-first security operator for authorized labs, audits, OSINT, and defensive investigations.
```

## Current Status

This is early software. It is useful as a local lab and audit assistant, but it is not a replacement for a professional tester, analyst, or incident responder. Local models can miss obvious paths, hallucinate, or choose weak next steps. The app is built to make that visible through evidence, traces, bounded commands, and repeatable workflows.

## License

MIT. See [LICENSE](LICENSE).
