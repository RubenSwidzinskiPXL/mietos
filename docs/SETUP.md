# Setup Guide

This guide assumes Windows 10/11, WSL, Kali Linux, Rust, and a local OpenAI-compatible model endpoint.

## 1. Install Rust

Install Rust from <https://rustup.rs/>, then verify:

```powershell
cargo --version
rustc --version
```

## 2. Prepare Kali WSL

Install or import a Kali WSL distro. Mietos defaults to:

```text
kali-linux
```

Use the Setup page to change the distro name if yours is different.

Inside Kali, install the tools you need for your authorized scope. Mietos can check/install common packs from the Tools and OSINT pages, but it is still your environment.

## 3. Start A Local Model Server

Start a local model server that exposes an OpenAI-compatible endpoint:

```text
http://127.0.0.1:18080/v1/chat/completions
```

Set the model name in Setup. The default public placeholder is:

```text
local-cyber-model
```

## 4. Run Mietos

```powershell
cargo run --release
```

Open Setup and confirm:

- Model endpoint
- Model name
- Kali WSL distro
- Safety mode
- Memory DB path

Click Save Settings to write `%LOCALAPPDATA%\mietos\mietos.toml`.

## 5. Choose Safety Mode

- Passive: OSINT, metadata, defensive notes, and low-noise work.
- Authorized Lab: CTF/lab workflows such as recon, exploit-development labs, and privilege escalation practice.
- Internal Audit: approved company audit work with bounded active checks, excluding lab-only exploit/privesc flows.
- Full Control: advanced mode for explicitly approved high-risk workflows.

You must also confirm that you are authorized to assess the target before active workflows run.
