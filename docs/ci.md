# CI And Release Builds

Mietos uses GitHub Actions to keep routine Rust checks repeatable while preserving the public safety framing for authorized labs, internal audits, OSINT, and defensive investigation workflows.

## Pull Request And Push CI

The `Rust CI` workflow runs on pushes to `main` or `master` and on pull requests.

It performs:

- `cargo fmt --all -- --check`
- `cargo test --locked --all-targets`
- `cargo build --locked --release`

The workflow currently runs on `windows-latest` because Mietos targets Windows desktop usage with Kali WSL integration.

## Manual Windows Release Build

The `Windows Release Build` workflow is started manually from the GitHub Actions tab with `workflow_dispatch`.

It builds the release executable with:

```powershell
cargo build --locked --release
```

Then it copies `target\release\mietos.exe` into a `dist` folder, creates a zip archive, and uploads that zip as a workflow artifact.

Release artifacts are build outputs only. Do not package local runtime memory, SQLite databases, scan logs, captures, flags, credentials, customer notes, or other investigation evidence.

## Local Preflight

Before opening a pull request or running a manual release build, run:

```powershell
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo build --locked --release
```
