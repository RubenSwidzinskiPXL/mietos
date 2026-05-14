# Release Builds

Mietos currently publishes source code and supports manual Windows artifact builds through GitHub Actions.

## Manual Release Artifact

1. Open the GitHub repository.
2. Go to Actions.
3. Select Windows Release Build.
4. Run the workflow.
5. Download the uploaded artifact zip.

The artifact contains:

```text
mietos.exe
```

It does not include:

- runtime memory databases,
- model weights,
- scan logs,
- packet captures,
- VPN configs,
- challenge flags,
- credentials,
- customer notes.

## Local Release Build

```powershell
cargo build --locked --release
```

The executable will be:

```text
target\release\mietos.exe
```

## Pre-Release Checklist

Before tagging a release:

```powershell
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo build --locked --release
git status --short --ignored
```

Confirm that ignored files include only expected local build output such as `target/`.

## Versioning

Until the app reaches a stable operator model, use `0.x.y` versions:

- `0.x.0` for meaningful feature batches,
- `0.x.y` for fixes and docs.
