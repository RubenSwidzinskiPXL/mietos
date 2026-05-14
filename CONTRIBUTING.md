# Contributing

Thanks for helping improve mietos.

## Ground Rules

Mietos is for authorized labs, internal audits, OSINT triage, and defensive investigations. Contributions should make scoped work safer, clearer, more reproducible, and easier to audit.

Do not contribute changes whose main purpose is stealth, evasion, persistence, credential theft, destructive behavior, or unauthorized access.

## Before A Pull Request

Run:

```powershell
cargo test -- --nocapture
cargo build --release
```

Also check:

```powershell
git status --short
```

Do not commit:

- `target/` or `target-*/`
- `*.sqlite3`, `*.db`
- runtime state files
- scan logs, packet captures, flags, credentials, customer notes, or challenge answers
- local model paths or private VPN configs

## Code Style

- Keep workflows bounded with timeouts.
- Prefer structured labels such as `[mietos-finding]` and `[mietos-answer]` so Results can extract evidence.
- Keep model prompts compact and evidence-focused.
- Add tests for parser, planner, workflow, and safety behavior.
- Treat Windows/Kali assumptions explicitly.

## Dual-Use Review Checklist

For any workflow that can touch a network target:

- Is the intended authorized use clear?
- Is it bounded by timeout, rate, or thread count?
- Does it avoid broad or noisy defaults?
- Does it produce evidence instead of hidden state?
- Does it fail closed when required target/scope data is missing?

For any workflow that can use brute force, exploit, or privilege escalation tooling:

- Is it lab or explicitly authorized audit scoped?
- Is it opt-in through user action?
- Are outputs treated as sensitive?

## Tests

New behavior needs tests. Bug fixes should include a regression test that fails before the fix and passes after it.
