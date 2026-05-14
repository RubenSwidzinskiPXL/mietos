# Mietos Public Hardening Roadmap

This roadmap tracks the first open-source hardening pass after the initial public release.

## Goals

- Make mietos safer to run by default.
- Make the codebase easier for contributors to understand.
- Add repeatable CI and release builds.
- Turn workflows into discoverable packs instead of a hidden monolith.
- Improve operator visibility: job state, terminal output, evidence, and release docs.

## Work Items

1. **Safety modes**
   - Add user-facing modes such as Passive, Authorized Lab, Internal Audit, and Full Control.
   - Gate higher-risk workflows behind explicit authorized scope.
   - Keep passive OSINT and local code-audit paths easy to reach.

2. **Architecture split**
   - Extract focused modules from the large app surface where low-risk.
   - Start with pure state/catalog/runtime helpers before moving UI views.

3. **Config file**
   - Add a local `mietos.toml` loader/saver for model endpoint, model name, Kali distro, memory path, and safety mode.
   - Keep defaults safe and portable.

4. **Runtime/job engine**
   - Track command label, status, timestamps, exit status, output bytes, and running count.
   - Preserve terminal streaming inside the app.

5. **Workflow packs**
   - Introduce a typed catalog for lab, web audit, OSINT, SIEM, and code-audit packs.
   - Document safety notes and default visibility for each pack.

6. **Docs and screenshots**
   - Add setup, first-run, OSINT, lab, and release documentation.
   - Add screenshot placeholders until polished images are available.

7. **CI**
   - Add GitHub Actions for formatting, tests, and release build checks.

8. **Release builds**
   - Add a manual workflow for Windows release artifacts.
   - Document how to download and run a release build.

## Commit Strategy

Each item should land as one or more focused commits. Push after each logical slice so the public repository stays updated and reviewable.
