# Workflow Packs

Workflow packs are typed groupings of existing workflows. They are the first step toward a future marketplace or plugin system without forcing every contributor to edit the full app surface.

The current catalog lives in `src/workflow_packs.rs`.

## Packs

### Core Lab

For enrolled CTF and training-lab work.

Includes recon, web enumeration, exploit pathing, web login, privilege escalation, deep privilege escalation, and full run.

### Web Audit

For authorized web application assessment.

Includes web enumeration, web assessment, vulnerability analysis, and deep web scanning.

### OSINT

For passive and low-impact public intelligence.

Includes domain surface, identity/brand, threat intel, metadata, and full OSINT run.

### SIEM

For defensive log investigation.

Includes Splunk-style SIEM investigation workflows.

### Code Audit

For local repository and defensive review.

Includes vulnerability analysis and defensive notes.

## Adding A Pack

1. Add a `WorkflowPack` entry in `src/workflow_packs.rs`.
2. Include a stable `id`, human `name`, one-sentence `summary`, workflow list, and safety notes.
3. Add or update tests proving:
   - the pack is listed,
   - it exposes at least one workflow,
   - safety notes mention authorization or scope.
4. Keep workflows bounded and evidence-producing.

Future work can use this catalog to drive UI filtering, pack selection, and external workflow manifests.
