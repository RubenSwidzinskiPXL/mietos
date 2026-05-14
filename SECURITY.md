# Security Policy

Mietos is dual-use cybersecurity software. Please report security issues in the project itself, abuse-enabling defaults, unsafe workflow behavior, or accidental data exposure risks.

## Supported Versions

The project is pre-1.0. Security fixes target the default branch until a release process exists.

## Reporting A Vulnerability

Open a private security advisory on GitHub if available. If private advisories are not enabled yet, open a minimal public issue that says a security report exists without publishing exploit details, secrets, customer data, or working abuse steps.

Please include:

- A concise description of the issue.
- Affected version or commit.
- Expected and actual behavior.
- Reproduction steps using a local lab or toy target.
- Impact and suggested mitigation.

## Responsible Use

Reports should avoid real third-party targets. Use local fixtures, owned systems, or intentionally vulnerable labs.

Do not submit:

- Stolen credentials, tokens, flags, or customer data.
- Exploit output from unauthorized systems.
- Requests to make the tool stealthier, more destructive, or harder to attribute.

## Scope

In scope:

- Command-injection bugs in mietos command construction.
- Unsafe defaults that can run intrusive actions without clear authorization.
- Memory or runtime files that leak sensitive data.
- Crashes or panics triggered by normal user input.
- Prompt/context bugs that bypass intended scope checks.

Out of scope:

- Vulnerabilities in third-party tools that mietos invokes.
- Model hallucinations that are not caused by mietos prompts, parsing, or UI behavior.
- Requests for unauthorized offensive capability.
