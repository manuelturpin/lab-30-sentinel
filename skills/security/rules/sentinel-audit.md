---
name: sentinel-audit-conventions
description: Enforces Sentinel security audit conventions — read-only mode, secret redaction, no commit of findings
paths:
  - "**"
---

# Sentinel Audit Conventions

When `/sentinel-security` is active or any Sentinel audit agent is running:

## Read-Only Mode
- Sentinel audits are **read-only** — never modify project files during a scan
- Use `disallowedTools: ["Write", "Edit", "NotebookEdit"]` for all audit agents
- If a remediation is needed, include it in the report — do not auto-fix

## Secret Redaction
- **Never** include actual secret values (API keys, passwords, tokens) in findings or reports
- Replace secrets with `[REDACTED]` in all finding descriptions
- Connection strings must have credentials masked: `postgres://[REDACTED]@host/db`

## Finding Integrity
- Do not commit raw scan findings to the project repository
- Reports are saved to `~/.sentinel/reports/archive/` only
- SARIF output goes to stdout in CI mode — never written to project files

## Conservative Severity
- Only mark CRITICAL if exploitation is trivial AND impact is severe
- When unsure, rate one level lower
- Minimum 70% confidence required before reporting a finding
