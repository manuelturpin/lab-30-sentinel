# Supply Chain Security Checklist — Sentinel

Covers npm, PyPI, Go, Cargo, RubyGems, and AI-specific supply chain risks.

## Vulnerable Dependencies

- [ ] **SC-VULN-001** | HIGH | All dependencies audited for known CVEs — automated scanning enabled (npm audit, pip-audit, cargo audit)

## Typosquatting

- [ ] **SC-TYPO-001** | HIGH | All package names verified against official registries — no character transpositions or similar-name packages

## Lockfile Integrity

- [ ] **SC-LOCK-001** | MEDIUM | Lockfiles generated, committed, and used in CI (npm ci, pip install --require-hashes)

## Lifecycle Scripts

- [ ] **SC-SCRIPT-001** | HIGH | All postinstall/preinstall scripts reviewed — suspicious scripts blocked with --ignore-scripts

## Version Pinning

- [ ] **SC-PIN-001** | MEDIUM | No wildcard (*) or "latest" version ranges — dependencies use exact or caret (^) pinning

## Dependency Confusion

- [ ] **SC-CONFUSION-001** | HIGH | Private package names reserved on public registries — scoped registries configured for internal packages

## AI Supply Chain

- [ ] **SC-AI-001** | CRITICAL | All AI skills, plugins, and MCP servers reviewed before installation — source code audited
- [ ] **SC-AI-002** | HIGH | ML models downloaded with hash verification — safetensors preferred over pickle formats

## Build Execution

- [ ] **SC-SETUP-001** | HIGH | Python setup.py files reviewed for arbitrary code execution — pyproject.toml preferred

## Namespace & Scope

- [ ] **SC-SCOPE-001** | MEDIUM | npm scoped packages verified against known organizations — suspicious scopes flagged

## Integrity Verification

- [ ] **SC-INTEGRITY-001** | MEDIUM | Dependencies installed with integrity checks — no curl-pipe-to-shell installations
