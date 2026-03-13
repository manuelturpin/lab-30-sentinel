# Sentinel Design Document

**Date**: 2026-03-13
**Status**: Session 1 Complete

## Overview

Sentinel is a comprehensive AI-powered cybersecurity auditing system for Claude Code. It provides automated security scanning across 12 domains via a single `/security` skill.

## Session 1 Deliverables (Complete)

- [x] Directory structure created
- [x] CLAUDE.md project documentation
- [x] SKILL.md orchestrator with full workflow
- [x] Stack detector (TypeScript) with 30+ indicator rules
- [x] 12 agent skeletons with domain-specific checklists
- [x] MCP Server skeleton with 6 tools
- [x] SARIF generator, SBOM generator, risk scorer utilities
- [x] Knowledge Base structure with OWASP/MITRE/CWE standards
- [x] RAG indexer skeleton (Python/ChromaDB)
- [x] External tool wrappers (Trivy, Semgrep, Nuclei, OSV-Scanner)
- [x] Cron definitions
- [x] Report templates
- [x] Setup and test scripts

## Session 2 Deliverables (Complete)

- [x] Web-app rules.json — 22 rules covering all OWASP Web Top 10 2025 categories
- [x] API rules.json — 14 rules covering all OWASP API Top 10 2023 categories
- [x] XSS detection patterns (8 patterns: DOM, React, Vue, Svelte, Angular, template)
- [x] SQLi detection patterns (6 patterns: JS concat, template, ORM raw, Python, Ruby, NoSQL)
- [x] CSRF detection patterns (4 patterns: missing tokens, cookies, forms)
- [x] Injection detection patterns (9 patterns: command, template, LDAP, XPath, header, SSRF, prototype pollution)
- [x] BOLA detection patterns (4 patterns: direct access, enumeration, list exposure)
- [x] SSRF detection patterns (4 patterns: fetch, axios, redirect, cloud metadata)
- [x] Mass assignment patterns (3 patterns: JS spread, Django, Rails)
- [x] OWASP Web Top 10 2025 full mapping (owasp-top10-2025.json)
- [x] OWASP API Top 10 2023 full mapping (owasp-api-top10-2023.json)
- [x] Web-app checklist with 22 rule references
- [x] API checklist with all 10 categories

**Totals**: 36 rules, 38 detection patterns, 2 OWASP mappings, 2 checklists

## Next: Session 3 — Knowledge Base LLM/AI + Supply Chain

Populate `knowledge-base/domains/llm-ai/` and `knowledge-base/domains/supply-chain/` with rules for OWASP LLM Top 10 2025, MITRE ATLAS, and supply chain attack patterns.
