# Sentinel Design Document

**Date**: 2026-03-13
**Status**: Session 3 Complete

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

## Session 3 Deliverables (Complete)

- [x] LLM-AI rules.json — 16 rules covering all OWASP LLM Top 10 2025 categories
- [x] Supply Chain rules.json — 11 rules covering npm, PyPI, lockfiles, typosquatting, AI skills
- [x] Prompt injection patterns (7 patterns: direct, indirect, extraction, jailbreak, template)
- [x] Model poisoning patterns (5 patterns: training data, RAG, embedding, unsafe deserialization, revision pinning)
- [x] Excessive agency patterns (6 patterns: shell, filesystem, network, escalation, HITL, chaining)
- [x] RAG poisoning patterns (5 patterns: ingestion, embedding, access control, tenant, source integrity)
- [x] MCP tool poisoning patterns (5 patterns: exfiltration, hidden instructions, permissions, untrusted, shadow)
- [x] npm supply chain patterns (4 patterns: unpinned, lifecycle scripts, scopes, curl-pipe)
- [x] PyPI supply chain patterns (3 patterns: setup.py execution, namespace confusion, hash verification)
- [x] Skills/plugins patterns (5 patterns: exfiltration, override, malicious MCP, hidden text, persistence)
- [x] Typosquatting patterns (3 patterns: npm transpositions, PyPI transpositions, prefix/suffix)
- [x] OWASP LLM Top 10 2025 full mapping (owasp-llm-top10-2025.json)
- [x] MITRE ATLAS full technique tree (13 techniques, 12 tactics)
- [x] LLM-AI checklist with 16 rule references
- [x] Supply Chain checklist with 11 rule references
- [x] Updated standards/owasp-llm-2025.json with sentinel_rules mappings
- [x] Updated standards/mitre-atlas.json with complete techniques and sentinel_rules

**Totals**: 27 rules, 43 detection patterns, 1 OWASP mapping, 1 MITRE mapping, 2 checklists

**Cumulative (Sessions 1-3)**: 63 rules, 81 detection patterns, 3 OWASP mappings, 1 MITRE mapping, 4 checklists

## Session 4 — Knowledge Base Mobile + Infra + DB + Privacy (Done)

Populated all 4 remaining KB domains:

- [x] Mobile: 11 rules, 10 patterns, OWASP Mobile Top 10 2024 mapping, checklist
- [x] Infrastructure: 10 rules, 14 patterns (docker, kubernetes, secrets), checklist
- [x] Database: 8 rules, 8 patterns (nosql-injection, misconfig), checklist
- [x] Data Privacy: 8 rules, 9 patterns (pii-exposure, consent), checklist
- [x] OWASP Mobile Top 10 2024 mapping with full CWE mappings

**Totals**: 37 rules, 41 detection patterns, 1 OWASP mapping, 4 checklists

**Cumulative (Sessions 1-4)**: 100 rules, 122 detection patterns, 4 OWASP mappings, 1 MITRE mapping, 8 checklists

## Next: Session 5 — MCP Server Implementation

Implement the TypeScript MCP server that exposes scanning tools to Claude Code.
