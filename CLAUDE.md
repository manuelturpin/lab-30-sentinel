# Lab-30 Sentinel — Systeme Complet de Cybersecurite IA

## Projet

Sentinel est un systeme de cybersecurite IA pour Claude Code. Il audite la securite de n'importe quel projet (web, mobile, API, DB, infra, SaaS, skills IA) via un skill orchestrateur `/security` qui detecte le stack, dispatche des agents specialises en parallele, consulte une Knowledge Base enrichie par RAG, et produit un rapport SARIF consolide avec scoring CVSS v4 + EPSS et remediations.

## Architecture

- **Skill `/security`** : Point d'entree — detecte le stack, dispatche les agents, agrege les resultats
- **12 Agents specialises** : web, api, llm-ai, mobile, infra, supply-chain, db, data-privacy, websocket, cors, ssl-tls, static-site
- **Knowledge Base** : Regles JSON machine-readable par domaine, mappees aux standards OWASP/MITRE/CWE
- **RAG (ChromaDB)** : Recherche semantique sur les regles et CVE
- **MCP Server** : Outils de scanning exposes a Claude Code
- **Crons** : Veille automatisee CVE, re-scan, mise a jour KB

## Standards couverts

OWASP Top 10 Web 2025, API 2023, LLM 2025, Mobile 2024 | MITRE ATLAS | NIST AI RMF | CWE Top 25 | CVSS v4 | EPSS | SARIF 2.1.0 | CycloneDX

## Conventions

- Les regles de la KB sont en JSON avec le schema defini dans le plan (id, severity, cvss_v4, category, detect.patterns, remediation, standards)
- Les rapports sont en format SARIF 2.1.0
- Le MCP Server est en TypeScript
- Le RAG utilise ChromaDB avec Python
- Les agents sont des fichiers Markdown dans skills/security/agents/

## Statut

**Session 10 — Production-ready** (2026-03-15)

- RAG indexe 2604 documents (115 regles domaine + 2273 NVD CVE + 94 standards)
- Tests systeme : `bash scripts/test-sentinel.sh` — 31 checks
- Tests E2E : `bash tests/e2e-session10.sh` — 27 checks
- MCP tools : error handling structuré sur les 6 outils
- Stack detector : 48+ regles d'indicateurs

## Commandes

- `/security` : Lancer un audit complet du projet courant
- `bash scripts/setup.sh` : Installer les dependances et outils externes
- `bash scripts/test-sentinel.sh` : Tester le systeme (structure, RAG, KB, templates)
- `bash tests/e2e-session10.sh` : Tests E2E (RAG queries, schema validation, error handling)
- `python3 rag/indexer.py` : Re-indexer la KB dans ChromaDB
- `python3 rag/query.py --query "..." --domain all --limit 10` : Requete semantique KB

## Structure cle

```
skills/security/SKILL.md          — Skill orchestrateur
skills/security/agents/*.md       — 12 agents specialises
knowledge-base/domains/*/         — Regles par domaine (115 regles)
knowledge-base/cve-feed/          — Caches NVD/OSV/GitHub (2273 CVE)
knowledge-base/standards/         — OWASP, MITRE, CWE, NIST (94 items)
mcp-servers/sentinel-scanner/     — MCP Server TypeScript (6 tools)
rag/                              — RAG ChromaDB (2604 docs indexes)
crons/                            — Taches automatisees
reports/                          — Templates et archives
tests/                            — E2E tests, vulnerable-app
```
