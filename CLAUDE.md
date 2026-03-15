# Lab-30 Sentinel — Systeme Complet de Cybersecurite IA

## Projet

Sentinel est un systeme de cybersecurite IA pour Claude Code. Il audite la securite de n'importe quel projet (web, mobile, API, DB, infra, SaaS, skills IA) via un skill orchestrateur `/security` qui detecte le stack, dispatche des agents specialises en parallele, consulte une Knowledge Base enrichie par RAG, et produit un rapport SARIF consolide avec scoring CVSS v4 + EPSS et remediations.

## Architecture

- **Skill `/security`** : Point d'entree — detecte le stack, dispatche les agents, agrege les resultats
- **12 Agents specialises** : web, api, llm-ai, mobile, infra, supply-chain, db, data-privacy, websocket, cors, ssl-tls, static-site
- **Knowledge Base** : Regles JSON machine-readable par domaine, mappees aux standards OWASP/MITRE/CWE
- **RAG (ChromaDB)** : Recherche semantique sur les regles et CVE
- **MCP Server** : 2 outils reseau (scan-dependencies, scan-headers) — les 4 outils locaux ont ete remplaces par Read/Grep/Bash natifs
- **Crons** : Veille automatisee CVE, re-scan, mise a jour KB

## Standards couverts

OWASP Top 10 Web 2025, API 2023, LLM 2025, Mobile 2024 | MITRE ATLAS | NIST AI RMF | CWE Top 25 | CVSS v4 | EPSS | SARIF 2.1.0 | CycloneDX

## Conventions

- Les regles de la KB sont en JSON avec le schema defini dans le plan (id, severity, cvss_v4, category, detect.patterns, remediation, standards)
- Les rapports sont en format SARIF 2.1.0
- Le MCP Server est en TypeScript
- Le RAG utilise ChromaDB avec Python
- Les agents sont des fichiers Markdown dans skills/security/agents/

---

## WORKFLOW DE SYNCHRONISATION (CRITIQUE)

Ce projet existe en **3 emplacements** qui doivent rester synchronises :

```
1. REPO SOURCE (ce dossier)
   /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/
   → C'est la source de verite. Toute modif commence ici.
   → Git repo: https://github.com/manuelturpin/lab-30-sentinel.git

2. DEPLOIEMENT LOCAL (runtime)
   ~/.claude/skills/security/          → Skills (SKILL.md + 12 agents + _protocol.md)
   ~/.sentinel/                        → Runtime (KB, RAG, MCP server, reports, scripts, tests)

3. GITHUB REMOTE
   origin/main
```

### Apres toute modification dans ce dossier :

```bash
# 1. Commit + push vers GitHub
git add <fichiers modifies>
git commit -m "description"
git push

# 2. Deployer sur la machine locale
bash scripts/deploy.sh
```

### Ce que fait `deploy.sh` :

| Source (repo)                    | Destination (local)                     |
|----------------------------------|-----------------------------------------|
| `skills/security/SKILL.md`      | `~/.claude/skills/security/SKILL.md`    |
| `skills/security/agents/*.md`   | `~/.claude/skills/security/agents/`     |
| `knowledge-base/`               | `~/.sentinel/knowledge-base/`           |
| `rag/`                           | `~/.sentinel/rag/` + re-index ChromaDB  |
| `mcp-servers/`                   | `~/.sentinel/mcp-servers/` + build      |
| `reports/`, `config/`, `scripts/`, `tests/`, `crons/` | `~/.sentinel/` |

### Regles importantes

- **Ne JAMAIS editer directement dans `~/.claude/skills/security/`** sans repercuter dans le repo — sinon le prochain `deploy.sh` ecrasera les changements
- **Les paths dans SKILL.md et les agents sont absolus** (`/Users/manuelturpin/.sentinel/...`). Le `deploy.sh` copie le SKILL.md tel quel (pas de sed)
- **Le MCP server sentinel-scanner reste installe** meme si les agents ne l'utilisent plus pour scan-project/scan-secrets/query-kb/query-cve — il est toujours necessaire pour `scan-dependencies` (OSV API) et `scan-headers` (HTTP GET)
- **Apres modif des rules.json** dans `knowledge-base/`, il faut re-indexer le RAG : `python3 rag/indexer.py`

---

## MCP Tools — Natif vs MCP

Depuis la session 12 (2026-03-15), les agents utilisent les outils natifs de Claude Code pour le scanning local :

| Ancien MCP Tool  | Remplace par                                           | Raison                        |
|------------------|--------------------------------------------------------|-------------------------------|
| `scan-project`   | `Read` rules.json + `Grep` patterns                   | Elimine serialisation MCP     |
| `scan-secrets`   | `Grep` avec regex secrets                              | Elimine serialisation MCP     |
| `query-kb`       | `Bash` python3 rag/query.py                            | Elimine serialisation MCP     |
| `query-cve`      | `Read` fichiers cache CVE JSON                         | Elimine serialisation MCP     |
| `scan-dependencies` | **CONSERVE** (MCP)                                  | Appel reseau externe OSV API  |
| `scan-headers`   | **CONSERVE** (MCP)                                     | Appel reseau externe HTTP GET |

## Statut

**Session 12 — MCP Bottleneck Elimination** (2026-03-15)

- Suppression de 4 MCP tools redondants (scan-project, scan-secrets, query-kb, query-cve)
- Agents utilisent Read/Grep/Bash natifs pour le scanning local
- Conservation de scan-dependencies et scan-headers (appels reseau)
- deploy.sh corrige (plus de double-path sed)
- RAG indexe 4088 documents (115 regles domaine + 2273 NVD CVE + 1484 OSV + 100 GitHub + 94 standards)
- Tests systeme : `bash scripts/test-sentinel.sh` — 31 checks
- Tests E2E : `bash tests/e2e-session10.sh` — 27 checks

## Commandes

- `/security` : Lancer un audit complet du projet courant
- `bash scripts/deploy.sh` : Deployer sur la machine locale (OBLIGATOIRE apres chaque modif)
- `bash scripts/setup.sh` : Installer les dependances et outils externes
- `bash scripts/test-sentinel.sh` : Tester le systeme (structure, RAG, KB, templates)
- `bash tests/e2e-session10.sh` : Tests E2E (RAG queries, schema validation, error handling)
- `python3 scripts/cve-sync.py --days 90` : Sync CVE (NVD + OSV batch + GitHub + EPSS)
- `python3 rag/indexer.py` : Re-indexer la KB dans ChromaDB
- `python3 rag/query.py --query "..." --domain all --limit 10` : Requete semantique KB

## Configuration projet

Creer un fichier `.sentinel.json` a la racine du projet cible pour personnaliser l'audit :

```json
{
  "exclude_agents": ["mobile-audit"],
  "exclude_paths": ["vendor/", "third-party/"],
  "false_positives": [{"rule_id": "LLM-MCP-002", "file": "docs/**"}],
  "severity_overrides": {"LLM-MCP-002": "INFO"}
}
```

## Variables d'environnement

- `GITHUB_TOKEN` : Token GitHub pour sync des Security Advisories (optionnel, sans token = 60 req/h)
- `NVD_API_KEY` : Cle API NVD pour rate limit plus eleve (optionnel)

## Structure cle

```
skills/security/SKILL.md          — Skill orchestrateur
skills/security/agents/*.md       — 12 agents specialises + _protocol.md
knowledge-base/domains/*/         — Regles par domaine (115 regles)
knowledge-base/cve-feed/          — Caches NVD/OSV/GitHub (2273 CVE)
knowledge-base/standards/         — OWASP, MITRE, CWE, NIST (94 items)
mcp-servers/sentinel-scanner/     — MCP Server TypeScript (2 tools actifs)
rag/                              — RAG ChromaDB (4088 docs indexes)
scripts/deploy.sh                 — Script de deploiement local
crons/                            — Taches automatisees
reports/                          — Templates et archives
tests/                            — E2E tests, vulnerable-app
```
