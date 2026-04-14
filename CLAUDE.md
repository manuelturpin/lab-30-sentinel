# Lab-30 Sentinel — Systeme Complet de Cybersecurite IA

## Projet

Sentinel est un systeme de cybersecurite IA pour Claude Code. Il regroupe trois skills dans le namespace sentinel : `/sentinel-security` qui audite la securite de n'importe quel projet (web, mobile, API, DB, infra, SaaS, skills IA) en detectant le stack, dispatchant des agents specialises en parallele, consultant une Knowledge Base enrichie par RAG, et produisant un rapport SARIF consolide avec scoring CVSS v4 + EPSS et remediations ; `/sentinel-rag` qui est un expert RAG autonome pour creer, diagnostiquer, optimiser et maintenir les systemes RAG ; et `/sentinel-evolve` qui est un meta-skill d'intelligence evolutive surveillant l'ecosysteme Anthropic (Claude Code, skills officiels, MCP, SDKs) pour detecter les opportunites d'optimisation et evoluer automatiquement les skills Sentinel.

## Architecture

- **Skill `/sentinel-security`** : Point d'entree — detecte le stack, dispatche les agents, agrege les resultats
- **Skill `/sentinel-rag`** : Expert RAG autonome — cree, diagnostique, optimise et maintient les systemes RAG avec sa propre base de connaissances
- **Skill `/sentinel-evolve`** : Meta-skill d'intelligence evolutive — surveille l'ecosysteme Anthropic, detecte les opportunites d'optimisation, produit des rapports EIR (Evolve Intelligence Report)
- **12 Agents specialises** : web, api, llm-ai, mobile, infra, supply-chain, db, data-privacy, websocket, cors, ssl-tls, static-site
- **Knowledge Base** : Regles JSON machine-readable par domaine, mappees aux standards OWASP/MITRE/CWE
- **Anthropic Intel** : Feature inventory + releases cache pour le suivi des capacites Claude Code
- **RAG (ChromaDB)** : 3 collections — securite (4088 docs), RAG expertise (100 docs), evolve intel (87 docs)
- **MCP Server** : 2 outils reseau (scan-dependencies, scan-headers) — les 4 outils locaux ont ete remplaces par Read/Grep/Bash natifs
- **Crons** : Veille automatisee CVE, re-scan, mise a jour KB, sync ecosysteme Anthropic (bi-hebdo)

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

**Session 14 — Rule Quality Pipeline** (2026-04-14)

- **Phase 3** : `rule-tester.py` — valide les patterns LLM contre un corpus de test (7 fichiers vulnérables + 6 safe). Precision gate >=70% pour promotion "active"
- **Phase 4** : `feedback-loop.py` — 5 sous-commandes (seed, ingest, score, propagate, report). Confidence Bayesienne, propagation cross-domaine par CWE
- **Pipeline CVE integre dans `/sentinel-evolve auto`** : cve-sync → pattern-gen → rule-tester → feedback-loop
- **14 regles CVE actives** (patterns valides, precision >=70%), 5 needs-review, 37 no-matches
- **100 feedback entries** seedees, 7 regles avec confidence recalculee (0.47→0.85)
- **53 opportunites de propagation** cross-domaine detectees (686 patterns potentiels)
- `/sentinel-evolve` default sur mode `auto` (pipeline complet sans argument)

**Session 12 — MCP Bottleneck Elimination** (2026-03-15)

- Suppression de 4 MCP tools redondants (scan-project, scan-secrets, query-kb, query-cve)
- Agents utilisent Read/Grep/Bash natifs pour le scanning local
- Conservation de scan-dependencies et scan-headers (appels reseau)
- RAG indexe 4088 documents (115 regles domaine + 2273 NVD CVE + 1484 OSV + 100 GitHub + 94 standards)

## Commandes

- `/sentinel-security` : Lancer un audit complet du projet courant
- `/sentinel-rag` : Expert RAG — diagnostic, optimisation, creation, evaluation
- `/sentinel-evolve` : Pipeline complet automatique (default: mode `auto`) — scan→CVE pipeline→analyze→recommend→apply→deploy→commit
- `/sentinel-evolve audit` : Audit Claude Code health (project, --all, --global)
- `bash scripts/deploy.sh` : Deployer sur la machine locale (OBLIGATOIRE apres chaque modif)
- `bash scripts/setup.sh` : Installer les dependances et outils externes
- `bash scripts/test-sentinel.sh` : Tester le systeme (structure, RAG, KB, templates)
- `bash tests/e2e-session10.sh` : Tests E2E (RAG queries, schema validation, error handling)
- `python3 scripts/cve-sync.py --days 90` : Sync CVE (NVD + OSV batch + GitHub + EPSS)
- `python3 scripts/pattern-gen.py --limit 50` : Generer patterns de detection pour CVE rules vides (claude -p, Max subscription)
- `python3 scripts/rule-tester.py` : Valider les patterns contre le corpus de test (precision gate 70%)
- `python3 scripts/feedback-loop.py report` : Stats feedback, confidence, propagation cross-domaine
- `python3 scripts/anthropic-sync.py` : Sync ecosysteme Anthropic (Claude Code, skills, SDKs, MCP)
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

- `GITHUB_TOKEN` : Token GitHub pour sync des Security Advisories ET Anthropic Sync (optionnel, sans token = 60 req/h)
- `NVD_API_KEY` : Cle API NVD pour rate limit plus eleve (optionnel)

## Structure cle

```
skills/security/SKILL.md              — Skill orchestrateur
skills/security/agents/*.md           — 12 agents specialises + _protocol.md
skills/sentinel-rag/SKILL.md          — Skill expert RAG
skills/sentinel-rag/knowledge/        — KB vectorielle du skill RAG (indexer, query, sources)
skills/sentinel-evolve/SKILL.md       — Skill meta-evolution
skills/sentinel-evolve/knowledge/     — KB intelligence evolutive (indexer, query, sources, ChromaDB)
knowledge-base/domains/*/             — Regles par domaine (115 curated + 3390 CVE)
knowledge-base/cve-feed/              — Caches NVD/OSV/GitHub (2273 CVE)
knowledge-base/feedback/              — Feedback TP/FP pour confidence scoring
knowledge-base/anthropic-intel/       — Feature inventory + releases cache ecosysteme Anthropic
knowledge-base/standards/             — OWASP, MITRE, CWE, NIST (94 items)
mcp-servers/sentinel-scanner/         — MCP Server TypeScript (2 tools actifs)
rag/                                  — RAG ChromaDB (4088 docs indexes)
scripts/deploy.sh                     — Script de deploiement local
scripts/pattern-gen.py                — Generation LLM de patterns (claude -p)
scripts/rule-tester.py                — Validation patterns (precision gate)
scripts/feedback-loop.py              — Feedback loop (seed, ingest, score, propagate, report)
scripts/anthropic-sync.py             — Pipeline sync ecosysteme Anthropic
crons/                                — Taches automatisees (4 crons)
reports/                              — Templates et archives
tests/fixtures/                       — Corpus de test vulnerable + safe (13 fichiers)
tests/vulnerable-app/                 — App intentionnellement vulnerable (E2E)
config/evolve-targets.json            — Skills cibles pour sentinel-evolve
```
