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
- **RAG (ChromaDB)** : 3 collections — securite (36 804 docs), RAG expertise (100 docs), evolve intel (210 docs)
- **MCP Server** : 3 outils (scan-dependencies, scan-headers, generate-sbom) — les 4 outils locaux ont ete supprimes Session 12 (2026-03-15), code nettoye T2 audit 2026-04-21 (voir docs/adr/2026-04-21-mcp-tools-removal.md)
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

## Workflow de synchronisation

Ce projet vit en **3 emplacements** qui doivent rester synchronises. Tout
desync casse silencieusement les skills en runtime — relire cette
section si un comportement parait bizarre apres une modif.

```
1. REPO SOURCE (ce dossier)
   /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/
   → C'est la source de verite. Toute modif commence ici.
   → Git repo: https://github.com/manuelturpin/lab-30-sentinel.git

2. DEPLOIEMENT LOCAL (runtime)
   ~/.claude/skills/sentinel-security/          → Skills (SKILL.md + 12 agents + _protocol.md)
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
| `skills/security/SKILL.md`      | `~/.claude/skills/sentinel-security/SKILL.md`    |
| `skills/security/agents/*.md`   | `~/.claude/skills/sentinel-security/agents/`     |
| `skills/sentinel-rag/`          | `~/.claude/skills/sentinel-rag/`                 |
| `skills/sentinel-evolve/`       | `~/.claude/skills/sentinel-evolve/`              |
| `knowledge-base/`               | `~/.sentinel/knowledge-base/`           |
| `rag/`                           | `~/.sentinel/rag/` + re-index ChromaDB  |
| `mcp-servers/`                   | `~/.sentinel/mcp-servers/` + build      |
| `reports/`, `config/`, `scripts/`, `tests/`, `crons/` | `~/.sentinel/` |

### Regles importantes

- Editer uniquement dans le repo source — les edits directs dans
  `~/.claude/skills/sentinel-security/` sont ecrases au prochain `deploy.sh`
  (utile pour du test rapide, pas comme workflow permanent)
- Les paths dans SKILL.md et les agents sont absolus
  (`/Users/manuelturpin/.sentinel/...`) ; `deploy.sh` copie SKILL.md tel
  quel sans substitution
- Le MCP server sentinel-scanner reste installe meme si les agents ont
  bascule sur Read/Grep/Bash natifs pour le scan local — il sert encore
  pour `scan-dependencies` (OSV API) et `scan-headers` (HTTP GET)
- Apres modification de `knowledge-base/**/rules.json`, re-indexer le
  RAG : `python3 rag/indexer.py`

---

## MCP Tools — Natif vs MCP

Depuis la session 12 (2026-03-15), les agents utilisent les outils natifs de Claude Code pour le scanning local :

| Ancien MCP Tool  | Remplace par                                           | Raison                        |
|------------------|--------------------------------------------------------|-------------------------------|
| `scan-project`   | `Read` rules.json + `Grep` patterns                    | SUPPRIME T2 (2026-04-21)      |
| `scan-secrets`   | `Grep` avec regex secrets                              | SUPPRIME T2 (2026-04-21)      |
| `query-kb`       | `Bash ~/.sentinel/rag/.venv/bin/python3 rag/query.py`  | SUPPRIME T2 (2026-04-21)      |
| `query-cve`      | `Read` fichiers cache CVE JSON                         | SUPPRIME T2 (2026-04-21)      |
| `scan-dependencies` | **CONSERVE** (MCP)                                  | Appel reseau externe OSV API  |
| `scan-headers`   | **CONSERVE** (MCP) + SSRF guard (T3)                   | Appel reseau externe HTTP GET |
| `generate-sbom`  | **CONSERVE** (MCP)                                     | Utilitaire format SBOM CycloneDX |

## Statut

**Session 14 — Rule Quality Pipeline** (2026-04-14)

- **Phase 3** : `rule-tester.py` — valide les patterns LLM contre un corpus de test (7 fichiers vulnérables + 6 safe). Precision gate >=70% pour promotion "active"
- **Phase 4** : `feedback-loop.py` — 5 sous-commandes (seed, ingest, score, propagate, report). Confidence Bayesienne, propagation cross-domaine par CWE
- **Pipeline CVE integre dans `/sentinel-evolve auto`** : cve-sync → pattern-gen → rule-tester → feedback-loop
- **14 regles CVE actives** (patterns valides, precision >=70%), 5 needs-review, 37 no-matches
- **100 feedback entries** seedees, 7 regles avec confidence recalculee (0.47→0.85)
- **53 opportunites de propagation** cross-domaine detectees (686 patterns potentiels)
- `/sentinel-evolve` default sur mode `auto` (pipeline complet sans argument)

**Session 15 — Audit Remediation** (2026-04-21)

- **T1** : Runtime recovery — `scripts/install-crons.sh`, 4 crons installes, RAG venv deps completees (rank_bm25 + certifi), anthropic-intel refreshed (+54 entries)
- **T2** : Suppression effective des 4 MCP tools (scan-project, scan-secrets, query-kb, query-cve) — ADR `docs/adr/2026-04-21-mcp-tools-removal.md`, MCP expose 3 tools (scan-dependencies, scan-headers, generate-sbom)
- **T3** : SSRF guard `mcp-servers/.../src/utils/url-validator.ts` + `scripts/lib/url_guard.py`, model whitelist `{opus,sonnet,haiku}` dans `pattern-gen.py`, `tests/vulnerable-app/.env` renomme en `dummy-env.txt`

**Session 12 — MCP Bottleneck Elimination** (2026-03-15)

- Decision de supprimer 4 MCP tools redondants (scan-project, scan-secrets, query-kb, query-cve) — appliquee au code en T2 (2026-04-21)
- Agents utilisent Read/Grep/Bash natifs pour le scanning local
- Conservation de scan-dependencies, scan-headers, generate-sbom (appels reseau / utilitaire SBOM)
- RAG indexe 36 804 documents (130 regles domaine + 3390 CVE-rules + 32 515 NVD + 1560 OSV + 1035 GitHub + 8 standards)

---

**Last verified:** 2026-04-21 (audit complet — cf. `reports/audit-2026-04-21.md`)
**Verification cmd:** `bash scripts/verify-audit-closure.sh`

## Commandes

- `/sentinel-security` : Lancer un audit complet du projet courant
- `/sentinel-rag` : Expert RAG — diagnostic, optimisation, creation, evaluation
- `/sentinel-evolve` : Pipeline complet automatique (default: mode `auto`) — scan→CVE pipeline→analyze→recommend→apply→deploy→commit
- `/sentinel-evolve audit` : Audit Claude Code health (project, --all, --global)
- `bash scripts/deploy.sh` : Deployer sur la machine locale (OBLIGATOIRE apres chaque modif)
- `bash scripts/setup.sh` : Installer les dependances et outils externes
- `bash scripts/test-sentinel.sh` : Tester le systeme (structure, RAG, KB, templates)
- `bash tests/e2e-session10.sh` : Tests E2E (RAG queries, schema validation, error handling)
- `bash scripts/install-crons.sh` : Installer les 4 crons dans le crontab local (T1 audit)
- `bash scripts/verify-audit-closure.sh` : Verifier que les findings de l'audit 2026-04-21 sont fermes

> **Python** : les scripts RAG utilisent un venv a `~/.sentinel/rag/.venv/bin/python3` (sentence_transformers + chromadb + rank_bm25). Le deploy.sh le detecte automatiquement ; en CLI, preferer `~/.sentinel/rag/.venv/bin/python3` pour tout script touchant au RAG.

- `~/.sentinel/rag/.venv/bin/python3 scripts/cve-sync.py --days 90` : Sync CVE (NVD + OSV batch + GitHub + EPSS)
- `~/.sentinel/rag/.venv/bin/python3 scripts/pattern-gen.py --limit 50` : Generer patterns de detection pour CVE rules vides (claude -p, Max subscription)
- `~/.sentinel/rag/.venv/bin/python3 scripts/rule-tester.py` : Valider les patterns contre le corpus de test (precision gate 70%)
- `~/.sentinel/rag/.venv/bin/python3 scripts/feedback-loop.py report` : Stats feedback, confidence, propagation cross-domaine
- `~/.sentinel/rag/.venv/bin/python3 scripts/anthropic-sync.py` : Sync ecosysteme Anthropic (Claude Code, skills, SDKs, MCP)
- `~/.sentinel/rag/.venv/bin/python3 rag/indexer.py` : Re-indexer la KB dans ChromaDB
- `~/.sentinel/rag/.venv/bin/python3 rag/query.py --query "..." --domain all --limit 10` : Requete semantique KB

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
