# Lab-30 Sentinel — Session 11 Handoff : Hardening + Live Validation

## Context

Sessions 1-10 completees (`0e07285`, tag `session-10-complete`). Sentinel est deploye en production :
- Skill `/security` global dans `~/.claude/skills/security/`
- Runtime dans `~/.sentinel/` (KB, RAG, MCP, reports)
- MCP server `sentinel-scanner` enregistre globalement (stdio, connected)
- Script `deploy.sh` pour deploiement local et VPS

## Etat actuel du systeme

### Composants

| Composant | Etat | Chiffres |
|-----------|------|----------|
| Skill `/security` | Deploye global | `~/.claude/skills/security/SKILL.md` |
| Agents | 12 + 1 protocol | `~/.claude/skills/security/agents/` |
| MCP Server | Build OK, Connected | 6 tools, `sentinel-scanner` |
| Knowledge Base | 115 regles manuelles | 11 domaines (6 static-sites ajoutees en S10) |
| RAG (ChromaDB) | 2604 docs indexes | 115 regles + 2273 NVD + 94 standards |
| CVE Feed | 2273 NVD + EPSS | OSV: 0, GitHub: 0 (pas de token) |
| Stack Detector | 48+ regles | Shallow recursion (2 niveaux, 70% confidence) |
| Tests | 58 checks (31+27) | 0 echecs |
| Deploy | Script operationnel | Local + VPS (`--remote`) |

### Resultats de validation E2E (Session 10)

**Target A — `tests/vulnerable-app/`:**
- Stack: nodejs + dotenv → 5 agents (web, api, cors, supply-chain, data-privacy)
- `scan-project`: 11 findings (3C/4H/4M) en 14ms
- `scan-secrets`: 3 secrets (2 connection_string, 1 api_key), tous redactes
- SARIF 2.1.0: 1 run, 11 results — genere correctement

**Target B — Sentinel self-scan:**
- Stack: claude-skills(100%), claude-code(100%), nodejs(70%), typescript(70%), dotenv(70%)
- Shallow recursion a detecte `package.json`/`tsconfig.json` dans `mcp-servers/sentinel-scanner/`
- 13 findings (3C/10H) — principalement LLM-MCP-002 (SKILL.md override) et SC-* (supply chain)

### Points resolus en Session 10

- [x] RAG re-indexe : 231 → 2604 documents (NVD, standards, static-sites)
- [x] `_flatten_nested()` dans indexer.py pour NVD/standards/GitHub
- [x] Error handling sur scan-project, scan-secrets, scan-dependencies
- [x] query.py: check ChromaDB dir, ImportError handling
- [x] Stack detector: poetry.lock, uv.lock, openapi.yaml, swagger.json
- [x] Stack detector: shallow recursion (2 niveaux)
- [x] Static-sites: 6 nouvelles regles (headers, CSP, redirect, exposure, HTTPS, SRI)
- [x] SKILL.md: edge cases (0 agents, all fail, agent success count)
- [x] Test suite complete: 31 systeme + 27 E2E
- [x] Deploiement global: deploy.sh (local + VPS)

---

## Chantier 1 : Live `/security` Validation (30 min)

**Objectif** : Executer le vrai skill `/security` (pas juste les tools individuels) sur des projets reels et valider le flow orchestrateur complet.

### Sous-taches

- [ ] Ouvrir un nouveau terminal Claude Code dans `tests/vulnerable-app/`
- [ ] Executer `/security` — verifier le flow complet :
  - Stack detection → agent dispatch → collect → aggregate → score → report
  - 3 rapports generes dans `~/.sentinel/reports/archive/`
  - SARIF valide, SBOM present, Markdown lisible
- [ ] Executer `/security` sur un projet reel (ex: un autre lab ou un side project)
- [ ] Documenter les bugs/ajustements dans les findings

### Bugs potentiels a surveiller

- Paths dans SKILL.md : les `sed` du deploy.sh ont-ils bien converti tous les chemins ?
- Les agents trouvent-ils `_protocol.md` et leurs fichiers `.md` ?
- Le MCP server repond-il correctement quand appele par les agents ?

---

## Chantier 2 : Peupler OSV + GitHub Advisories (20 min)

**Objectif** : Les caches OSV et GitHub sont vides. Les peupler pour enrichir les resultats.

### Sous-taches

- [ ] **OSV** : Verifier que le cron `cve-sync` peuple `osv-cache.json` (l'API est gratuite, pas de token)
  - Si le script existe : `python3 scripts/cve-sync.py` (ou dry-run)
  - Sinon : creer un script minimal qui query `https://api.osv.dev/v1/query` pour les ecosystemes npm, PyPI, Go
- [ ] **GitHub Advisories** : Necessite `GITHUB_TOKEN`
  - Documenter la config dans `CLAUDE.md` ou `config/`
  - Tester avec token : `GITHUB_TOKEN=xxx python3 scripts/cve-sync.py`
- [ ] Re-indexer le RAG apres peuplement
- [ ] Verifier que `query-cve` MCP tool retourne des resultats OSV

---

## Chantier 3 : Ameliorations Skill Flow (45 min)

**Objectif** : Ameliorer l'orchestrateur `/security` base sur les retours du Chantier 1.

### Sous-taches possibles (selon les bugs decouverts)

- [ ] **Timeout agents** : Les agents n'ont pas de timeout — si un agent bloque, tout bloque
  - Ajouter un timeout raisonnable (2-3 min par agent) dans SKILL.md
- [ ] **Rapport de synthese** : Le rapport MD pourrait inclure :
  - Duree totale du scan
  - Liste des agents dispatches vs reussis
  - Top 5 findings par severite composite
- [ ] **Delta report** : Comparer avec le dernier scan du meme projet
  - Nouvelles vulnerabilites, resolues, inchangees
  - Necessiterait un diff SARIF
- [ ] **Filtrage false positives** : Le self-scan trouve LLM-MCP-002 sur des docs/plans MD
  - Les regles LLM devraient exclure `docs/`, `plans/`, `*.md` dans les repertoires non-skill
- [ ] **Configuration par projet** : Ajouter un `.sentinel.json` optionnel
  - Exclure des domaines, agents, ou patterns
  - Override de severite pour les faux positifs connus

---

## Chantier 4 : VPS Deployment + Test (20 min)

**Objectif** : Deployer sur le VPS et verifier que tout fonctionne.

### Sous-taches

- [ ] Verifier les pre-requis VPS : `node`, `python3`, `pip install sentence-transformers chromadb`
- [ ] Executer `bash scripts/deploy.sh --remote user@vps`
- [ ] SSH sur le VPS, verifier :
  - `claude mcp list` montre `sentinel-scanner: Connected`
  - `python3 ~/.sentinel/rag/query.py --query "SQL injection" --limit 3` retourne des resultats
  - `/security` fonctionne dans un projet test
- [ ] Documenter la procedure dans `docs/deployment.md`

---

## Chantier 5 : Documentation + Polish Final (15 min)

### Sous-taches

- [ ] Mettre a jour `docs/roadmap.md` — Sessions 10-11 Done
- [ ] Creer `docs/deployment.md` — Guide complet (local, VPS, pre-requis, troubleshooting)
- [ ] Mettre a jour `CLAUDE.md` avec nouvelles metriques
- [ ] Commit + tag `session-11-complete`

---

## Ordre d'execution

```
Chantier 1 (live /security)
    ↓
Chantier 3 (ameliorations — selon bugs du C1)
    |
    |   en parallele
    ↓         ↓
Chantier 2   Chantier 4
(OSV/GitHub)  (VPS deploy)
    ↓         ↓
    └────┬────┘
         ↓
    Chantier 5 (docs + tag)
```

---

## Fichiers a creer

| Fichier | Type | Role |
|---------|------|------|
| `docs/deployment.md` | Markdown | Guide deploiement complet |
| `.sentinel.json` (schema) | JSON | Config par projet (optionnel) |

## Fichiers a modifier

| Fichier | Modification |
|---------|-------------|
| `skills/security/SKILL.md` | Timeouts agents, rapport ameliore |
| `knowledge-base/domains/llm-ai/rules.json` | Exclude docs/ pour LLM-MCP-002 |
| `docs/roadmap.md` | Sessions 10-11 Done |
| `CLAUDE.md` | Metriques finales post-session 11 |

---

## Metriques cibles fin Session 11

| Metrique | Actuel | Cible |
|----------|--------|-------|
| KB Rules | 115 manuelles | 115+ (corrections FP) |
| RAG Documents | 2604 | 2604+ (OSV/GitHub si peuple) |
| CVE Sources | NVD seul | NVD + OSV + GitHub |
| `/security` live tests | 0 | 2+ projets valides |
| Deploy targets | local | local + VPS |
| Tests | 58 | 58+ |

## Chemins de deploiement

```
Dev (source):    ~/Desktop/bonsai974/claude/lab/lab-30-sentinel/
Local (prod):    ~/.sentinel/ + ~/.claude/skills/security/
VPS (prod):      ~/.sentinel/ + ~/.claude/skills/security/ (via deploy.sh --remote)
```

## Verification finale

- [ ] `/security` fonctionne sur un projet reel (pas juste vulnerable-app)
- [ ] MCP `sentinel-scanner` repond dans toutes les sessions Claude Code
- [ ] VPS deploye et fonctionnel
- [ ] `docs/deployment.md` complet
- [ ] Tag `session-11-complete`
