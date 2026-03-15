# Lab-30 Sentinel — Session 9 : Crons + Automated Monitoring

## Context

Sessions 1-8 complete (`7425144`, tag `session-8-complete`). Le systeme est fonctionnellement complet : 12 agents, 7 MCP tools, KB (100 rules), RAG (ChromaDB), SARIF enrichi, SBOM CycloneDX, report renderer, 31/31 E2E. Session 9 met en place l'automatisation : veille CVE, mise a jour KB/RAG, et re-scan projets.

## Etat actuel de l'infrastructure

### CVE Feed (`knowledge-base/cve-feed/`)

| Fichier | Etat | Role |
|---------|------|------|
| `sync-config.json` | Config prete | Sources (NVD, OSV, GitHub, EPSS), rate limits, ecosystems |
| `nvd-cache.json` | Vide `{}` | Cache NVD a peupler |
| `osv-cache.json` | Vide `{}` | Cache OSV a peupler |
| `github-advisories.json` | Vide `[]` | Cache GitHub Advisories a peupler |

**Jamais synchronise** (`last_sync: null`). Les endpoints API sont deja configures dans sync-config.json.

### RAG (`rag/`)

| Fichier | Etat | Role |
|---------|------|------|
| `config.json` | Operationnel | Collection `sentinel_kb`, model `all-MiniLM-L6-v2` |
| `indexer.py` | Operationnel | Indexation batch (500 docs), deduplication, metadata extraction |
| `query.py` | Operationnel | Interface CLI pour MCP server, filtrage par domaine |
| `chromadb/` | Peuple (231 docs) | Store vectoriel persistant |

### Cron specs (`crons/`)

| Fichier | Schedule | Etat |
|---------|----------|------|
| `cve-sync.md` | `0 6 * * *` (daily 6h) | Spec seulement, pas d'implementation |
| `kb-update.md` | `0 9 * * 1` (lundi 9h) | Spec seulement, pas d'implementation |
| `project-rescan.md` | `0 8 * * 1` (lundi 8h) | Spec seulement, pas d'implementation |

### Scripts existants (`scripts/`)

| Script | Role |
|--------|------|
| `setup.sh` | Bootstrap complet (npm, pip, tools externes) |
| `install-tools.sh` | Install trivy, semgrep, nuclei, osv-scanner, bearer, testssl, corscanner |
| `test-sentinel.sh` | Validation systeme (77 checks) |

---

## Chantier 1 : CVE Sync Script (45 min)

**Objectif** : Script Python qui synchronise les CVE depuis les 4 sources configurees.

**Creer** : `scripts/cve-sync.py`

### Sous-taches

- [ ] Lire la config depuis `knowledge-base/cve-feed/sync-config.json`
- [ ] Implementer le fetch NVD API 2.0 :
  - Endpoint : `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - Parametres : `lastModStartDate` / `lastModEndDate` (depuis last_sync)
  - Rate limit : 6000ms entre requetes (config)
  - Extraire : CVE ID, description, CVSS v4 score, CWE, affected products
  - Sauvegarder dans `nvd-cache.json` (merge, pas overwrite)
- [ ] Implementer le fetch OSV API :
  - Endpoint : `https://api.osv.dev/v1/query`
  - Pour chaque ecosystem tracke (npm, pypi, go, cargo, maven, rubygems)
  - Sauvegarder dans `osv-cache.json`
- [ ] Implementer le fetch GitHub Advisories :
  - Endpoint : `https://api.github.com/advisories`
  - Filtrer par ecosystem
  - Sauvegarder dans `github-advisories.json`
- [ ] Implementer le fetch EPSS :
  - Endpoint : `https://api.first.org/data/v1/epss`
  - Pour tous les CVE IDs caches
  - Enrichir les caches existants avec les scores EPSS
- [ ] Mettre a jour `last_sync` et `last_sync_status` dans sync-config.json
- [ ] Ajouter un mode `--dry-run` pour tester sans ecrire
- [ ] Ajouter logging structure (nombre de CVEs ajoutees/mises a jour par source)

### Contraintes

- Python 3 uniquement (pas de deps externes au-dela de `requests` — deja disponible)
- Gestion d'erreurs robuste : si une source echoue, continuer avec les autres
- Respecter les rate limits NVD (6s entre requetes, ou utiliser API key si disponible via env var `NVD_API_KEY`)
- Premier run : fetch les 30 derniers jours. Runs suivants : depuis last_sync.

### API Details (from sync-config.json)

```json
{
  "sources": {
    "nvd": { "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "rate_limit_ms": 6000 },
    "osv": { "url": "https://api.osv.dev/v1", "rate_limit_ms": 1000 },
    "github": { "url": "https://api.github.com/advisories", "rate_limit_ms": 1000 },
    "epss": { "url": "https://api.first.org/data/v1/epss", "rate_limit_ms": 1000 }
  },
  "ecosystems": ["npm", "pypi", "go", "cargo", "maven", "rubygems"],
  "cache": { "max_age_days": 7 }
}
```

---

## Chantier 2 : KB Update Script (30 min)

**Objectif** : Script qui enrichit les regles KB avec les nouveaux CVE et re-indexe ChromaDB.

**Creer** : `scripts/kb-update.py`

### Sous-taches

- [ ] Lire les caches CVE (`nvd-cache.json`, `osv-cache.json`, `github-advisories.json`)
- [ ] Pour chaque CVE, determiner le domaine KB correspondant (mapping ecosystem → domaine) :
  - npm/pypi/go/cargo/maven/rubygems → `supply-chain`
  - CVE affectant frameworks web (express, django, rails) → `web-app`
  - CVE affectant des DB (postgres, mysql, mongodb) → `database`
  - Autre → `supply-chain` (default)
- [ ] Generer des regles KB supplementaires pour les CVE critiques (CVSS >= 7.0) :
  - Format : meme schema que les regles existantes (`knowledge-base/domains/*/rules.json`)
  - ID : `CVE-YYYY-NNNNN` (l'ID CVE lui-meme)
  - detect.patterns : regex basee sur le package/version affecte
- [ ] Sauvegarder les nouvelles regles dans `knowledge-base/domains/{domain}/cve-rules.json` (fichier separe des regles manuelles)
- [ ] Re-indexer ChromaDB : appeler `python3 rag/indexer.py`
- [ ] Valider avec une requete test : `python3 rag/query.py --query "latest CVE" --limit 5`
- [ ] Logger le resume : nombre de nouvelles regles, domaines mis a jour, docs re-indexes

### Dependances

- Necessite que `cve-sync.py` ait ete execute au moins une fois (caches non-vides)
- ChromaDB + sentence-transformers installes (`pip3 install chromadb sentence-transformers`)

---

## Chantier 3 : Project Rescan Script (30 min)

**Objectif** : Script qui re-scanne les projets surveilles et detecte les nouvelles vulnerabilites.

**Creer** : `scripts/project-rescan.py`

### Sous-taches

- [ ] Creer un fichier de config des projets surveilles : `config/monitored-projects.json`
  ```json
  {
    "projects": [
      { "path": "/absolute/path/to/project", "name": "my-project", "depth": "standard" }
    ],
    "notifications": { "slack_webhook": null, "email": null },
    "archive_path": "reports/archive"
  }
  ```
- [ ] Pour chaque projet, invoquer le MCP server via stdio :
  - Appeler `scan-project` avec le path et depth configures
  - Appeler `generate-sbom` pour le SBOM
- [ ] Comparer avec le dernier rapport archive (`reports/archive/{project}_*.sarif.json` le plus recent) :
  - Identifier les **nouveaux** findings (absents du rapport precedent)
  - Identifier les findings **resolus** (presents avant, absents maintenant)
- [ ] Generer un rapport delta (diff) en Markdown
- [ ] Sauvegarder les 3 fichiers dans `reports/archive/` (SARIF, SBOM, MD)
- [ ] Si nouveaux findings CRITICAL/HIGH → logger une alerte (et optionnellement notifier via webhook)

### Contraintes

- Le MCP server doit etre build avant execution (`npm run build` dans sentinel-scanner)
- Comparaison basee sur `ruleId` + `location.uri` + `location.region.startLine` du SARIF
- Mode `--project <name>` pour re-scanner un seul projet

---

## Chantier 4 : Orchestration Cron (20 min)

**Objectif** : Unifier les 3 scripts sous un orchestrateur et configurer l'execution automatisee.

**Creer** : `scripts/sentinel-cron.sh`

### Sous-taches

- [ ] Script shell qui execute dans l'ordre :
  1. `python3 scripts/cve-sync.py` (daily)
  2. `python3 scripts/kb-update.py` (weekly — verifier le jour)
  3. `python3 scripts/project-rescan.py` (weekly — apres kb-update)
- [ ] Logique conditionnelle : kb-update et project-rescan ne tournent que le lundi
- [ ] Logging dans `logs/sentinel-cron.log` avec timestamps
- [ ] Gestion d'erreurs : si un step echoue, continuer les autres + logger l'erreur
- [ ] Mettre a jour les specs dans `crons/*.md` avec les instructions d'installation :
  ```bash
  # macOS (launchd) ou Linux (crontab)
  crontab -e
  0 6 * * * cd /path/to/lab-30-sentinel && bash scripts/sentinel-cron.sh >> logs/sentinel-cron.log 2>&1
  ```
- [ ] Creer le repertoire `logs/` avec un `.gitkeep`

---

## Chantier 5 : Validation E2E (15 min)

### Sous-taches

- [ ] Run initial du CVE sync : `python3 scripts/cve-sync.py` — verifier que les caches se peuplent
- [ ] Run KB update : `python3 scripts/kb-update.py` — verifier que les nouvelles regles sont creees et ChromaDB re-indexe
- [ ] Run project rescan sur `tests/vulnerable-app/` : verifier les 3 fichiers generes
- [ ] Verifier les logs dans `logs/sentinel-cron.log`
- [ ] `npm run build` dans sentinel-scanner — zero erreurs

---

## Ordre d'execution

```
1. CVE Sync (Chantier 1)        — pas de dependance
2. KB Update (Chantier 2)       — depend de 1 (caches non-vides)
3. Project Rescan (Chantier 3)  — depend de 2 (KB a jour)
4. Orchestration (Chantier 4)   — depend de 1, 2, 3
5. Validation E2E (Chantier 5)  — depend de tout
```

**Chantiers 1 est le fondement** — les autres en dependent sequentiellement.

---

## Fichiers a creer

| Fichier | Type | Role |
|---------|------|------|
| `scripts/cve-sync.py` | Python | Synchronisation CVE multi-sources |
| `scripts/kb-update.py` | Python | Enrichissement KB + re-indexation RAG |
| `scripts/project-rescan.py` | Python | Re-scan projets surveilles + diff |
| `scripts/sentinel-cron.sh` | Shell | Orchestrateur cron |
| `config/monitored-projects.json` | JSON | Liste des projets a surveiller |
| `logs/.gitkeep` | — | Repertoire de logs |

## Fichiers a modifier

| Fichier | Modification |
|---------|-------------|
| `crons/cve-sync.md` | Ajouter instructions d'installation |
| `crons/kb-update.md` | Ajouter instructions d'installation |
| `crons/project-rescan.md` | Ajouter instructions d'installation |
| `docs/roadmap.md` | Marquer Session 9 Done |

---

## Points d'attention

1. **API Keys** : NVD rate limit sans cle = 5 req/30s. Avec cle (`NVD_API_KEY` env var) = 50 req/30s. Le script doit supporter les deux modes.
2. **Premier run** : Les caches sont vides. Le premier CVE sync fetchera les 30 derniers jours — potentiellement beaucoup de donnees. Prevoir un `--days 7` pour limiter au premier run.
3. **ChromaDB** : Le re-indexing detruit et recree la collection. S'assurer que `indexer.py` gere correctement l'upsert ou la recreation.
4. **MCP Server invocation** : Le project-rescan doit appeler le MCP server via subprocess + stdio JSON-RPC. Alternative : importer directement les fonctions TS compilees via Node subprocess.
5. **Pas de deps nouvelles** : Utiliser uniquement `requests` (Python) et les builtins. Pas de nouvelles deps npm.

## Verification finale

- [ ] `python3 scripts/cve-sync.py --dry-run` fonctionne
- [ ] `python3 scripts/cve-sync.py` peuple les 3 caches
- [ ] `python3 scripts/kb-update.py` cree des `cve-rules.json` et re-indexe ChromaDB
- [ ] `python3 scripts/project-rescan.py --project vulnerable-app` genere un rapport delta
- [ ] `bash scripts/sentinel-cron.sh` execute le pipeline complet
- [ ] `docs/roadmap.md` mis a jour
- [ ] Commit final avec tag `session-9-complete`
