# Lab-30 Sentinel — Session 10 : E2E Complet + Polish

## Context

Sessions 1-9 complete (`82b5968`, tag `session-9-complete`). Sentinel est fonctionnellement complet : 12 agents, 7 MCP tools, KB (1286 rules dont 1177 auto-generees), RAG (ChromaDB), SARIF enrichi, SBOM CycloneDX, report renderer, cron pipeline. Session 10 valide le systeme de bout en bout, corrige les derniers problemes, et polish pour production.

## Etat actuel du systeme

### Composants

| Composant | Etat | Chiffres |
|-----------|------|----------|
| Skill `/security` | Operationnel | Orchestrateur avec stack detection |
| Agents | 13 fichiers MD | 12 specialises + 1 websocket |
| MCP Server | Build OK | 6 tools + 2 utils (SARIF, SBOM) |
| Knowledge Base | 1286 rules | 109 manuelles + 1177 CVE auto-generees, 11 domaines |
| RAG (ChromaDB) | 231 docs indexes | Doit etre re-indexe pour inclure les cve-rules.json |
| CVE Feed | 2273 NVD + EPSS | OSV cross-ref pret mais jamais execute en live |
| Cron Pipeline | 4 scripts | cve-sync, kb-update, project-rescan, sentinel-cron.sh |
| Reports Archive | 8 fichiers | SARIF, SBOM, delta MD pour vulnerable-app |
| Tests | test-sentinel.sh (10/14) | 4 FAIL = outils externes optionnels non installes |

### Points connus a resoudre

1. **ChromaDB pas re-indexe depuis Session 9** — Les 1177 cve-rules.json ne sont pas encore dans le RAG (le kb-update a ete lance avec `--skip-reindex` pour les tests). Le `rag/config.json` est deja mis a jour pour les inclure.

2. **Test suite incomplete** — `test-sentinel.sh` ne teste que la structure. Il manque :
   - Validation du MCP server (build + tool call)
   - Validation du RAG (query retourne des resultats)
   - Validation des cron scripts (dry-run)
   - Test E2E du flow `/security` complet

3. **OSV sync** — L'approche cross-reference CVE→OSV fonctionne en theorie mais n'a pas ete validee en live (NVD a ete la seule source peuplee). A tester.

4. **GitHub Advisories** — Retourne 0 resultats sans `GITHUB_TOKEN`. Fonctionne correctement avec token mais non teste.

5. **`test-sentinel.sh` compte les utils comme 6 au lieu de 5** — Le check `5 util files` trouve 6 fichiers (types.ts ajoute en session 7). Minor.

---

## Chantier 1 : Re-indexation ChromaDB complte (15 min)

**Objectif** : Indexer les 1177 nouvelles regles CVE dans ChromaDB.

### Sous-taches

- [ ] Run `python3 rag/indexer.py` — verifier que les cve-rules.json sont collectes
- [ ] Verifier le nombre de documents indexes (devrait passer de 231 a ~1400+)
- [ ] Valider avec `python3 rag/query.py --query "SQL injection CVE" --limit 5` — doit retourner des CVE recentes
- [ ] Valider avec `python3 rag/query.py --query "XSS cross-site scripting" --domain web-app --limit 5`

---

## Chantier 2 : Test Suite Complete (45 min)

**Objectif** : Etendre `test-sentinel.sh` pour couvrir tous les composants et ajouter des tests E2E.

### Sous-taches

- [ ] Ajouter a `test-sentinel.sh` :
  - Section **MCP Server** : `npm run build` dans sentinel-scanner (zero erreurs)
  - Section **RAG** : `python3 rag/query.py --query "test" --limit 1` retourne un resultat
  - Section **Cron Scripts** : `python3 scripts/cve-sync.py --dry-run` exit 0
  - Section **Cron Scripts** : `python3 scripts/kb-update.py --dry-run` exit 0
  - Section **Cron Scripts** : `python3 scripts/project-rescan.py --dry-run` exit 0
  - Section **KB** : Verifier que `knowledge-base/domains/*/cve-rules.json` existent (>= 8 fichiers)
  - Section **CVE Feed** : Verifier que `nvd-cache.json` contient des vulnerabilites
  - Fix : Mettre a jour le check `5 util files` → `6 util files`
- [ ] Creer `tests/e2e-session10.sh` (script bash, pas TS) :
  - Test 1 : MCP `scan-project` sur `tests/vulnerable-app/` — doit retourner du SARIF avec findings
  - Test 2 : MCP `generate-sbom` — doit retourner du CycloneDX
  - Test 3 : MCP `query-kb` avec query "SQL injection" — doit retourner des resultats
  - Test 4 : MCP `query-cve` avec component "express" — doit retourner des CVEs
  - Test 5 : `project-rescan.py --project vulnerable-app` — doit generer 3 fichiers dans archive
  - Test 6 : RAG query avec domaine filtre — resultats coherents
- [ ] Tous les tests passent

### Format de test

```bash
run_test "description" "command" "expected_pattern_in_output"
```

---

## Chantier 3 : Flow `/security` E2E (30 min)

**Objectif** : Valider le flow complet du skill `/security` manuellement et documenter le resultat.

### Sous-taches

- [ ] Executer `/security` sur `tests/vulnerable-app/` — verifier :
  - Stack detection correcte (Node.js/JavaScript)
  - Agents dispatches (web-audit, supply-chain-audit, data-privacy-audit)
  - Rapport SARIF genere avec findings
  - Rapport SBOM genere
  - Rapport Markdown genere avec severites
- [ ] Executer `/security` sur le projet Sentinel lui-meme — verifier :
  - Detection du stack (TypeScript, Python, AI/LLM)
  - Agents : llm-ai-audit, supply-chain-audit, data-privacy-audit
  - Pas de false positives bloquants
- [ ] Documenter les resultats dans `reports/archive/session-10-e2e-results.md`

---

## Chantier 4 : Polish + Error Handling (30 min)

**Objectif** : Corriger les derniers edge cases et ameliorer la robustesse.

### Sous-taches

- [ ] **Error handling MCP server** : Verifier que `scan-project` gere gracieusement :
  - Chemin inexistant → message d'erreur clair
  - Projet vide (pas de package.json/etc.) → rapport vide, pas de crash
  - Permissions insuffisantes → message explicite
- [ ] **Cron robustesse** : Verifier `sentinel-cron.sh` quand :
  - Pas de connexion internet → les scripts continuent, errors loggees
  - ChromaDB pas installe → kb-update echoue proprement
- [ ] **CLAUDE.md update** : Mettre a jour avec :
  - Metriques finales (nombre de rules, docs indexes, CVEs)
  - Commandes de Session 10 (`bash tests/e2e-session10.sh`)
- [ ] **Roadmap** : Marquer Session 10 Done, ajouter metriques finales

---

## Chantier 5 : Tag Final + Documentation (10 min)

### Sous-taches

- [ ] `bash scripts/test-sentinel.sh` — tous les checks passent (hors outils externes optionnels)
- [ ] `bash tests/e2e-session10.sh` — tous les tests E2E passent
- [ ] Commit final
- [ ] Tag `session-10-complete`
- [ ] Push

---

## Ordre d'execution

```
1. Re-indexation ChromaDB (Chantier 1) — pas de dependance
2. Test Suite (Chantier 2)             — depend de 1 (RAG a jour)
3. Flow /security E2E (Chantier 3)    — depend de 1 (RAG a jour)
4. Polish (Chantier 4)                — depend de 2, 3 (issues decouvertes)
5. Tag Final (Chantier 5)             — depend de tout
```

**Chantiers 2 et 3 peuvent tourner en parallele** apres le Chantier 1.

---

## Fichiers a creer

| Fichier | Type | Role |
|---------|------|------|
| `tests/e2e-session10.sh` | Shell | Tests E2E complets |
| `reports/archive/session-10-e2e-results.md` | Markdown | Resultats du flow /security |

## Fichiers a modifier

| Fichier | Modification |
|---------|-------------|
| `scripts/test-sentinel.sh` | Ajouter sections MCP, RAG, Cron, KB, CVE Feed |
| `CLAUDE.md` | Metriques finales |
| `docs/roadmap.md` | Session 10 Done + metriques |

---

## Metriques cibles a la fin de Session 10

| Metrique | Cible |
|----------|-------|
| KB Rules | ~1300 (109 manuelles + ~1177 CVE) |
| RAG Documents | ~1400+ (apres re-indexation avec cve-rules.json) |
| MCP Tools | 7 (scan-project, scan-secrets, scan-deps, scan-headers, query-kb, query-cve, generate-sbom) |
| Agents | 12 specialises |
| Domaines KB | 11 |
| CVE Feed | 2273+ NVD, enrichis EPSS |
| Test checks | ~25+ (structure + MCP + RAG + cron + E2E) |
| E2E tests | ~8+ (MCP tools + rescan + RAG + /security flow) |

## Verification finale

- [ ] `bash scripts/test-sentinel.sh` — 0 echecs (hors outils externes)
- [ ] `bash tests/e2e-session10.sh` — 0 echecs
- [ ] `/security` fonctionne sur un projet reel
- [ ] `docs/roadmap.md` complet
- [ ] `CLAUDE.md` a jour
- [ ] Tag `session-10-complete` pousse
- [ ] Sentinel est pret pour utilisation en production
