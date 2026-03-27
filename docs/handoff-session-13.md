# Handoff Session 13 — CVE Sync Fixes + RAG Research

**Date** : 2026-03-19 → 2026-03-20
**Branche** : main
**Dernier commit** : `2597b4e` fix: index GitHub advisories in RAG (ghsa_id→id)

---

## Ce qui a été fait

### 1. CVE Sync — 3 bugs corrigés

| Bug | Fichier | Fix |
|-----|---------|-----|
| **NVD API 404** | `scripts/cve-sync.py:107-108` | Le `+` dans `+00:00` n'était pas URL-encodé → remplacé par `%2B00:00` |
| **GitHub pagination infinie** | `scripts/cve-sync.py:383` | Ajout `max_pages = 10` (cap à 1000 advisories/ecosystem) |
| **GitHub advisories pas dans RAG** | `rag/indexer.py:94-107` | `ghsa_id` → `id` normalization dans `_flatten_nested()` |

### 2. Sync complète réussie

| Source | Avant session | Après session | Delta |
|--------|--------------|---------------|-------|
| NVD | 2273 | 3409 | +1136 |
| OSV | 1491 | 1492 | +1 |
| GitHub | 130 | 406 | +276 |
| **Total CVE** | **3894** | **5307** | **+1413** |
| Règles KB | 1239 | 1846 | +607 |
| Docs RAG | 4088 | 5621 | +1533 |

- Tests : 31/31 passent
- Deploy : `~/.sentinel/` à jour
- `GITHUB_TOKEN` requis pour sync GitHub (disponible via `gh auth token`)

### 3. Recherche RAG Best Practices

4 documents de recherche sauvegardés dans `docs/research/rag-best-practices/` :

| Fichier | Contenu |
|---------|---------|
| `01-embedding-chunking-hybrid.md` | Comparatif modèles embedding (MiniLM vs mpnet vs bge), chunking JSON structuré, hybrid search BM25+semantic, RRF, cross-encoder reranking |
| `02-evaluation-monitoring.md` | RAGAS/DeepEval frameworks, Hit@k/MRR/NDCG, embedding drift detection, data freshness, HNSW tuning, multi-collection |
| `03-architecture-security.md` | GraphRAG, Agentic/Self/Corrective RAG, HyDE, query routing, RAG poisoning, OWASP LLM 2025, NIST AI RMF, ISO 42001, EU AI Act |
| `04-chromadb-docs.md` | ChromaDB API best practices, HNSW config, metadata filtering, batch ops, re-indexing patterns |

**Total : ~725 KB de recherche structurée avec code Python, benchmarks, et sources.**

Un prompt de recherche avancée a aussi été généré (dans le plan file) et lancé par l'utilisateur dans 2 autres modèles IA. Les résultats externes ne sont pas encore déposés.

---

## Ce qui reste à faire

### Priorité 1 : Créer le skill `/rag-manage`

**Objectif** : Skill dédié à la gestion du RAG Sentinel — diagnostique, optimise, évalue et maintient le pipeline RAG.

**Inputs pour la création** :
- 4 fichiers de recherche Claude dans `docs/research/rag-best-practices/`
- Résultats de 2 autres modèles IA (à déposer par l'utilisateur dans le même dossier)
- Architecture actuelle documentée dans `CLAUDE.md` et `rag/config.json`

**Le skill devrait couvrir** :
1. **Diagnostic** — état du RAG (count, freshness, drift, santé HNSW)
2. **Évaluation** — benchmark avec golden dataset, Hit@k, MRR
3. **Optimisation** — hybrid search, HNSW tuning, embedding model upgrade
4. **Maintenance** — re-index, backup, garbage collection
5. **Sécurité** — validation des sources, détection de poisoning
6. **Monitoring** — alertes freshness, drift, query analytics

### Priorité 2 : Quick wins identifiés (implémentables sans le skill)

| Action | Effort | Impact |
|--------|--------|--------|
| HNSW tuning (ef_construction=150, search_ef=75) | 30min | Meilleur recall |
| Golden dataset 50 queries + Hit@5 benchmark | 2h | Baseline évaluation |
| Hybrid BM25+semantic search | 4h | Fix exact match CVE/CWE |
| Tester `bge-small-en-v1.5` vs MiniLM | 1h | Potentiel qualité++ |

### Priorité 3 : Crons non installés

Les 3 crons Sentinel ne sont pas actifs (ni crontab ni Claude Code CronCreate). Le script `sentinel-cron.sh` existe et fonctionne. Options :
- Crontab système : `0 6 * * * cd /path && bash scripts/sentinel-cron.sh >> logs/sentinel-cron.log 2>&1`
- Claude Code CronCreate (nécessite CC ouvert)

---

## État du système

```
Last sync:     2026-03-19T06:33:39Z
NVD cache:     3409 CVE
OSV cache:     1492 advisories
GitHub cache:  406 advisories
KB rules:      1846 (10 domaines)
RAG indexed:   5621 documents (ChromaDB, sentinel_kb)
Tests:         31/31 passing
Deploy:        ~/.sentinel/ synced
```

## Fichiers modifiés cette session

- `scripts/cve-sync.py` — fix NVD URL encoding + GitHub pagination cap
- `rag/indexer.py` — fix GitHub advisory ghsa_id normalization
- `knowledge-base/cve-feed/*.json` — caches mis à jour
- `knowledge-base/domains/*/cve-rules.json` — règles régénérées
- `docs/research/rag-best-practices/` — 4 fichiers de recherche (nouveau)
