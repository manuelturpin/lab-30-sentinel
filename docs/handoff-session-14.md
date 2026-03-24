# Handoff Session 14 — /sentinel-rag + RAG Optimization

**Date** : 2026-03-20 -> 2026-03-24
**Branche** : main
**Dernier commit** : `ed7ef55` revert(rag): remove cross-encoder reranker

---

## Ce qui a ete fait

### 1. Namespace /sentinel-* etabli

Le skill /security a ete renomme /sentinel-security. "Sentinel" est le namespace umbrella pour tous les outils IA (separe de B974 = bonsai uniquement).

| Skill | Commande | Status |
|---|---|---|
| /sentinel-security | Audit cybersecurite | Actif (renomme) |
| /sentinel-rag | Expert RAG autonome | Actif (nouveau) |

### 2. Skill /sentinel-rag cree from scratch

Expert RAG conversationnel et auto-evolutif, deploye dans tous les projets Claude Code.

**Architecture RAG-ception** : Le skill possede sa propre base vectorielle ChromaDB (sentinel_rag_expertise, 100 chunks, bge-base-en-v1.5) qu'il consulte avant chaque recommandation.

| Composant | Emplacement repo | Deploiement |
|---|---|---|
| SKILL.md | skills/sentinel-rag/SKILL.md | ~/.claude/skills/sentinel-rag/ |
| Indexer | skills/sentinel-rag/knowledge/indexer.py | ~/.sentinel/skills/sentinel-rag/knowledge/ |
| Query | skills/sentinel-rag/knowledge/query.py | idem |
| Sources (7 docs) | skills/sentinel-rag/knowledge/sources/ | idem |
| Metadata | skills/sentinel-rag/metadata.json | ~/.sentinel/skills/sentinel-rag/ |
| Golden dataset | skills/sentinel-rag/knowledge/golden_dataset.json | idem |

**6 modes** : create, diagnose, optimize, evaluate, secure, maintain
**Self-update** : Check metadata.json a chaque invocation, propose recherche web si >7 jours

### 3. RAG Sentinel optimise (diagnostic + optimize via /sentinel-rag)

Le RAG de la KB security a ete audite et optimise par le nouveau skill lui-meme.

| Optimisation | Avant | Apres |
|---|---|---|
| Embedding | all-MiniLM-L6-v2 (384d) | BAAI/bge-base-en-v1.5 (768d) |
| Query prefix | Aucun | Asymetrique bge-base |
| Normalisation | Non | normalize_embeddings=True |
| HNSW | Defauts ChromaDB | ef_construction=200, M=16, search_ef=100 |
| Search | Semantic seul | Hybrid BM25 + RRF (k=60, alpha=0.6) |
| Query routing | Aucun | Regex ID -> lookup direct (CVE-*, CWE-*, rule IDs) |
| Golden dataset | Absent | 50 queries (30 semantic, 10 exact-id, 3 standards) |

**Benchmark final :**

| Metrique | Pre-session | Post-session |
|---|---|---|
| Hit@1 | ~40% (estime) | 70% |
| Hit@5 | ~55% (estime) | 90% |
| Exact-ID Hit@1 | ~10% | 100% |
| MRR | ~0.4 | 0.793 |

**Decision data-driven** : Cross-encoder reranking (ms-marco-MiniLM) teste et retire. Ameliore Hit@1 (+4%) mais degrade Hit@5 (-4%) sur contenu cybersecurite. Pas rentable.

### 4. deploy.sh mis a jour

Deploie les deux skills + indexe les deux RAG. Metadata sentinel-rag preservee (no-clobber).

### 5. Tests

- bash scripts/test-sentinel.sh : 31/31 PASS
- bash tests/test-sentinel-rag.sh : 18/18 PASS

---

## Fichiers modifies cette session (24 fichiers, +3923 lignes)

### Nouveaux
- skills/sentinel-rag/ (SKILL.md, knowledge/, metadata.json)
- docs/superpowers/specs/2026-03-20-sentinel-rag-design.md
- docs/superpowers/plans/2026-03-20-sentinel-rag.md
- rag/golden_dataset.json (50 queries benchmark)
- tests/test-sentinel-rag.sh (18 tests)

### Modifies
- skills/security/SKILL.md (name: sentinel-security)
- scripts/deploy.sh (bloc sentinel-rag + skill dir)
- rag/config.json (bge-base + query_prefix)
- rag/indexer.py (HNSW tuning + normalize)
- rag/query.py (hybrid BM25+RRF + query routing)
- CLAUDE.md (references sentinel-security + sentinel-rag)

---

## Ce qui reste a faire

### Priorite 1 : Crons non installes
Les 3 crons Sentinel ne sont pas actifs. Le script sentinel-cron.sh existe. Options :
- Crontab systeme
- Claude Code CronCreate
- VPS cron (phase 2)

### Priorite 2 : VPS hub de mise a jour
Architecture prevue dans le design spec (section 5.3) : le VPS Archi fait les recherches/indexations en amont, les skills locaux pull.

### Priorite 3 : Standards queries faibles (33% Hit@5)
Les queries OWASP/MITRE ne matchent qu'a 33%. Le texte indexe est trop generique. Options :
- Enrichir _build_text() pour les standards
- Ajouter synonymes/descriptions aux standards JSON

### Priorite 4 : Self-update flow E2E
Le mecanisme est dans le SKILL.md mais pas teste end-to-end (recherche web -> sauvegarde -> re-index -> update metadata).

### Priorite 5 : Dependance rank-bm25
Installee manuellement via pip3. A ajouter dans scripts/setup.sh ou requirements.txt.

---

## Etat du systeme

```
Last sync:     2026-03-19T06:33:39Z
NVD cache:     3409 CVE
OSV cache:     1492 advisories
GitHub cache:  406 advisories
KB rules:      1846 (10 domaines)
RAG security:  5621 documents (sentinel_kb, bge-base-en-v1.5)
RAG expertise: 100 chunks (sentinel_rag_expertise, bge-base-en-v1.5)
Tests:         31/31 sentinel + 18/18 sentinel-rag
Deploy:        ~/.sentinel/ + ~/.claude/skills/sentinel-{security,rag}/ synced
Benchmark:     Hit@5=90%, MRR=0.793, Exact-ID=100%
```

## Commits cette session (13)

```
ed7ef55 revert(rag): remove cross-encoder reranker
7fb1626 feat(rag): hybrid search BM25+RRF + query routing + golden dataset
7e75365 perf(rag): migrate embedding to bge-base-en-v1.5 + HNSW tuning
db485b7 chore: update metadata after indexing (100 docs)
bd981ae feat(sentinel-rag): SKILL.md with 6 modes, self-update, and KB consultation
7fb83c6 docs: update CLAUDE.md with sentinel-rag and sentinel-security rename
64aafc0 feat(deploy): add sentinel-rag skill deployment
654e3bf test(sentinel-rag): golden dataset with 15 queries and Hit@5 validation
e8f758d feat(sentinel-rag): query CLI with bge-base asymmetric prefix
2b45af3 feat(sentinel-rag): markdown indexer with H2 chunking and domain classification
b168fac feat(sentinel-rag): add config, metadata template, and research sources
0a73ac5 plan(sentinel-rag): implementation plan with 8 tasks
1cb4535 feat: rename /security to /sentinel-security + design spec for /sentinel-rag
```
