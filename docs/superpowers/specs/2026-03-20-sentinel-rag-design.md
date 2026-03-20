# Design Spec: /sentinel-rag

**Date**: 2026-03-20
**Status**: Draft
**Auteur**: Manuel Turpin + Claude Opus 4.6

---

## 1. Vision

`/sentinel-rag` est un expert RAG autonome, conversationnel et auto-evolutif. Il couvre le cycle de vie complet d'un systeme RAG — de la creation from scratch au monitoring en production — et maintient sa propre base de connaissances vectorielle qu'il consulte pour fournir des recommandations a jour.

### Principes fondateurs

- **Expert, pas outil** — il analyse le contexte et propose la bonne action, pas un menu
- **Generique** — fonctionne sur tout projet RAG (ChromaDB, Qdrant, LanceDB, pgvector)
- **Auto-evolutif** — detecte sa propre obsolescence et propose des mises a jour
- **RAG-ception** — utilise un RAG pour sa propre expertise

### Namespace

Le skill fait partie de l'ecosysteme `/sentinel-*` :

| Skill | Role | Status |
|---|---|---|
| `/sentinel-security` | Audit cybersecurite | Actif (renomme depuis `/security` — session 14) |
| `/sentinel-rag` | Expert RAG | Ce design |
| `/sentinel-monitor` | Monitoring/alertes | Futur |

---

## 2. Architecture

```
~/.claude/skills/sentinel-rag/
    SKILL.md                           # Principes cles + logique conversationnelle

~/.sentinel/skills/sentinel-rag/
    knowledge/
        chromadb/                      # Base vectorielle dediee (collection: sentinel_rag_expertise)
        sources/                       # Documents source (recherches, articles, REX)
        indexer.py                     # Indexation des sources dans ChromaDB
        query.py                       # Requete semantique sur l'expertise RAG
        config.json                    # Config collection + embedding model
    metadata.json                      # Etat du skill (last_updated, version, stats)
```

### Separation des responsabilites

| Composant | Emplacement | Role |
|---|---|---|
| **SKILL.md** | `~/.claude/skills/sentinel-rag/` | Instructions Claude — principes cles, workflow, logique de detection |
| **Knowledge Base** | `~/.sentinel/skills/sentinel-rag/knowledge/` | Expertise RAG indexee (best practices, benchmarks, code) |
| **Metadata** | `~/.sentinel/skills/sentinel-rag/metadata.json` | Etat du skill (timestamps, stats, version) |
| **Sources** | `~/.sentinel/skills/sentinel-rag/knowledge/sources/` | Documents bruts (recherches, articles) |

### Flux de donnees

```
Invocation /sentinel-rag
    |
    ├─ 1. Lire metadata.json → check last_updated
    │     └─ > 7 jours ? → proposer mise a jour (avec validation user)
    │
    ├─ 2. Detecter le contexte projet
    │     ├─ rag/ ou chromadb/ existe ? → mode diagnostic/optimisation
    │     ├─ config RAG detecte ? → analyser la config
    │     └─ rien detecte ? → mode creation
    │
    ├─ 3. Consulter sa KB avant de recommander
    │     └─ Bash: python3 ~/.sentinel/skills/sentinel-rag/knowledge/query.py
    │            --query "<question contextuelle>"
    │            --limit 5
    │     └─ Resultats → enrichissent la reponse
    │
    └─ 4. Agir (diagnostic, optimisation, creation, etc.)
```

---

## 3. Modes de fonctionnement

Le skill detecte automatiquement le mode adapte au contexte via cette logique :

```
1. L'utilisateur a-t-il demande un mode explicite ? → utiliser ce mode
2. Sinon, detecter le contexte projet :
   a. Glob: **/chromadb/**, **/qdrant/**, **/chroma.sqlite3, **/config.json avec "collection"
   b. Grep: "chromadb", "qdrant", "lancedb", "pgvector", "sentence_transformers", "embedding"
   c. Si RAG detecte → diagnose (premiere visite) ou optimize (si deja diagnostique)
   d. Si rien detecte → create
3. Le mode secure est invoque uniquement par /sentinel-security (via sub-agent)
   ou par demande explicite de l'utilisateur
4. Le mode evaluate et maintain sont toujours explicites
```

### 3.1 Mode Creation (`create`)

**Declencheur** : Aucun RAG detecte dans le projet, ou demande explicite.

Actions :
- Poser des questions sur le corpus (taille, type, langue, domaine)
- Recommander le modele d'embedding adapte
- Recommander la base vectorielle (ChromaDB, Qdrant, LanceDB)
- Generer le scaffolding : `indexer.py`, `query.py`, `config.json`
- Configurer HNSW (ef_construction, M, search_ef)
- Configurer la distance (cosine, ip, L2)
- Generer un golden dataset initial

### 3.2 Mode Diagnostic (`diagnose`)

**Declencheur** : RAG existant detecte.

Actions :
- Compter les documents indexes
- Verifier la sante HNSW (fragmentation, params)
- Verifier le modele d'embedding utilise vs recommandations actuelles
- Verifier la distance configuree
- Detecter les problemes courants (JSON brut indexe, pas de metadata, pas de hybrid search)
- Mesurer la fraicheur des donnees (age du dernier index)
- Produire un rapport de sante avec score global

### 3.3 Mode Optimisation (`optimize`)

**Declencheur** : Apres diagnostic, ou demande explicite.

Actions :
- Proposer un upgrade du modele d'embedding (avec benchmark comparatif)
- Implementer hybrid search (BM25 + semantic + RRF)
- Tuner HNSW (ef_construction, M, search_ef)
- Implementer le cross-encoder reranking
- Convertir JSON brut en templates textuels
- Implementer le query routing (regex pour IDs exacts vs semantic)
- Ajouter document expansion (questions generees)

### 3.4 Mode Evaluation (`evaluate`)

**Declencheur** : Demande explicite ou apres optimisation.

Actions :
- Creer/enrichir un golden dataset (paires question → doc attendu)
- Mesurer Hit@k, MRR, NDCG@k
- Comparer avant/apres une modification
- Generer un rapport de benchmark avec visualisations
- Integrer RAGAS/DeepEval si disponibles

### 3.5 Mode Securite (`secure`)

**Declencheur** : Audit de securite du RAG, ou integration avec `/sentinel-security`.

Actions :
- Detecter les risques de RAG poisoning
- Verifier la validation des sources avant indexation
- Verifier l'absence de prompt injection dans les documents indexes
- Verifier le controle d'acces aux collections
- Mapper sur OWASP LLM Top 10 2025 (LLM06: Excessive Agency, LLM08: RAG Poisoning)
- Recommandations NIST AI RMF / ISO 42001

### 3.6 Mode Maintenance (`maintain`)

**Declencheur** : Demande explicite ou schedule.

Actions :
- Re-indexation complete ou incrementale
- Backup de la base vectorielle
- Garbage collection (documents orphelins, doublons)
- Migration de modele d'embedding (re-embed complet)
- Monitoring du drift (centroid shift, neighbor persistence)

---

## 4. Self-Knowledge System (RAG-ception)

### 4.1 Collection dediee

```json
{
  "collection_name": "sentinel_rag_expertise",
  "embedding_model": "BAAI/bge-base-en-v1.5",
  "distance": "cosine",
  "chromadb_path": "~/.sentinel/skills/sentinel-rag/knowledge/chromadb"
}
```

Le skill utilise `bge-base-en-v1.5` pour sa propre KB (pas MiniLM) — il pratique ce qu'il preche.

**Note memoire** : La KB security (`sentinel_kb`) utilise encore `all-MiniLM-L6-v2`. Les deux modeles coexistent en memoire (~1.5 GB supplementaire pour bge-base). C'est acceptable car les deux ne tournent jamais simultanement (le skill RAG charge bge-base uniquement quand il consulte sa KB). A terme, `/sentinel-rag` pourra recommander la migration de la KB security vers bge-base aussi.

### 4.2 Sources initiales

Les 7 documents de recherche actuels (725 KB) :

| Source | Contenu |
|---|---|
| `01-embedding-chunking-hybrid.md` | Comparatif embedding, chunking JSON, hybrid search, RRF, reranking |
| `02-evaluation-monitoring.md` | RAGAS/DeepEval, Hit@k/MRR/NDCG, drift, HNSW tuning |
| `03-architecture-security.md` | GraphRAG, Agentic RAG, HyDE, RAG poisoning, OWASP/NIST |
| `04-chromadb-docs.md` | ChromaDB API, HNSW config, metadata, batch ops |
| `05-claude-desktop.md` | Analyse detaillee embedding + hybrid search + templates |
| `06-mistral.md` | Recherche complementaire (embedding, chunking, hybrid) |
| `07-gemini.md` | Analyse exhaustive architecture, securite, gouvernance RAG |

### 4.3 Chunking des sources Markdown

Les documents de recherche (50-200 KB chacun) sont trop longs pour un seul embedding. Strategie :

- **Chunk par heading H2** — chaque section `## Titre` devient un document independant
- **Overlap** : 0 (les headings sont des frontieres semantiques naturelles)
- **Metadata par chunk** : `source_file`, `section_title`, `heading_level`, `type` (best-practice|benchmark|code|anti-pattern)
- **Taille cible** : 200-800 tokens par chunk (la plupart des sections H2 tombent dans cette fourchette)
- **Si une section H2 > 1000 tokens** : splitter sur les H3

```python
# Schema metadata par chunk
{
    "source": "05-claude-desktop.md",
    "section": "Hybrid search is non-negotiable for cybersecurity identifiers",
    "type": "best-practice",        # best-practice | benchmark | code | anti-pattern | rex
    "domain": "hybrid-search",      # embedding | chunking | hybrid-search | evaluation | security | architecture
    "date_indexed": "2026-03-20"
}
```

### 4.4 Golden dataset (format)

```json
[
  {
    "query": "best embedding model for cybersecurity RAG",
    "expected_docs": ["05-claude-desktop.md#1", "07-gemini.md#1"],
    "relevance": [3, 2],
    "category": "embedding"
  },
  {
    "query": "how to implement hybrid search with BM25 and ChromaDB",
    "expected_docs": ["05-claude-desktop.md#3", "01-embedding-chunking-hybrid.md#3"],
    "relevance": [3, 3],
    "category": "hybrid-search"
  }
]
```

### 4.5 Pattern de consultation

Le SKILL.md instruit Claude de consulter la KB avant toute recommandation technique :

```
Avant de recommander un modele d'embedding, une strategie de chunking,
ou une architecture de search :
1. Formuler une query contextuelle
2. Executer: python3 ~/.sentinel/skills/sentinel-rag/knowledge/query.py
   --query "<question>" --limit 5
3. Integrer les resultats dans la recommandation
4. Citer les sources (doc + section)
```

### 4.6 Enrichissement continu

Le skill peut ingerer de nouvelles sources :
- L'utilisateur fournit un article/doc → le skill l'indexe dans `sources/`
- Resultat d'une recherche web → sauvegarde + indexation
- Retour d'experience → indexe comme REX (type: experience)

```bash
# Ajout d'une source
cp article.md ~/.sentinel/skills/sentinel-rag/knowledge/sources/
python3 ~/.sentinel/skills/sentinel-rag/knowledge/indexer.py
```

---

## 5. Self-Update Mechanism

### 5.1 Metadata tracking

```json
// ~/.sentinel/skills/sentinel-rag/metadata.json
{
  "version": "1.0.0",
  "last_updated": "2026-03-20T10:00:00Z",
  "last_update_check": "2026-03-20T10:00:00Z",
  "update_check_interval_days": 7,
  "total_sources": 7,
  "total_indexed_docs": 0,
  "update_history": [
    {
      "date": "2026-03-20T10:00:00Z",
      "type": "initial",
      "sources_added": 7,
      "description": "Initial knowledge base from research docs"
    }
  ]
}
```

### 5.2 Check a l'invocation

A chaque invocation de `/sentinel-rag` :

```
1. Lire metadata.json
2. Calculer: jours_depuis_update = now - last_updated
3. Si jours_depuis_update > update_check_interval_days:
   → "Ma base de connaissances date du {date}. Veux-tu que je fasse
      une recherche rapide pour verifier si des nouveautes importantes
      sont sorties ? (embedding models, ChromaDB updates, nouvelles
      techniques de search)"
4. Si l'utilisateur accepte:
   a. Recherche web ciblee (3-5 queries)
   b. Synthese des nouveautes pertinentes
   c. Si du contenu nouveau est trouve:
      - Sauvegarder dans sources/
      - Re-indexer
      - Mettre a jour metadata.json
   d. Si rien de nouveau:
      - Mettre a jour last_update_check
      - "Rien de nouveau depuis la derniere mise a jour."
```

### 5.3 Phase 2 : VPS comme hub central (futur)

```
VPS Archi (cron hebdomadaire)
    │
    ├─ Recherche web automatisee (embedding models, ChromaDB releases, etc.)
    ├─ Indexation des nouveautes
    ├─ Build d'un package KB a jour
    └─ Expose via rsync/git/API
         │
         ▼
Machine locale (au prochain /sentinel-rag)
    │
    ├─ Check: version locale < version VPS ?
    ├─ Si oui: pull le package KB mis a jour
    └─ Re-index local
```

Le mecanisme VPS est identique a celui deja prevu pour `/sentinel-security` (CVE sync). Les deux skills partagent le meme pattern de distribution.

---

## 6. SKILL.md — Structure du contenu hybride

Le SKILL.md contient les **principes cles** en dur (toujours disponibles sans query) et les **instructions de consultation** de la KB pour les details.

### Contenu embarque (en dur dans SKILL.md)

- Persona et role
- Workflow de detection de contexte
- Principes fondamentaux (YAGNI, quick wins first)
- Checklist par mode (create, diagnose, optimize, evaluate, secure, maintain)
- Instructions de consultation KB
- Self-update logic
- Modeles d'embedding recommandes (top 3 avec scores — mis a jour via self-update)
- Distances recommandees par cas d'usage
- Anti-patterns critiques (les 5 plus importants)

### Contenu reference (via KB query)

- Benchmarks detailles et comparatifs
- Code d'implementation complet (hybrid search, RRF, reranking, etc.)
- Configurations HNSW par taille de corpus
- Details des frameworks d'evaluation (RAGAS, DeepEval)
- Securite RAG (OWASP, NIST, poisoning detection)
- Retours d'experience indexes

---

## 7. Integration avec l'ecosysteme Sentinel

### 7.1 Avec `/sentinel-security`

Quand `/sentinel-security` detecte un RAG dans le projet audite (presence de chromadb/, qdrant/, ou imports sentence_transformers), il dispatche un sub-agent avec ce prompt :

```
Tu es l'agent RAG security de Sentinel. Audite la securite du RAG detecte
dans ce projet en suivant le protocole du mode "secure" de /sentinel-rag.
Consulte la KB: python3 ~/.sentinel/skills/sentinel-rag/knowledge/query.py
  --query "RAG security poisoning OWASP" --limit 5
```

Le sub-agent produit des findings SARIF que `/sentinel-security` integre dans son rapport consolide. Pas besoin d'invocation directe de `/sentinel-rag` — c'est un sub-agent qui lit les memes instructions.

- Les deux skills partagent le meme mecanisme de distribution VPS

### 7.2 Avec le RAG Sentinel existant

- `/sentinel-rag diagnose` peut auditer le RAG de Sentinel lui-meme (`~/.sentinel/rag/`)
- Il peut recommander des ameliorations (upgrade MiniLM → bge-base, ajout hybrid search)
- Meta: le skill RAG optimise le RAG du skill security

---

## 8. Fichiers a creer

### 8.1 Structure repo (source de verite)

```
lab-30-sentinel/                          # Repo git
    skills/
        security/                         # Renomme sentinel-security (nom frontmatter)
            SKILL.md
            agents/*.md
        sentinel-rag/                     # NOUVEAU
            SKILL.md                      # Instructions Claude
            knowledge/
                indexer.py                # Indexation des sources markdown
                query.py                  # Requete semantique
                config.json               # Config collection + embedding
                sources/                  # Copie des 7 docs de recherche
                    01-embedding-chunking-hybrid.md
                    02-evaluation-monitoring.md
                    03-architecture-security.md
                    04-chromadb-docs.md
                    05-claude-desktop.md
                    06-mistral.md
                    07-gemini.md
            metadata.json                 # Template metadata initial
    scripts/deploy.sh                     # Mis a jour
```

### 8.2 Structure deployee (runtime)

| Source (repo) | Destination (deploy) |
|---|---|
| `skills/sentinel-rag/SKILL.md` | `~/.claude/skills/sentinel-rag/SKILL.md` |
| `skills/sentinel-rag/knowledge/` | `~/.sentinel/skills/sentinel-rag/knowledge/` |
| `skills/sentinel-rag/metadata.json` | `~/.sentinel/skills/sentinel-rag/metadata.json` |

### 8.3 Modifications a deploy.sh

```bash
# Nouvelles variables
SENTINEL_RAG_SKILL_DIR="$HOME/.claude/skills/sentinel-rag"
SENTINEL_RAG_HOME="$SENTINEL_HOME/skills/sentinel-rag"

# Nouveaux blocs dans deploy_local()
# 1. Copier SKILL.md
mkdir -p "$SENTINEL_RAG_SKILL_DIR"
cp "$PROJECT_DIR/skills/sentinel-rag/SKILL.md" "$SENTINEL_RAG_SKILL_DIR/SKILL.md"

# 2. Copier knowledge (scripts + sources, PAS chromadb data)
mkdir -p "$SENTINEL_RAG_HOME/knowledge/sources"
cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/indexer.py" "$SENTINEL_RAG_HOME/knowledge/"
cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/query.py" "$SENTINEL_RAG_HOME/knowledge/"
cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/config.json" "$SENTINEL_RAG_HOME/knowledge/"
rsync -a "$PROJECT_DIR/skills/sentinel-rag/knowledge/sources/" "$SENTINEL_RAG_HOME/knowledge/sources/"

# 3. Copier metadata template (seulement si absent — ne pas ecraser l'etat runtime)
[ ! -f "$SENTINEL_RAG_HOME/metadata.json" ] && \
  cp "$PROJECT_DIR/skills/sentinel-rag/metadata.json" "$SENTINEL_RAG_HOME/metadata.json"

# 4. Indexer la KB sentinel-rag
(cd "$SENTINEL_RAG_HOME/knowledge" && python3 indexer.py 2>&1) || warn "RAG expertise indexing failed"
```

### 8.4 Note structurelle

Le RAG security existant est a `~/.sentinel/rag/` (top-level). Le RAG du skill sentinel-rag est a `~/.sentinel/skills/sentinel-rag/knowledge/`. Cette divergence est intentionnelle : le nouveau pattern (self-contained par skill) est meilleur. La migration du RAG security vers `~/.sentinel/skills/sentinel-security/knowledge/` est envisageable dans une future session mais hors scope ici.

### Hors scope (phase 2)

- VPS cron de mise a jour automatique
- API/endpoint sur le VPS pour servir les KB
- Dashboard de monitoring RAG
- Integration CI/CD avec DeepEval

---

## 9. Criteres de succes

1. `/sentinel-rag` detecte correctement le contexte (creation vs diagnostic vs optimisation)
2. La KB interne repond avec des resultats pertinents quand consultee
3. Le self-update detecte l'obsolescence et propose une mise a jour apres 7 jours
4. Le skill peut creer un RAG from scratch avec les bonnes pratiques
5. Le skill peut diagnostiquer un RAG existant et produire un rapport de sante
6. Le skill peut optimiser un RAG (embedding upgrade, hybrid search, HNSW tuning)
7. Les recommandations sont sourcees (reference au doc + section de la KB)
