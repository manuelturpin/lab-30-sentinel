# /sentinel-rag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create `/sentinel-rag`, an auto-evolving RAG expert skill with its own ChromaDB knowledge base, covering the full RAG lifecycle (create, diagnose, optimize, evaluate, secure, maintain).

**Architecture:** A SKILL.md (deployed to `~/.claude/skills/sentinel-rag/`) provides conversational instructions with embedded principles. A separate knowledge system (deployed to `~/.sentinel/skills/sentinel-rag/`) contains a ChromaDB collection indexed from 7 research documents (725 KB), queried via `query.py` before each recommendation. A `metadata.json` tracks staleness for self-update.

**Tech Stack:** Python 3, ChromaDB, sentence-transformers (BAAI/bge-base-en-v1.5), Markdown chunking by H2 headings

**Spec:** `docs/superpowers/specs/2026-03-20-sentinel-rag-design.md`

---

## File Map

| File | Responsibility |
|---|---|
| `skills/sentinel-rag/SKILL.md` | Skill instructions — persona, modes, detection logic, KB consultation, self-update |
| `skills/sentinel-rag/knowledge/config.json` | ChromaDB collection config (model, distance, paths) |
| `skills/sentinel-rag/knowledge/indexer.py` | Markdown chunker + ChromaDB indexer (chunk by H2, metadata extraction) |
| `skills/sentinel-rag/knowledge/query.py` | Semantic query CLI with bge-base-en-v1.5 asymmetric prefix |
| `skills/sentinel-rag/knowledge/sources/*.md` | 7 research docs (copied from `docs/research/rag-best-practices/`) |
| `skills/sentinel-rag/knowledge/golden_dataset.json` | 15 query/expected-doc pairs for KB quality validation |
| `skills/sentinel-rag/knowledge/.gitignore` | Exclude chromadb/ data from git |
| `skills/sentinel-rag/metadata.json` | Template: version, last_updated, update_history |
| `scripts/deploy.sh` | Add sentinel-rag deployment block |
| `tests/test-sentinel-rag.sh` | End-to-end tests for indexer, query, and deployment |

---

### Task 1: Config + Metadata Template

**Files:**
- Create: `skills/sentinel-rag/knowledge/config.json`
- Create: `skills/sentinel-rag/metadata.json`

- [ ] **Step 1: Create config.json**

```json
{
  "collection_name": "sentinel_rag_expertise",
  "embedding_model": "BAAI/bge-base-en-v1.5",
  "query_prefix": "Represent this sentence for searching relevant passages: ",
  "distance": "cosine",
  "chromadb_path": "./chromadb",
  "sources": ["./sources/*.md"]
}
```

- [ ] **Step 2: Create metadata.json template**

```json
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
      "description": "Initial knowledge base from 7 research documents"
    }
  ]
}
```

- [ ] **Step 3: Copy research sources**

```bash
mkdir -p skills/sentinel-rag/knowledge/sources
cp docs/research/rag-best-practices/*.md skills/sentinel-rag/knowledge/sources/
```

- [ ] **Step 4: Create .gitignore for chromadb data**

Create `skills/sentinel-rag/knowledge/.gitignore`:

```
chromadb/
```

- [ ] **Step 5: Commit**

```bash
git add skills/sentinel-rag/knowledge/config.json skills/sentinel-rag/metadata.json skills/sentinel-rag/knowledge/sources/ skills/sentinel-rag/knowledge/.gitignore
git commit -m "feat(sentinel-rag): add config, metadata template, and research sources"
```

---

### Task 2: Markdown Indexer

**Files:**
- Create: `skills/sentinel-rag/knowledge/indexer.py`
- Reference: `rag/indexer.py` (existing pattern — but this one chunks Markdown, not JSON)

- [ ] **Step 1: Write the indexer test**

Create `tests/test-sentinel-rag.sh` with indexer tests:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
INDEXER="$PROJECT_DIR/skills/sentinel-rag/knowledge/indexer.py"
CONFIG="$PROJECT_DIR/skills/sentinel-rag/knowledge/config.json"
SOURCES="$PROJECT_DIR/skills/sentinel-rag/knowledge/sources"

PASS=0; FAIL=0; TOTAL=0
check() {
  TOTAL=$((TOTAL+1))
  if eval "$2"; then
    echo "  [PASS] $1"; PASS=$((PASS+1))
  else
    echo "  [FAIL] $1"; FAIL=$((FAIL+1))
  fi
}

echo "=== Sentinel RAG Skill Tests ==="
echo ""

# --- Structure tests ---
echo "--- Structure ---"
check "config.json exists" "[ -f '$CONFIG' ]"
check "config has collection_name" "grep -q 'sentinel_rag_expertise' '$CONFIG'"
check "config has bge-base model" "grep -q 'bge-base-en-v1.5' '$CONFIG'"
check "config has query_prefix" "grep -q 'query_prefix' '$CONFIG'"
check "metadata.json exists" "[ -f '$PROJECT_DIR/skills/sentinel-rag/metadata.json' ]"
check "sources dir has 7 files" "[ $(ls '$SOURCES'/*.md 2>/dev/null | wc -l | tr -d ' ') -ge 7 ]"
check "indexer.py exists" "[ -f '$INDEXER' ]"

# --- Indexer tests ---
echo ""
echo "--- Indexer ---"
check "indexer runs without error" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 indexer.py 2>&1 | tail -1 | grep -q 'Indexing complete'"
check "chromadb created" "[ -d '$PROJECT_DIR/skills/sentinel-rag/knowledge/chromadb' ]"
check "indexed >50 chunks" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 -c \"
import chromadb, json
cfg = json.load(open('config.json'))
c = chromadb.PersistentClient(path='./chromadb')
col = c.get_collection(cfg['collection_name'])
assert col.count() > 50, f'Only {col.count()} docs'
print(f'{col.count()} docs indexed')
\""

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
```

- [ ] **Step 2: Run test to verify it fails**

```bash
bash tests/test-sentinel-rag.sh
```

Expected: FAIL on "indexer.py exists" and subsequent tests.

- [ ] **Step 3: Write the Markdown indexer**

Create `skills/sentinel-rag/knowledge/indexer.py`:

```python
"""
Sentinel RAG Skill — Markdown Indexer
Chunks Markdown documents by H2 headings and indexes into ChromaDB
with BAAI/bge-base-en-v1.5 embeddings.
"""

import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

import chromadb
from sentence_transformers import SentenceTransformer

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
METADATA_PATH = os.path.join(os.path.dirname(__file__), "..", "metadata.json")

# Domain classification keywords
DOMAIN_KEYWORDS = {
    "embedding": ["embedding", "model", "MiniLM", "bge", "nomic", "e5", "gte", "MTEB", "dimension", "asymmetric"],
    "chunking": ["chunk", "token", "split", "template", "JSON", "markdown", "parent-child"],
    "hybrid-search": ["hybrid", "BM25", "RRF", "Reciprocal Rank", "keyword", "lexical", "rerank", "cross-encoder"],
    "evaluation": ["RAGAS", "DeepEval", "Hit@k", "MRR", "NDCG", "golden dataset", "benchmark", "metric"],
    "security": ["poisoning", "injection", "OWASP", "NIST", "ISO 42001", "EU AI Act", "compliance", "governance"],
    "architecture": ["GraphRAG", "Agentic", "HyDE", "query routing", "multi-query", "self-RAG", "corrective"],
    "chromadb": ["ChromaDB", "HNSW", "collection", "PersistentClient", "where_document", "metadata filter"],
    "monitoring": ["drift", "centroid", "freshness", "latency", "monitoring", "alert", "Evidently"],
}


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def classify_domain(text: str) -> str:
    text_lower = text.lower()
    scores = {}
    for domain, keywords in DOMAIN_KEYWORDS.items():
        scores[domain] = sum(1 for kw in keywords if kw.lower() in text_lower)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "general"


def classify_type(text: str) -> str:
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["anti-pattern", "avoid", "don't", "never", "mistake", "wrong"]):
        return "anti-pattern"
    if any(kw in text_lower for kw in ["benchmark", "score", "accuracy", "comparison", "vs", "%"]):
        return "benchmark"
    if "```python" in text or "```bash" in text or "```json" in text:
        return "code"
    return "best-practice"


def chunk_markdown(filepath: str) -> list[dict]:
    """Split a Markdown file into chunks by H2 headings.
    If an H2 section > 1000 tokens, split further on H3."""
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    filename = os.path.basename(filepath)
    chunks = []
    # Split on H2
    h2_pattern = re.compile(r'^## (.+)$', re.MULTILINE)
    h2_splits = h2_pattern.split(content)

    # h2_splits: [preamble, title1, body1, title2, body2, ...]
    # Handle preamble (text before first H2)
    if h2_splits[0].strip():
        preamble = h2_splits[0].strip()
        # Extract title from H1 if present
        h1_match = re.search(r'^# (.+)$', preamble, re.MULTILINE)
        title = h1_match.group(1) if h1_match else "Introduction"
        chunks.append({
            "source": filename,
            "section": title,
            "heading_level": 1,
            "text": preamble,
        })

    for i in range(1, len(h2_splits), 2):
        if i + 1 > len(h2_splits):
            break
        title = h2_splits[i].strip()
        body = h2_splits[i + 1] if i + 1 < len(h2_splits) else ""
        section_text = f"## {title}\n\n{body}".strip()

        # Rough token estimate: words * 1.3
        est_tokens = len(section_text.split()) * 1.3

        if est_tokens > 1000:
            # Split on H3
            h3_pattern = re.compile(r'^### (.+)$', re.MULTILINE)
            h3_splits = h3_pattern.split(section_text)
            # Preamble of H2 (before first H3)
            if h3_splits[0].strip():
                chunks.append({
                    "source": filename,
                    "section": title,
                    "heading_level": 2,
                    "text": h3_splits[0].strip(),
                })
            for j in range(1, len(h3_splits), 2):
                h3_title = h3_splits[j].strip()
                h3_body = h3_splits[j + 1] if j + 1 < len(h3_splits) else ""
                h3_text = f"### {h3_title}\n\n{h3_body}".strip()
                chunks.append({
                    "source": filename,
                    "section": f"{title} > {h3_title}",
                    "heading_level": 3,
                    "text": h3_text,
                })
        else:
            chunks.append({
                "source": filename,
                "section": title,
                "heading_level": 2,
                "text": section_text,
            })

    return chunks


def collect_documents(config: dict) -> list[dict]:
    """Collect and chunk all Markdown sources."""
    documents = []
    rag_dir = os.path.dirname(os.path.abspath(__file__))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for pattern in config["sources"]:
        full_pattern = os.path.normpath(os.path.join(rag_dir, pattern))
        for filepath in sorted(glob.glob(full_pattern)):
            chunks = chunk_markdown(filepath)
            for idx, chunk in enumerate(chunks):
                doc_id = f"{chunk['source']}#{idx}"
                documents.append({
                    "id": doc_id,
                    "text": chunk["text"],
                    "metadata": {
                        "source": chunk["source"],
                        "section": chunk["section"],
                        "heading_level": chunk["heading_level"],
                        "type": classify_type(chunk["text"]),
                        "domain": classify_domain(chunk["text"]),
                        "date_indexed": today,
                    },
                })

    return documents


def index_documents(documents: list[dict], config: dict):
    """Index documents into ChromaDB with bge-base embeddings."""
    chromadb_path = os.path.join(os.path.dirname(__file__), config["chromadb_path"])
    client = chromadb.PersistentClient(path=chromadb_path)

    try:
        client.delete_collection(config["collection_name"])
    except Exception:
        pass

    collection = client.create_collection(
        name=config["collection_name"],
        metadata={"hnsw:space": config.get("distance", "cosine")},
    )

    print(f"Loading embedding model: {config['embedding_model']}...")
    model = SentenceTransformer(config["embedding_model"])

    batch_size = 100
    for i in range(0, len(documents), batch_size):
        batch = documents[i:i + batch_size]
        ids = [doc["id"] for doc in batch]
        texts = [doc["text"] for doc in batch]
        metadatas = [doc["metadata"] for doc in batch]
        # bge-base: no prefix for documents
        embeddings = model.encode(texts, normalize_embeddings=True, show_progress_bar=False).tolist()
        collection.add(ids=ids, documents=texts, embeddings=embeddings, metadatas=metadatas)
        print(f"  Indexed batch {i // batch_size + 1}: {len(batch)} chunks")

    total = collection.count()
    print(f"Total: {total} chunks in collection '{config['collection_name']}'")
    return total


def update_metadata(total_docs: int):
    """Update metadata.json with indexing results."""
    if not os.path.isfile(METADATA_PATH):
        return
    with open(METADATA_PATH) as f:
        meta = json.load(f)
    meta["total_indexed_docs"] = total_docs
    meta["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(METADATA_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Metadata updated: {total_docs} docs indexed")


def main():
    print("=== Sentinel RAG Skill — Indexer ===")
    config = load_config()
    print(f"Collection: {config['collection_name']}")
    print(f"Model: {config['embedding_model']}")

    documents = collect_documents(config)
    print(f"Collected {len(documents)} chunks from sources")

    if not documents:
        print("No documents found. Check source patterns in config.json.")
        sys.exit(1)

    total = index_documents(documents, config)
    update_metadata(total)
    print("Indexing complete.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run indexer tests**

```bash
bash tests/test-sentinel-rag.sh
```

Expected: All structure + indexer tests PASS. Should index >50 chunks from 7 docs.

- [ ] **Step 5: Commit**

```bash
git add skills/sentinel-rag/knowledge/indexer.py tests/test-sentinel-rag.sh
git commit -m "feat(sentinel-rag): markdown indexer with H2 chunking and domain classification"
```

---

### Task 3: Query Script

**Files:**
- Create: `skills/sentinel-rag/knowledge/query.py`
- Reference: `rag/query.py` (existing pattern — adapt for bge-base asymmetric prefix)

- [ ] **Step 1: Add query tests to test script**

Append to `tests/test-sentinel-rag.sh` before the results line:

```bash
# --- Query tests ---
echo ""
echo "--- Query ---"
QUERY="$PROJECT_DIR/skills/sentinel-rag/knowledge/query.py"
check "query.py exists" "[ -f '$QUERY' ]"
check "query returns results for 'embedding model'" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'best embedding model' --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"totalResults\"]>0, f\"got {d}\"'"
check "query returns results for 'hybrid search BM25'" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'hybrid search BM25 RRF' --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"totalResults\"]>0'"
check "query returns results for 'RAG poisoning OWASP'" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'RAG poisoning OWASP security' --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"totalResults\"]>0'"
check "query domain filter works" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'embedding' --domain embedding --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); r=d[\"results\"]; assert all(x[\"domain\"]==\"embedding\" for x in r) if r else True'"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
bash tests/test-sentinel-rag.sh
```

Expected: FAIL on "query.py exists".

- [ ] **Step 3: Write query.py**

Create `skills/sentinel-rag/knowledge/query.py`:

```python
"""
Sentinel RAG Skill — Query CLI
Searches the RAG expertise knowledge base using bge-base-en-v1.5 with asymmetric prefix.

Usage:
    python3 query.py --query "best embedding model for cybersecurity" --limit 5
    python3 query.py --query "hybrid search" --domain hybrid-search --limit 3
"""

import argparse
import json
import os
import sys

try:
    import chromadb
    from sentence_transformers import SentenceTransformer
except ImportError as e:
    print(f"Missing dependency: {e}\nInstall: pip install sentence-transformers chromadb", file=sys.stderr)
    sys.exit(1)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def query_kb(query: str, domain: str = "all", limit: int = 5) -> dict:
    config = load_config()
    chromadb_path = os.path.join(os.path.dirname(__file__), config["chromadb_path"])

    if not os.path.isdir(chromadb_path):
        return {"query": query, "domain": domain, "totalResults": 0, "results": [],
                "error": f"ChromaDB not found at {chromadb_path}. Run indexer.py first."}

    client = chromadb.PersistentClient(path=chromadb_path)
    try:
        collection = client.get_collection(config["collection_name"])
    except ValueError:
        return {"query": query, "domain": domain, "totalResults": 0, "results": [],
                "error": "Collection not found. Run indexer.py first."}

    count = collection.count()
    if count == 0:
        return {"query": query, "domain": domain, "totalResults": 0, "results": []}

    model = SentenceTransformer(config["embedding_model"])
    # bge-base asymmetric: prefix for queries, no prefix for docs
    query_prefix = config.get("query_prefix", "")
    prefixed_query = query_prefix + query
    query_embedding = model.encode([prefixed_query], normalize_embeddings=True).tolist()

    where_filter = None
    if domain != "all":
        where_filter = {"domain": domain}

    results = collection.query(
        query_embeddings=query_embedding,
        n_results=min(limit, count),
        where=where_filter,
        include=["documents", "metadatas", "distances"],
    )

    entries = []
    if results["ids"] and results["ids"][0]:
        for i, doc_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            distance = results["distances"][0][i] if results["distances"] else 1.0
            # ChromaDB cosine distance = 1 - cosine_similarity, range [0, 2]
            score = round(max(0, 1 - distance), 4)
            entries.append({
                "id": doc_id,
                "score": score,
                "source": meta.get("source", ""),
                "section": meta.get("section", ""),
                "domain": meta.get("domain", ""),
                "type": meta.get("type", ""),
                "text": (results["documents"][0][i] if results["documents"] else "")[:500],
            })

    return {"query": query, "domain": domain, "totalResults": len(entries), "results": entries}


def main():
    parser = argparse.ArgumentParser(description="Query Sentinel RAG Expertise KB")
    parser.add_argument("--query", required=True, help="Search query")
    parser.add_argument("--domain", default="all", help="Domain filter (embedding, chunking, hybrid-search, evaluation, security, architecture, chromadb, monitoring)")
    parser.add_argument("--limit", type=int, default=5, help="Max results")
    args = parser.parse_args()

    try:
        result = query_kb(args.query, args.domain, args.limit)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e), "query": args.query, "totalResults": 0, "results": []}))
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run query tests**

```bash
bash tests/test-sentinel-rag.sh
```

Expected: All tests PASS including query results for embedding, hybrid search, and security topics.

- [ ] **Step 5: Commit**

```bash
git add skills/sentinel-rag/knowledge/query.py tests/test-sentinel-rag.sh
git commit -m "feat(sentinel-rag): query CLI with bge-base asymmetric prefix"
```

---

### Task 3b: Golden Dataset

**Files:**
- Create: `skills/sentinel-rag/knowledge/golden_dataset.json`

- [ ] **Step 1: Create golden dataset with 15 query/expected-doc pairs**

Create `skills/sentinel-rag/knowledge/golden_dataset.json`:

```json
[
  {"query": "best embedding model for cybersecurity RAG", "expected_sources": ["05-claude-desktop.md", "07-gemini.md"], "category": "embedding"},
  {"query": "bge-base-en-v1.5 vs all-MiniLM-L6-v2", "expected_sources": ["05-claude-desktop.md", "06-mistral.md"], "category": "embedding"},
  {"query": "asymmetric embedding query prefix", "expected_sources": ["05-claude-desktop.md", "07-gemini.md"], "category": "embedding"},
  {"query": "how to chunk JSON documents for RAG", "expected_sources": ["05-claude-desktop.md", "07-gemini.md"], "category": "chunking"},
  {"query": "parent-child chunking strategy", "expected_sources": ["07-gemini.md", "05-claude-desktop.md"], "category": "chunking"},
  {"query": "hybrid search BM25 with ChromaDB", "expected_sources": ["05-claude-desktop.md", "01-embedding-chunking-hybrid.md"], "category": "hybrid-search"},
  {"query": "Reciprocal Rank Fusion RRF implementation", "expected_sources": ["05-claude-desktop.md", "07-gemini.md"], "category": "hybrid-search"},
  {"query": "cross-encoder reranking for RAG", "expected_sources": ["05-claude-desktop.md", "07-gemini.md"], "category": "hybrid-search"},
  {"query": "RAGAS evaluation framework for RAG", "expected_sources": ["02-evaluation-monitoring.md", "07-gemini.md"], "category": "evaluation"},
  {"query": "Hit@k MRR NDCG metrics for retrieval", "expected_sources": ["02-evaluation-monitoring.md", "07-gemini.md"], "category": "evaluation"},
  {"query": "HNSW tuning ef_construction M parameters", "expected_sources": ["04-chromadb-docs.md", "02-evaluation-monitoring.md"], "category": "chromadb"},
  {"query": "ChromaDB cosine vs L2 distance", "expected_sources": ["05-claude-desktop.md", "04-chromadb-docs.md"], "category": "chromadb"},
  {"query": "RAG poisoning attack detection", "expected_sources": ["03-architecture-security.md", "07-gemini.md"], "category": "security"},
  {"query": "OWASP LLM Top 10 RAG security", "expected_sources": ["03-architecture-security.md", "07-gemini.md"], "category": "security"},
  {"query": "HyDE hypothetical document embeddings", "expected_sources": ["03-architecture-security.md", "07-gemini.md"], "category": "architecture"}
]
```

- [ ] **Step 2: Add golden dataset validation test**

Append to `tests/test-sentinel-rag.sh` (before query tests):

```bash
# --- Golden dataset ---
echo ""
echo "--- Golden Dataset ---"
GOLDEN="$PROJECT_DIR/skills/sentinel-rag/knowledge/golden_dataset.json"
check "golden_dataset.json exists" "[ -f '$GOLDEN' ]"
check "golden dataset has 15 entries" "python3 -c 'import json; d=json.load(open(\"'$GOLDEN'\")); assert len(d)==15, f\"got {len(d)}\"'"
check "golden Hit@5 >= 80%" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 -c \"
import json
golden = json.load(open('golden_dataset.json'))
from query import query_kb
hits = 0
for entry in golden:
    r = query_kb(entry['query'], limit=5)
    sources_found = {x['source'] for x in r['results']}
    if any(s in sources_found for s in entry['expected_sources']):
        hits += 1
pct = hits / len(golden) * 100
print(f'Hit@5: {hits}/{len(golden)} ({pct:.0f}%)')
assert pct >= 80, f'Hit@5 too low: {pct:.0f}%'
\""
```

- [ ] **Step 3: Run test**

```bash
bash tests/test-sentinel-rag.sh
```

Expected: Golden dataset Hit@5 >= 80%.

- [ ] **Step 4: Commit**

```bash
git add skills/sentinel-rag/knowledge/golden_dataset.json tests/test-sentinel-rag.sh
git commit -m "test(sentinel-rag): golden dataset with 15 queries and Hit@5 validation"
```

---

### Task 4: SKILL.md

**Files:**
- Create: `skills/sentinel-rag/SKILL.md`
- Reference: `skills/security/SKILL.md` (existing skill pattern)
- Reference: `docs/superpowers/specs/2026-03-20-sentinel-rag-design.md` (sections 3, 5, 6)

This is the core skill file — conversational expert with embedded principles and KB consultation instructions.

- [ ] **Step 1: Write SKILL.md**

Create `skills/sentinel-rag/SKILL.md` with the full skill content. Key sections:

1. **Frontmatter** — `name: sentinel-rag`, `user_invocable: true`
2. **Persona** — Expert RAG autonome, conversationnel
3. **Self-Update Check** — Read metadata.json, check staleness >7 days, propose update
4. **Context Detection** — Glob/Grep to detect existing RAG, route to mode
5. **KB Consultation** — Before recommending, query the expertise KB
6. **6 Modes** — create, diagnose, optimize, evaluate, secure, maintain with checklists
7. **Embedded Quick Reference** — Top 3 embedding models, distances, anti-patterns
8. **Enrichment** — How to add new sources

The SKILL.md should be ~300-400 lines. All runtime paths are absolute (`/Users/manuelturpin/.sentinel/skills/sentinel-rag/...`).

Content outline (the full SKILL.md):

```markdown
---
name: sentinel-rag
description: Expert RAG autonome et auto-evolutif — cree, diagnostique, optimise, evalue et securise les systemes RAG. Maintient sa propre base de connaissances vectorielle.
user_invocable: true
---

# /sentinel-rag — Sentinel RAG Expert

You are an autonomous RAG (Retrieval-Augmented Generation) expert. You analyze context, consult your own knowledge base, and guide users through the full RAG lifecycle. You work with any vector database (ChromaDB, Qdrant, LanceDB, pgvector).

## Step 0: Self-Update Check

Before anything else, check your knowledge freshness:

1. Read `/Users/manuelturpin/.sentinel/skills/sentinel-rag/metadata.json`
2. Calculate days since `last_updated`
3. If > `update_check_interval_days` (default 7):
   - Tell the user: "My knowledge base was last updated on {date} ({N} days ago). Want me to do a quick web search for recent developments in embedding models, ChromaDB, and RAG techniques?"
   - If accepted: search web (3-5 queries), save relevant findings to sources/, re-index, update metadata
   - If declined: note the date and proceed

## Step 1: Context Detection

Detect what the user needs by analyzing the project:

1. **User explicitly requested a mode?** → Use that mode
2. **Auto-detect:**
   - Glob for: `**/chromadb/**`, `**/chroma.sqlite3`, `**/qdrant/**`, `**/lancedb/**`
   - Grep for: `chromadb`, `qdrant`, `lancedb`, `pgvector`, `sentence_transformers`, `SentenceTransformer`, `embedding`
   - If RAG detected → **diagnose** mode
   - If nothing detected → **create** mode
3. **Modes `evaluate`, `secure`, `maintain`** → explicit request only

## Step 2: Consult Knowledge Base

Before making any technical recommendation (embedding model, chunking strategy, search architecture, HNSW config, evaluation framework), consult your expertise KB:

```
Bash: python3 /Users/manuelturpin/.sentinel/skills/sentinel-rag/knowledge/query.py \
  --query "<formulate a specific question from the user's context>" \
  --domain <relevant domain: embedding|chunking|hybrid-search|evaluation|security|architecture|chromadb|monitoring|all> \
  --limit 5
```

Parse the JSON output. Use the `section` and `source` fields to cite your sources. Integrate the retrieved knowledge into your recommendation. If results are insufficient, query with different terms.

## Step 3: Execute Mode

### Mode: create

Guide the user to build a RAG from scratch:

1. **Understand the corpus** — Ask: size, document type (JSON/text/PDF), language, domain, update frequency
2. **Recommend embedding model** — Consult KB, present top 3 with trade-offs
3. **Recommend vector DB** — ChromaDB for <100K docs local, Qdrant for hybrid-native, pgvector if already using PostgreSQL
4. **Generate scaffolding** — Create `indexer.py`, `query.py`, `config.json` adapted to their corpus
5. **Configure HNSW** — Based on corpus size (see Quick Reference below)
6. **Set distance metric** — cosine for normalized embeddings, ip for bge/e5 with L2 norm
7. **Suggest golden dataset** — 50 representative queries with expected doc IDs

### Mode: diagnose

Audit an existing RAG system:

1. **Read config** — Find and read the RAG config (config.json, .env, or inline)
2. **Check embedding model** — Compare to current recommendations from KB
3. **Check distance** — L2 default is suboptimal; cosine or ip preferred
4. **Count documents** — Query collection.count()
5. **Check HNSW params** — ef_construction, M, search_ef vs corpus size
6. **Detect anti-patterns** — Raw JSON indexed? No metadata filters? No hybrid search?
7. **Check data freshness** — When was the last indexing?
8. **Produce health report** — Score 0-100 with findings and recommendations

### Mode: optimize

Implement improvements (after diagnosis or on request):

1. **Embedding upgrade** — Migrate to bge-base-en-v1.5 or nomic-embed-text with benchmark
2. **Hybrid search** — Add BM25 + RRF fusion (consult KB for implementation code)
3. **HNSW tuning** — Adjust params based on corpus size
4. **Cross-encoder reranking** — Add bge-reranker-base for top-k refinement
5. **Text templating** — Convert raw JSON to searchable text templates
6. **Query routing** — Regex detection for exact IDs (CVE-*, CWE-*) vs semantic
7. **Document expansion** — Generate hypothetical questions per doc

### Mode: evaluate

Benchmark RAG quality:

1. **Golden dataset** — Create or load pairs (query → expected_doc_ids with relevance scores)
2. **Run queries** — Execute each query, record results
3. **Calculate metrics** — Hit@5, MRR, NDCG@5
4. **Compare** — Before/after a modification
5. **Report** — Summary with per-category breakdown

### Mode: secure

Audit RAG security (also invoked by /sentinel-security):

1. **Source validation** — Are indexed documents from trusted sources?
2. **Poisoning detection** — Look for anomalous documents, outlier embeddings
3. **Prompt injection in docs** — Grep for injection patterns in indexed content
4. **Access control** — Who can read/write the collection?
5. **Map to standards** — OWASP LLM Top 10 2025 (LLM06, LLM08), NIST AI RMF
6. **Recommendations** — Actionable remediations

### Mode: maintain

Ongoing RAG maintenance:

1. **Re-index** — Full or incremental rebuild
2. **Backup** — Copy ChromaDB directory
3. **Garbage collection** — Find orphan/duplicate documents
4. **Embedding migration** — Re-embed entire collection with new model
5. **Drift monitoring** — Compare centroid shift between versions

## Quick Reference (Embedded)

### Top Embedding Models (2026)

| Model | Dims | MTEB Retrieval | Best For |
|---|---|---|---|
| BAAI/bge-base-en-v1.5 | 768 | ~53.3 | General production (recommended default) |
| nomic-embed-text-v1.5 | 768 | ~52.8 | Long docs (8K context) |
| BAAI/bge-small-en-v1.5 | 384 | ~51.7 | Resource-constrained |

### HNSW Config by Corpus Size

| Corpus Size | ef_construction | M | search_ef |
|---|---|---|---|
| < 10K docs | 128 | 16 | 64 |
| 10K-100K | 200 | 32 | 100 |
| > 100K | 400 | 48 | 200 |

### Distance Metrics

| Metric | When to Use |
|---|---|
| cosine | Default for text embeddings, most models |
| ip (inner product) | When embeddings are L2-normalized (faster than cosine) |
| L2 (euclidean) | Almost never for text — avoid |

### Top 5 Anti-Patterns

1. Indexing raw JSON instead of templated text
2. Using L2 distance (ChromaDB default) for text embeddings
3. No hybrid search — pure semantic misses exact identifiers (CVE-*, CWE-*)
4. Using all-MiniLM-L6-v2 when better models exist at same latency
5. No golden dataset — optimizing blindly without measurement

## Enrichment

To add knowledge to this skill:

1. Save new source: `cp article.md /Users/manuelturpin/.sentinel/skills/sentinel-rag/knowledge/sources/`
2. Re-index: `python3 /Users/manuelturpin/.sentinel/skills/sentinel-rag/knowledge/indexer.py`
3. The source will be chunked by H2, classified by domain, and available for future queries.

## Important Notes

- Always consult the KB before recommending — your embedded quick reference is a summary, the KB has the details
- Cite sources: mention the source file and section when making recommendations
- Be conversational — analyze the situation first, then propose actions
- Quick wins first — prioritize changes with highest impact/effort ratio
- Generic — your recommendations apply to any RAG, not just Sentinel's
```

- [ ] **Step 2: Verify SKILL.md structure**

Add to `tests/test-sentinel-rag.sh`:

```bash
echo ""
echo "--- SKILL.md ---"
SKILL="$PROJECT_DIR/skills/sentinel-rag/SKILL.md"
check "SKILL.md exists" "[ -f '$SKILL' ]"
check "SKILL.md has frontmatter name" "head -5 '$SKILL' | grep -q 'name: sentinel-rag'"
check "SKILL.md has user_invocable" "grep -q 'user_invocable: true' '$SKILL'"
check "SKILL.md references metadata.json" "grep -q 'metadata.json' '$SKILL'"
check "SKILL.md references query.py" "grep -q 'query.py' '$SKILL'"
check "SKILL.md has 6 modes" "grep -c '### Mode:' '$SKILL' | grep -q '6'"
```

- [ ] **Step 3: Run tests**

```bash
bash tests/test-sentinel-rag.sh
```

Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git add skills/sentinel-rag/SKILL.md tests/test-sentinel-rag.sh
git commit -m "feat(sentinel-rag): SKILL.md with 6 modes, self-update, and KB consultation"
```

---

### Task 5: Update deploy.sh

**Files:**
- Modify: `scripts/deploy.sh`

- [ ] **Step 1: Add sentinel-rag deployment block to deploy.sh**

After the existing sentinel-security skill deployment section (around line 97), add:

```bash
  # --- 3b. Deploy sentinel-rag skill ---
  SENTINEL_RAG_SKILL_DIR="$HOME/.claude/skills/sentinel-rag"
  SENTINEL_RAG_HOME="$SENTINEL_HOME/skills/sentinel-rag"

  info "Deploying sentinel-rag skill..."
  mkdir -p "$SENTINEL_RAG_SKILL_DIR"
  mkdir -p "$SENTINEL_RAG_HOME/knowledge/sources"

  cp "$PROJECT_DIR/skills/sentinel-rag/SKILL.md" "$SENTINEL_RAG_SKILL_DIR/SKILL.md"

  # Knowledge scripts + sources (NOT chromadb data)
  cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/indexer.py" "$SENTINEL_RAG_HOME/knowledge/"
  cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/query.py" "$SENTINEL_RAG_HOME/knowledge/"
  cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/config.json" "$SENTINEL_RAG_HOME/knowledge/"
  rsync -a "$PROJECT_DIR/skills/sentinel-rag/knowledge/sources/" "$SENTINEL_RAG_HOME/knowledge/sources/"

  # Metadata: only copy if absent (don't overwrite runtime state)
  [ ! -f "$SENTINEL_RAG_HOME/metadata.json" ] && \
    cp "$PROJECT_DIR/skills/sentinel-rag/metadata.json" "$SENTINEL_RAG_HOME/metadata.json"

  # Index sentinel-rag KB
  info "Indexing sentinel-rag expertise KB..."
  if command -v python3 &>/dev/null; then
    (cd "$SENTINEL_RAG_HOME/knowledge" && python3 indexer.py 2>&1) || warn "RAG expertise indexing failed"
  fi
```

Also update the verification section to check sentinel-rag:

```bash
  [ -f "$SENTINEL_RAG_SKILL_DIR/SKILL.md" ] && info "Sentinel-RAG Skill: OK" || { error "Sentinel-RAG Skill: MISSING"; ERRORS=$((ERRORS+1)); }
```

And update the final output messages:

```bash
  echo "  /sentinel-rag                              # RAG expert in any project"
```

- [ ] **Step 2: Test deploy locally**

```bash
bash scripts/deploy.sh
```

Expected: Deployment completes with "Sentinel-RAG Skill: OK" and indexing succeeds.

- [ ] **Step 3: Verify deployed files**

```bash
ls ~/.claude/skills/sentinel-rag/SKILL.md
ls ~/.sentinel/skills/sentinel-rag/knowledge/query.py
ls ~/.sentinel/skills/sentinel-rag/metadata.json
```

- [ ] **Step 4: Commit**

```bash
git add scripts/deploy.sh
git commit -m "feat(deploy): add sentinel-rag skill deployment"
```

---

### Task 6: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md references**

Replace all references to `/security` with `/sentinel-security`. Add `/sentinel-rag` to the commands section and architecture description.

Key changes:
- **Projet section**: Add sentinel-rag mention
- **Architecture section**: Add sentinel-rag skill entry
- **Commandes section**: Add `/sentinel-rag` command, rename `/security` to `/sentinel-security`
- **Structure cle section**: Add sentinel-rag paths

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with sentinel-rag and sentinel-security rename"
```

---

### Task 7: End-to-End Validation

**Files:**
- Modify: `tests/test-sentinel-rag.sh` (add final integration checks)

- [ ] **Step 1: Add deployment integration tests**

Append to `tests/test-sentinel-rag.sh`:

```bash
# --- Deployment integration ---
echo ""
echo "--- Deployment ---"
check "deployed SKILL.md exists" "[ -f '$HOME/.claude/skills/sentinel-rag/SKILL.md' ]"
check "deployed query.py exists" "[ -f '$HOME/.sentinel/skills/sentinel-rag/knowledge/query.py' ]"
check "deployed metadata.json exists" "[ -f '$HOME/.sentinel/skills/sentinel-rag/metadata.json' ]"
check "deployed KB indexed" "cd '$HOME/.sentinel/skills/sentinel-rag/knowledge' && python3 -c \"
import chromadb, json
cfg = json.load(open('config.json'))
c = chromadb.PersistentClient(path='./chromadb')
col = c.get_collection(cfg['collection_name'])
assert col.count() > 50, f'Only {col.count()} docs'
print(f'{col.count()} docs indexed')
\""
check "deployed query works" "cd '$HOME/.sentinel/skills/sentinel-rag/knowledge' && python3 query.py --query 'embedding model' --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"totalResults\"]>0'"
```

- [ ] **Step 2: Run full test suite**

```bash
bash tests/test-sentinel-rag.sh
```

Expected: All tests PASS (structure + indexer + query + SKILL.md + deployment).

- [ ] **Step 3: Run existing sentinel tests to verify no regression**

```bash
bash scripts/test-sentinel.sh
```

Expected: 31/31 still passing.

- [ ] **Step 4: Final commit + push**

```bash
git add tests/test-sentinel-rag.sh
git commit -m "test(sentinel-rag): complete E2E test suite"
git push
```

---

## Summary

| Task | What | Key Files |
|---|---|---|
| 1 | Config + metadata + sources + .gitignore | `config.json`, `metadata.json`, `sources/*.md`, `.gitignore` |
| 2 | Markdown indexer | `indexer.py`, `tests/test-sentinel-rag.sh` |
| 3 | Query CLI | `query.py` |
| 3b | Golden dataset + Hit@5 validation | `golden_dataset.json` |
| 4 | SKILL.md | `SKILL.md` |
| 5 | Deploy script | `scripts/deploy.sh` |
| 6 | CLAUDE.md update | `CLAUDE.md` |
| 7 | E2E validation | `tests/test-sentinel-rag.sh` |

8 tasks, ~8 commits. Tasks 1-3b are sequential (each builds on previous). Tasks 4-6 can parallel after 3b. Task 7 validates everything.

**Note**: The `/security` to `/sentinel-security` rename (SKILL.md frontmatter + deploy.sh) was already done earlier in this session. Task 6 only updates CLAUDE.md references. Cross-skill integration (sentinel-security dispatching to sentinel-rag secure mode) is a future task — not blocking for v1.
