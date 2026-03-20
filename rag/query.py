"""
Sentinel RAG Query — CLI for querying the Knowledge Base via ChromaDB.
Supports hybrid search (BM25 + semantic + cross-encoder reranking) with RRF.

Pipeline: Query → ID routing (exact) → Hybrid search (semantic + BM25/RRF) → Top-k

Usage:
    python3 query.py --query "SQL injection" --domain all --limit 10
    python3 query.py --query "CWE-89" --limit 1

Outputs JSON to stdout for consumption by the TypeScript MCP server.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

try:
    import chromadb
    from sentence_transformers import SentenceTransformer
except ImportError as _imp_err:
    print(f"Missing dependency: {_imp_err}\nInstall with: pip install sentence-transformers chromadb", file=sys.stderr)
    sys.exit(1)

try:
    from rank_bm25 import BM25Okapi
    HAS_BM25 = True
except ImportError:
    HAS_BM25 = False


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

# Regex for exact identifier queries
ID_PATTERN = re.compile(
    r'^(?:CVE-\d{4}-\d{4,}|CWE-\d+|[A-Z]+-[A-Z]+-\d+|A\d{2}|AML\.TA\d{4})$',
    re.IGNORECASE,
)


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def _tokenize(text: str) -> list[str]:
    """Tokenize preserving CVE/CWE/rule identifiers as single tokens."""
    text = text.lower()
    return re.findall(r'cve-\d{4}-\d+|cwe-\d+|[a-z]+-[a-z]+-\d+|[a-z0-9]+', text)


def _rrf_fuse(semantic_ids: list[str], bm25_ids: list[str], alpha: float = 0.6, k: int = 60) -> list[str]:
    """Reciprocal Rank Fusion of semantic and BM25 results."""
    scores = defaultdict(float)
    for rank, doc_id in enumerate(semantic_ids):
        scores[doc_id] += alpha * (1.0 / (k + rank + 1))
    for rank, doc_id in enumerate(bm25_ids):
        scores[doc_id] += (1 - alpha) * (1.0 / (k + rank + 1))
    return [doc_id for doc_id, _ in sorted(scores.items(), key=lambda x: x[1], reverse=True)]


def query_kb(query: str, domain: str = "all", limit: int = 10) -> dict:
    """Query ChromaDB with hybrid search (semantic + BM25 via RRF)."""
    config = load_config()
    chromadb_path = os.path.join(os.path.dirname(__file__), config["chromadb_path"])

    if not os.path.isdir(chromadb_path):
        return {
            "query": query, "domain": domain, "totalResults": 0, "results": [],
            "error": f"ChromaDB directory not found at {chromadb_path}. Run indexer.py first.",
        }

    client = chromadb.PersistentClient(path=chromadb_path)

    try:
        collection = client.get_collection(config["collection_name"])
    except ValueError:
        return {
            "query": query, "domain": domain, "totalResults": 0, "results": [],
            "error": "Collection not found. Run indexer.py first.",
        }

    count = collection.count()
    if count == 0:
        return {"query": query, "domain": domain, "totalResults": 0, "results": []}

    # Build where filter for domain
    where_filter = None
    if domain != "all":
        where_filter = {"domain": domain}

    # --- Query routing: exact ID → metadata filter ---
    query_stripped = query.strip()
    if ID_PATTERN.match(query_stripped):
        # Try exact match by ID first
        try:
            exact = collection.get(ids=[query_stripped.upper()], include=["documents", "metadatas"])
            if exact["ids"]:
                entries = []
                for i, doc_id in enumerate(exact["ids"]):
                    meta = exact["metadatas"][i] if exact["metadatas"] else {}
                    standards_raw = meta.get("standards", "[]")
                    try:
                        standards = json.loads(standards_raw) if isinstance(standards_raw, str) else standards_raw
                    except json.JSONDecodeError:
                        standards = [standards_raw] if standards_raw else []
                    if isinstance(standards, str):
                        standards = [standards]
                    entries.append({
                        "id": doc_id, "score": 1.0,
                        "domain": meta.get("domain", ""), "title": meta.get("title", ""),
                        "severity": meta.get("severity", "UNKNOWN"),
                        "description": exact["documents"][i] if exact["documents"] else "",
                        "standards": standards, "source": meta.get("source", ""),
                    })
                return {"query": query, "domain": domain, "totalResults": len(entries), "results": entries}
        except Exception:
            pass  # Fall through to hybrid search

    # --- Semantic search ---
    n_fetch = min(limit * 3, count)
    model = SentenceTransformer(config["embedding_model"])
    query_prefix = config.get("query_prefix", "")
    prefixed_query = query_prefix + query[:1000]
    query_embedding = model.encode([prefixed_query], normalize_embeddings=True).tolist()

    sem_results = collection.query(
        query_embeddings=query_embedding,
        n_results=n_fetch,
        where=where_filter,
        include=["documents", "metadatas", "distances"],
    )

    sem_ids = sem_results["ids"][0] if sem_results["ids"] else []
    sem_docs = sem_results["documents"][0] if sem_results["documents"] else []
    sem_metas = sem_results["metadatas"][0] if sem_results["metadatas"] else []
    sem_dists = sem_results["distances"][0] if sem_results["distances"] else []

    # Build doc lookup from semantic results
    doc_lookup = {}
    for i, doc_id in enumerate(sem_ids):
        doc_lookup[doc_id] = {
            "document": sem_docs[i] if i < len(sem_docs) else "",
            "metadata": sem_metas[i] if i < len(sem_metas) else {},
            "distance": sem_dists[i] if i < len(sem_dists) else 1.0,
        }

    # --- BM25 search (if available) ---
    if HAS_BM25 and sem_docs:
        tokenized_docs = [_tokenize(doc) for doc in sem_docs]
        bm25 = BM25Okapi(tokenized_docs)
        query_tokens = _tokenize(query)
        bm25_scores = bm25.get_scores(query_tokens)

        # Rank by BM25 score
        bm25_ranked = sorted(
            [(sem_ids[i], bm25_scores[i]) for i in range(len(sem_ids)) if bm25_scores[i] > 0],
            key=lambda x: x[1], reverse=True,
        )
        bm25_ids = [doc_id for doc_id, _ in bm25_ranked]

        # RRF fusion
        fused_ids = _rrf_fuse(sem_ids, bm25_ids, alpha=0.6, k=60)
    else:
        fused_ids = sem_ids

    # --- Build response ---
    entries = []
    for doc_id in fused_ids[:limit]:
        if doc_id not in doc_lookup:
            continue
        info = doc_lookup[doc_id]
        meta = info["metadata"]
        distance = info["distance"]
        score = round(max(0, 1 - distance / 2), 4)

        standards_raw = meta.get("standards", "[]")
        try:
            standards = json.loads(standards_raw) if isinstance(standards_raw, str) else standards_raw
        except json.JSONDecodeError:
            standards = [standards_raw] if standards_raw else []
        if isinstance(standards, str):
            standards = [standards]

        entries.append({
            "id": doc_id,
            "score": score,
            "domain": meta.get("domain", ""),
            "title": meta.get("title", ""),
            "severity": meta.get("severity", "UNKNOWN"),
            "description": info["document"],
            "standards": standards,
            "source": meta.get("source", ""),
        })

    return {
        "query": query,
        "domain": domain,
        "totalResults": len(entries),
        "results": entries,
    }


def main():
    parser = argparse.ArgumentParser(description="Query Sentinel Knowledge Base")
    parser.add_argument("--query", required=True, help="Search query")
    parser.add_argument("--domain", default="all", help="Domain filter")
    parser.add_argument("--limit", type=int, default=10, help="Max results")
    args = parser.parse_args()

    try:
        result = query_kb(args.query, args.domain, args.limit)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e), "query": args.query, "domain": args.domain, "totalResults": 0, "results": []}))
        sys.exit(1)


if __name__ == "__main__":
    main()
