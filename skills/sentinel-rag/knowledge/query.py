"""
Sentinel RAG Skill — Query CLI
Searches the RAG expertise knowledge base using bge-base-en-v1.5 with asymmetric prefix.

Usage:
    python3 query.py --query "best embedding model for cybersecurity" --limit 5
    python3 query.py --query "hybrid search" --domain hybrid-search --limit 3
"""

import argparse
import json
import logging
import os
import sys
import warnings

# Suppress noisy progress output so stdout stays clean JSON.
# TQDM_DISABLE must be set before importing sentence_transformers/tqdm.
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ["TQDM_DISABLE"] = "1"
logging.disable(logging.WARNING)
warnings.filterwarnings("ignore")

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

    # Load model while redirecting stdout to stderr so tqdm progress bars
    # don't corrupt the JSON output on stdout.
    _real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        model = SentenceTransformer(config["embedding_model"])
    finally:
        sys.stdout = _real_stdout
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
