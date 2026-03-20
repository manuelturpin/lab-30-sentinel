"""
Sentinel RAG Query — CLI for querying the Knowledge Base via ChromaDB.

Usage:
    python3 query.py --query "SQL injection" --domain all --limit 10

Outputs JSON to stdout for consumption by the TypeScript MCP server.
"""

import argparse
import json
import os
import sys

try:
    import chromadb
    from sentence_transformers import SentenceTransformer
except ImportError as _imp_err:
    print(f"Missing dependency: {_imp_err}\nInstall with: pip install sentence-transformers chromadb", file=sys.stderr)
    sys.exit(1)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def query_kb(query: str, domain: str = "all", limit: int = 10) -> dict:
    """Query ChromaDB and return results as a dict."""
    config = load_config()
    chromadb_path = os.path.join(os.path.dirname(__file__), config["chromadb_path"])

    if not os.path.isdir(chromadb_path):
        return {
            "query": query,
            "domain": domain,
            "totalResults": 0,
            "results": [],
            "error": f"ChromaDB directory not found at {chromadb_path}. Run indexer.py first.",
        }

    client = chromadb.PersistentClient(path=chromadb_path)

    try:
        collection = client.get_collection(config["collection_name"])
    except ValueError:
        return {
            "query": query,
            "domain": domain,
            "totalResults": 0,
            "results": [],
            "error": "Collection not found. Run indexer.py first.",
        }

    count = collection.count()
    if count == 0:
        return {"query": query, "domain": domain, "totalResults": 0, "results": []}

    # Load embedding model
    model = SentenceTransformer(config["embedding_model"])
    # bge-base asymmetric: prefix for queries, normalize for cosine
    query_prefix = config.get("query_prefix", "")
    prefixed_query = query_prefix + query[:1000]
    query_embedding = model.encode([prefixed_query], normalize_embeddings=True).tolist()

    # Build where filter for domain
    where_filter = None
    if domain != "all":
        where_filter = {"domain": domain}

    results = collection.query(
        query_embeddings=query_embedding,
        n_results=min(limit, count),
        where=where_filter,
        include=["documents", "metadatas", "distances"],
    )

    # Map to KBEntry format
    entries = []
    if results["ids"] and results["ids"][0]:
        for i, doc_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            distance = results["distances"][0][i] if results["distances"] else 1.0
            # ChromaDB cosine distance: 0 = identical, 2 = opposite
            # Convert to similarity score 0-1
            score = round(max(0, 1 - distance / 2), 4)

            standards_raw = meta.get("standards", "[]")
            try:
                standards = json.loads(standards_raw) if isinstance(standards_raw, str) else standards_raw
            except json.JSONDecodeError:
                standards = [standards_raw] if standards_raw else []
            # Normalize: if standards is a single string, wrap in list
            if isinstance(standards, str):
                standards = [standards]

            entries.append({
                "id": doc_id,
                "score": score,
                "domain": meta.get("domain", ""),
                "title": meta.get("title", ""),
                "severity": meta.get("severity", "UNKNOWN"),
                "description": results["documents"][0][i] if results["documents"] else "",
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
