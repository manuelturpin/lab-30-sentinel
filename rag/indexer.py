"""
Sentinel RAG Indexer — Indexes Knowledge Base rules into ChromaDB
for semantic search capabilities.
"""

import json
import glob
import os
import sys

import chromadb
from sentence_transformers import SentenceTransformer

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
KB_BASE = os.path.join(os.path.dirname(__file__), "..", "knowledge-base")


def load_config():
    """Load RAG configuration."""
    with open(CONFIG_PATH) as f:
        return json.load(f)


def _extract_domain(filepath: str) -> str:
    """Extract domain name from filepath (e.g. .../domains/web-app/... -> web-app)."""
    parts = filepath.replace("\\", "/").split("/")
    if "domains" in parts:
        idx = parts.index("domains")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "general"


def _build_text(rule: dict) -> str:
    """Build searchable text from a rule or pattern entry."""
    parts = [
        rule.get("title", ""),
        rule.get("description", ""),
    ]
    # Rules have remediation as dict, patterns have it as string
    rem = rule.get("remediation", "")
    if isinstance(rem, dict):
        parts.append(rem.get("description", ""))
    elif isinstance(rem, str):
        parts.append(rem)
    # Include subcategory/type for better search
    parts.append(rule.get("subcategory", ""))
    parts.append(rule.get("type", ""))
    return " ".join(p for p in parts if p)


def collect_documents(config: dict) -> list[dict]:
    """Collect all documents from KB sources for indexing."""
    documents = []
    seen_ids = set()
    rag_dir = os.path.dirname(os.path.abspath(__file__))
    for pattern in config["sources"]:
        full_pattern = os.path.normpath(os.path.join(rag_dir, pattern))
        for filepath in glob.glob(full_pattern, recursive=True):
            try:
                with open(filepath) as f:
                    data = json.load(f)

                rules = data if isinstance(data, list) else [data]
                domain = _extract_domain(filepath)
                for rule in rules:
                    if isinstance(rule, dict) and "id" in rule:
                        if rule["id"] in seen_ids:
                            continue
                        seen_ids.add(rule["id"])
                        documents.append({
                            "id": rule["id"],
                            "text": _build_text(rule),
                            "metadata": {
                                "source": filepath,
                                "domain": rule.get("category", domain),
                                "severity": rule.get("severity", "UNKNOWN"),
                                "category": rule.get("subcategory", rule.get("type", "")),
                                "title": rule.get("title", ""),
                                "standards": json.dumps(rule.get("standards", rule.get("cwe", []))),
                            },
                        })
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Could not parse {filepath}: {e}", file=sys.stderr)
                continue

    return documents


def index_documents(documents: list[dict], config: dict):
    """Index documents into ChromaDB with sentence-transformer embeddings."""
    chromadb_path = os.path.join(os.path.dirname(__file__), config["chromadb_path"])
    client = chromadb.PersistentClient(path=chromadb_path)

    # Delete and recreate for clean index
    try:
        client.delete_collection(config["collection_name"])
    except Exception:
        pass

    collection = client.create_collection(
        name=config["collection_name"],
        metadata={"hnsw:space": "cosine"},
    )

    print(f"Loading embedding model: {config['embedding_model']}...")
    model = SentenceTransformer(config["embedding_model"])

    # Batch upsert (ChromaDB max batch ~5000)
    batch_size = 500
    for i in range(0, len(documents), batch_size):
        batch = documents[i : i + batch_size]
        ids = [doc["id"] for doc in batch]
        texts = [doc["text"] for doc in batch]
        metadatas = [doc["metadata"] for doc in batch]

        embeddings = model.encode(texts, show_progress_bar=False).tolist()

        collection.add(
            ids=ids,
            documents=texts,
            embeddings=embeddings,
            metadatas=metadatas,
        )
        print(f"  Indexed batch {i // batch_size + 1}: {len(batch)} documents")

    print(f"Total: {collection.count()} documents in collection '{config['collection_name']}'")


def main():
    """Main entry point for KB indexing."""
    print("=== Sentinel RAG Indexer ===")

    config = load_config()
    print(f"Config loaded: {config['collection_name']}")

    documents = collect_documents(config)
    print(f"Collected {len(documents)} documents from KB")

    if not documents:
        print("No documents found. Check source patterns in config.json.")
        sys.exit(1)

    index_documents(documents, config)
    print("Indexing complete.")


if __name__ == "__main__":
    main()
