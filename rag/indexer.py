"""
Sentinel RAG Indexer — Indexes Knowledge Base rules into ChromaDB
for semantic search capabilities.

Skeleton for Session 6 implementation.
"""

import json
import glob
import os

# ChromaDB and sentence-transformers will be installed via setup.sh
# import chromadb
# from sentence_transformers import SentenceTransformer

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
KB_BASE = os.path.join(os.path.dirname(__file__), "..", "knowledge-base")


def load_config():
    """Load RAG configuration."""
    with open(CONFIG_PATH) as f:
        return json.load(f)


def collect_documents(config: dict) -> list[dict]:
    """Collect all documents from KB sources for indexing."""
    documents = []
    for pattern in config["sources"]:
        # Resolve pattern relative to project root (parent of rag/)
        project_root = os.path.dirname(os.path.dirname(__file__))
        full_pattern = os.path.join(project_root, pattern.lstrip("../"))
        for filepath in glob.glob(full_pattern, recursive=True):
            try:
                with open(filepath) as f:
                    data = json.load(f)

                # Handle both single rules and arrays of rules
                rules = data if isinstance(data, list) else [data]
                for rule in rules:
                    if isinstance(rule, dict) and "id" in rule:
                        documents.append({
                            "id": rule["id"],
                            "text": f"{rule.get('title', '')} {rule.get('description', '')} {rule.get('remediation', {}).get('description', '')}",
                            "metadata": {
                                "source": filepath,
                                "severity": rule.get("severity", "UNKNOWN"),
                                "category": rule.get("category", ""),
                                "standards": json.dumps(rule.get("standards", [])),
                            },
                        })
            except (json.JSONDecodeError, KeyError):
                print(f"Warning: Could not parse {filepath}")
                continue

    return documents


def index_documents(documents: list[dict], config: dict):
    """Index documents into ChromaDB."""
    # Skeleton — Session 6 implementation
    print(f"Would index {len(documents)} documents into collection '{config['collection_name']}'")
    print(f"Using embedding model: {config['embedding_model']}")
    print(f"ChromaDB path: {config['chromadb_path']}")


def main():
    """Main entry point for KB indexing."""
    print("=== Sentinel RAG Indexer ===")

    config = load_config()
    print(f"Config loaded: {config['collection_name']}")

    documents = collect_documents(config)
    print(f"Collected {len(documents)} documents from KB")

    index_documents(documents, config)
    print("Indexing complete.")


if __name__ == "__main__":
    main()
