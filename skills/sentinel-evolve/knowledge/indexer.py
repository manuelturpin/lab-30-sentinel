"""
Sentinel Evolve — Knowledge Base Indexer

Chunks Markdown sources (changelog, skill catalogs, patterns) and JSON feature
inventory into ChromaDB with BAAI/bge-base-en-v1.5 embeddings.

Adapted from sentinel-rag/knowledge/indexer.py with evolve-specific domain classification.
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

CHUNK_TOKEN_LIMIT = 1000
PARA_WORD_LIMIT = 800
PARA_MIN_CHARS = 150

# Evolve-specific domain classification
DOMAIN_KEYWORDS = {
    "skills": ["SKILL.md", "frontmatter", "user_invocable", "paths:", "effort", "mode", "slash command"],
    "agents": ["agent", "teammate", "team lead", "background", "maxTurns", "disallowedTools", "memory", "subagent"],
    "hooks": ["hook", "FileChanged", "CwdChanged", "PostToolUse", "HTTP hook", "command hook", "SessionStart", "PreToolUse", "StopFailure"],
    "mcp": ["MCP", "server", "elicitation", "OAuth", "transport", "stdio", "tool", "resource"],
    "performance": ["fast mode", "streaming", "resume", "context", "output limit", "token", "cache", "compact"],
    "config": ["managed-settings", "sandbox", "SUBPROCESS_ENV_SCRUB", "auto mode", "settings.json", "plist", "registry"],
    "models": ["Opus", "Sonnet", "Haiku", "model", "context window", "1M", "128k"],
    "cli": ["--bare", "--channels", "--worktree", "-p", "flag", "command line", "CLI"],
    "isolation": ["worktree", "sparse", "isolation", "branch", "fork"],
}


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def classify_domain(text):
    text_lower = text.lower()
    scores = {}
    for domain, keywords in DOMAIN_KEYWORDS.items():
        scores[domain] = sum(1 for kw in keywords if kw.lower() in text_lower)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "general"


def classify_type(text):
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["deprecat", "removed", "breaking", "migration"]):
        return "deprecation"
    if any(kw in text_lower for kw in ["new", "added", "feature", "support"]):
        return "feature"
    if "```" in text:
        return "code"
    return "info"


def split_by_h2_h3(text, filename):
    """Split text into chunks by H2 headings; split large H2 sections on H3."""
    chunks = []
    h2_pattern = re.compile(r"^## (.+)$", re.MULTILINE)
    h2_splits = h2_pattern.split(text)

    if h2_splits[0].strip():
        preamble = h2_splits[0].strip()
        h1_match = re.search(r"^# (.+)$", preamble, re.MULTILINE)
        title = h1_match.group(1) if h1_match else "Introduction"
        chunks.append({"source": filename, "section": title, "heading_level": 1, "text": preamble})

    for i in range(1, len(h2_splits), 2):
        if i >= len(h2_splits):
            break
        title = h2_splits[i].strip()
        body = h2_splits[i + 1] if i + 1 < len(h2_splits) else ""
        section_text = f"## {title}\n\n{body}".strip()
        est_tokens = len(section_text.split()) * 1.3

        if est_tokens > CHUNK_TOKEN_LIMIT:
            h3_pattern = re.compile(r"^### (.+)$", re.MULTILINE)
            h3_splits = h3_pattern.split(section_text)
            if h3_splits[0].strip():
                chunks.append({"source": filename, "section": title, "heading_level": 2, "text": h3_splits[0].strip()})
            for j in range(1, len(h3_splits), 2):
                h3_title = h3_splits[j].strip()
                h3_body = h3_splits[j + 1] if j + 1 < len(h3_splits) else ""
                chunks.append({
                    "source": filename,
                    "section": f"{title} > {h3_title}",
                    "heading_level": 3,
                    "text": f"### {h3_title}\n\n{h3_body}".strip(),
                })
        else:
            chunks.append({"source": filename, "section": title, "heading_level": 2, "text": section_text})

    return chunks


def split_by_paragraphs(text, filename):
    """Fallback chunker for files without H2 headings."""
    paras = [p.strip() for p in re.split(r"\n{2,}", text) if p.strip() and len(p.strip()) >= PARA_MIN_CHARS]
    chunks = []
    current = []
    current_words = 0

    for para in paras:
        words = len(para.split())
        if current_words + words > PARA_WORD_LIMIT and current:
            chunks.append({"source": filename, "section": f"Part {len(chunks) + 1}", "heading_level": 2, "text": "\n\n".join(current)})
            current = [para]
            current_words = words
        else:
            current.append(para)
            current_words += words

    if current:
        chunks.append({"source": filename, "section": f"Part {len(chunks) + 1}", "heading_level": 2, "text": "\n\n".join(current)})
    return chunks


def chunk_markdown(filepath):
    with open(filepath, encoding="utf-8") as f:
        text = f.read()
    filename = os.path.basename(filepath)
    h2_count = len(re.findall(r"^## .+", text, re.MULTILINE))
    if h2_count >= 2:
        return split_by_h2_h3(text, filename)
    else:
        return split_by_paragraphs(text, filename)


def collect_feature_inventory(config):
    """Index feature inventory JSON as individual documents."""
    documents = []
    inv_path = config.get("feature_inventory_path")
    if not inv_path:
        return documents

    abs_path = os.path.normpath(os.path.join(os.path.dirname(__file__), inv_path))
    if not os.path.isfile(abs_path):
        print(f"  Feature inventory not found: {abs_path}")
        return documents

    with open(abs_path) as f:
        inventory = json.load(f)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for key, feat in inventory.get("features", {}).items():
        text = (
            f"Claude Code feature: {key}\n"
            f"Introduced in version {feat.get('introduced', '?')} on {feat.get('date', '?')}.\n"
            f"Category: {feat.get('category', 'unknown')}. Status: {feat.get('status', 'unknown')}.\n"
            f"{feat.get('description', '')}"
        )
        documents.append({
            "id": f"feature:{key}",
            "text": text,
            "metadata": {
                "source": "feature-inventory.json",
                "section": key,
                "heading_level": 2,
                "type": "feature",
                "domain": feat.get("category", "general"),
                "date_indexed": today,
            },
        })

    return documents


def collect_markdown_sources(config):
    """Collect and chunk markdown sources."""
    documents = []
    rag_dir = os.path.dirname(os.path.abspath(__file__))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for pattern in config.get("sources", []):
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


def index_documents(documents, config):
    """Index documents into ChromaDB."""
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
        embeddings = model.encode(texts, normalize_embeddings=True, show_progress_bar=False).tolist()
        collection.add(ids=ids, documents=texts, embeddings=embeddings, metadatas=metadatas)
        print(f"  Indexed batch {i // batch_size + 1}: {len(batch)} chunks")

    total = collection.count()
    print(f"Total: {total} chunks in collection '{config['collection_name']}'")
    return total


def update_metadata(total_docs):
    if not os.path.isfile(METADATA_PATH):
        return
    with open(METADATA_PATH) as f:
        meta = json.load(f)
    meta["total_indexed_docs"] = total_docs
    meta["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta["total_sources"] = len(glob.glob(os.path.join(os.path.dirname(__file__), "sources", "*.md")))
    with open(METADATA_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Metadata updated: {total_docs} docs indexed")


def main():
    print("=== Sentinel Evolve — KB Indexer ===")
    config = load_config()
    print(f"Collection: {config['collection_name']}")
    print(f"Model: {config['embedding_model']}")

    # Collect from both sources
    md_docs = collect_markdown_sources(config)
    feat_docs = collect_feature_inventory(config)
    documents = md_docs + feat_docs

    print(f"Collected {len(md_docs)} markdown chunks + {len(feat_docs)} feature entries = {len(documents)} total")

    if not documents:
        print("No documents found. Run anthropic-sync.py first to populate sources.")
        sys.exit(1)

    total = index_documents(documents, config)
    update_metadata(total)
    print("Indexing complete.")


if __name__ == "__main__":
    main()
