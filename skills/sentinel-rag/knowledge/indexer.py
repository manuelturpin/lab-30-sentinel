"""
Sentinel RAG Skill — Markdown Indexer
Chunks Markdown documents by H2 headings and indexes into ChromaDB
with BAAI/bge-base-en-v1.5 embeddings.

Supports two source formats:
  - Pure Markdown (.md files with ## headings)
  - JSONL conversation exports (Claude session logs — extracts assistant text blocks)

For files without H2 headings, falls back to paragraph-based chunking (~800 words/chunk).
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

CHUNK_TOKEN_LIMIT = 1000   # rough word*1.3 threshold for H2→H3 split
PARA_WORD_LIMIT = 800      # max words per paragraph-mode chunk
PARA_MIN_CHARS = 200       # skip paragraphs shorter than this

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


def extract_text_from_jsonl(content: str) -> str:
    """Extract assistant text blocks from a JSONL conversation export.

    Each line is a JSON object. We collect text blocks from assistant messages
    that are longer than PARA_MIN_CHARS (short intro sentences are skipped).
    """
    texts = []
    for line in content.strip().split("\n"):
        try:
            obj = json.loads(line)
            if obj.get("type") != "assistant":
                continue
            msg_content = obj.get("message", {}).get("content", "")
            if isinstance(msg_content, list):
                for block in msg_content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        t = block["text"].strip()
                        if len(t) > PARA_MIN_CHARS:
                            texts.append(t)
            elif isinstance(msg_content, str) and len(msg_content) > PARA_MIN_CHARS:
                texts.append(msg_content.strip())
        except Exception:
            pass
    return "\n\n".join(texts)


def split_by_h2_h3(text: str, filename: str) -> list[dict]:
    """Split text into chunks by H2 headings; split large H2 sections on H3."""
    chunks = []
    h2_pattern = re.compile(r"^## (.+)$", re.MULTILINE)
    h2_splits = h2_pattern.split(text)

    # Preamble (text before first H2)
    if h2_splits[0].strip():
        preamble = h2_splits[0].strip()
        h1_match = re.search(r"^# (.+)$", preamble, re.MULTILINE)
        title = h1_match.group(1) if h1_match else "Introduction"
        chunks.append({
            "source": filename,
            "section": title,
            "heading_level": 1,
            "text": preamble,
        })

    for i in range(1, len(h2_splits), 2):
        if i >= len(h2_splits):
            break
        title = h2_splits[i].strip()
        body = h2_splits[i + 1] if i + 1 < len(h2_splits) else ""
        section_text = f"## {title}\n\n{body}".strip()

        est_tokens = len(section_text.split()) * 1.3

        if est_tokens > CHUNK_TOKEN_LIMIT:
            # Split on H3
            h3_pattern = re.compile(r"^### (.+)$", re.MULTILINE)
            h3_splits = h3_pattern.split(section_text)
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


def split_by_paragraphs(text: str, filename: str) -> list[dict]:
    """Fallback chunker for files without H2 headings.

    Splits on blank lines, groups paragraphs into ~PARA_WORD_LIMIT-word chunks.
    Short paragraphs (< PARA_MIN_CHARS) are skipped.
    """
    paras = [
        p.strip()
        for p in re.split(r"\n{2,}", text)
        if p.strip() and len(p.strip()) >= PARA_MIN_CHARS
    ]

    chunks = []
    current: list[str] = []
    current_words = 0

    for para in paras:
        words = len(para.split())
        if current_words + words > PARA_WORD_LIMIT and current:
            chunk_text = "\n\n".join(current)
            chunks.append({
                "source": filename,
                "section": f"Part {len(chunks) + 1}",
                "heading_level": 2,
                "text": chunk_text,
            })
            current = [para]
            current_words = words
        else:
            current.append(para)
            current_words += words

    if current:
        chunk_text = "\n\n".join(current)
        chunks.append({
            "source": filename,
            "section": f"Part {len(chunks) + 1}",
            "heading_level": 2,
            "text": chunk_text,
        })

    return chunks


def chunk_markdown(filepath: str) -> list[dict]:
    """Auto-detect file format and split into indexable chunks.

    - JSONL conversation export: extract assistant text blocks first
    - Pure Markdown with >= 2 H2 headings: split by H2/H3
    - Otherwise: split by paragraphs (~800 words/chunk)
    """
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    filename = os.path.basename(filepath)

    # Detect JSONL format (Claude conversation export)
    first_line = content.strip().split("\n")[0]
    if first_line.startswith("{"):
        text = extract_text_from_jsonl(content)
    else:
        text = content

    # Choose chunking strategy based on H2 heading count
    h2_count = len(re.findall(r"^## .+", text, re.MULTILINE))
    if h2_count >= 2:
        return split_by_h2_h3(text, filename)
    else:
        return split_by_paragraphs(text, filename)


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
        # bge-base: no prefix for documents (prefix is for queries only)
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
