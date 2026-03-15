---
name: kb-update
description: Met a jour hebdomadairement la Knowledge Base et re-indexe les embeddings ChromaDB
schedule: "0 9 * * 1"
---

# KB Update — Weekly Knowledge Base Refresh

## Purpose

Keep the Knowledge Base and RAG index current by:
1. Updating rules with new vulnerability patterns
2. Re-indexing all rules in ChromaDB for semantic search
3. Updating standard references (OWASP, CWE, MITRE)

## Process

1. Check for updates to OWASP, CWE, MITRE ATLAS references
2. Merge new CVE patterns into domain rule files
3. Re-run the ChromaDB indexer (`rag/indexer.py`)
4. Validate embedding quality with test queries
5. Log update summary

## Implementation

**Script:** `scripts/kb-update.py`

```bash
# Manual run
python3 scripts/kb-update.py

# Dry run (preview only)
python3 scripts/kb-update.py --dry-run

# Generate rules without re-indexing ChromaDB
python3 scripts/kb-update.py --skip-reindex
```

## Automated Installation

Runs weekly (Monday 9h) as part of the unified cron pipeline:

```bash
crontab -e
0 6 * * * cd /path/to/lab-30-sentinel && bash scripts/sentinel-cron.sh >> logs/sentinel-cron.log 2>&1
```

## Dependencies

- Requires `cve-sync.py` to have run at least once (non-empty caches)
- ChromaDB + sentence-transformers (`pip3 install chromadb sentence-transformers`)
