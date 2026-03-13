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

Pending — Session 9.
