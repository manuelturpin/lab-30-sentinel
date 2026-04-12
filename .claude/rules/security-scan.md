---
paths:
  - "knowledge-base/**/*.json"
  - "**/rules.json"
---

# Security KB Rules

- Never manually edit CVSS scores — they are computed from the NVD/OSV feeds
- Always validate JSON schema after editing any rules.json file
- Never include real secrets, API keys, or tokens in rules examples — use `[REDACTED]`
- After modifying rules, re-index the RAG: `python3 rag/indexer.py`
