# Sentinel Roadmap

| Session | Focus | Status |
|---------|-------|--------|
| 1 | Fondations (structure, skill, agents, stack detector) | Done |
| 2 | KB: Web + API rules (OWASP Web/API Top 10) — 36 rules, 38 patterns | Done |
| 3 | KB: LLM/AI + Supply Chain (OWASP LLM, MITRE ATLAS) — 27 rules, 43 patterns | Done |
| 4 | KB: Mobile + Infra + DB + Privacy — 37 rules, 41 patterns | Done |
| 5 | MCP Server (6 outils: scan-project, scan-secrets, scan-deps, scan-headers, query-kb, query-cve) | Done |
| 6 | RAG ChromaDB (231 docs indexes, all-MiniLM-L6-v2) | Done |
| 7 | Agent implementation (execution protocols, MCP tool mapping, Finding[] output, E2E tests) | Done |
| 8 | Orchestrator finalization + Reports (SARIF completion, SBOM implementation, report rendering) | Pending |
| 9 | Crons + Automated monitoring (CVE sync, KB update, project rescan) | Pending |
| 10 | End-to-end testing + Polish (full /security flow, error handling, perf) | Pending |

## Metrics

- **Knowledge Base**: 100 rules across 11 domains (web-app, api, llm-ai, mobile, infrastructure, supply-chain, database, data-privacy, ssl-tls, cors, static-sites)
- **RAG**: 231 documents indexed in ChromaDB
- **MCP Server**: 6 tools operational
- **Agents**: 12 specialized agents with execution protocols
- **E2E tests**: web-audit (13 findings), llm-ai-audit (13 findings)
