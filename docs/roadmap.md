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
| 8 | Orchestrator finalization + Reports (SARIF enrichi, SBOM CycloneDX, report renderer, 31/31 E2E) | Done |
| 9 | Crons + Automated monitoring (CVE sync, KB update, project rescan) | Done |
| 10 | Production-ready: RAG re-index, test suite, error handling, deploy | Done |
| 11 | Hardening: live /security validation, OSV/GitHub feeds, VPS deploy | Pending |

## Metrics (Session 10)

- **Knowledge Base**: 115 manual rules across 11 domains + 2273 NVD CVEs + 94 standards
- **RAG**: 2604 documents indexed in ChromaDB (all-MiniLM-L6-v2)
- **MCP Server**: 6 tools operational, globally registered (`sentinel-scanner`)
- **Stack Detector**: 48+ indicator rules with shallow recursion (2 levels)
- **Agents**: 12 specialized agents with execution protocols
- **Reports**: SARIF 2.1.0, CycloneDX 1.5 SBOM, Markdown (template renderer)
- **Tests**: 58 checks (31 system + 27 E2E), 0 failures
- **Deployment**: Global (`~/.sentinel/` + `~/.claude/skills/security/`) + VPS script
