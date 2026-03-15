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
| 11 | Hardening: OSV batch API, LLM-MCP-002 false positives fix, agent timeouts, delta reports, .sentinel.json config, enriched reports | Done |

## Metrics (Session 11)

- **Knowledge Base**: 115 manual rules across 11 domains + 2273 NVD CVEs + OSV cross-references + 94 standards
- **RAG**: 4088 documents indexed in ChromaDB (all-MiniLM-L6-v2), re-indexed with OSV + GitHub data
- **MCP Server**: 6 tools operational, globally registered (`sentinel-scanner`)
- **Stack Detector**: 48+ indicator rules with shallow recursion (2 levels)
- **Agents**: 12 specialized agents with execution protocols + 180s timeout + timing guidance
- **Reports**: SARIF 2.1.0, CycloneDX 1.5 SBOM, Markdown (enriched with duration, agent summary, top 5, delta)
- **Tests**: 58 checks (31 system + 27 E2E), 0 failures
- **CVE Sync**: OSV batch API (`/v1/querybatch`), GitHub Advisories (optional `GITHUB_TOKEN`), EPSS enrichment
- **Config**: Per-project `.sentinel.json` support (exclude agents/paths, false positives, severity overrides)
- **Deployment**: Global (`~/.sentinel/` + `~/.claude/skills/security/`) + VPS script

## Session 11 Changes

- **OSV batch API**: `cve-sync.py` uses `/v1/querybatch` (up to 1000 queries/batch) instead of individual `/v1/query` calls — reduces ~2273 requests to ~3 batches
- **LLM-MCP-002 fix**: Added `docs`, `plans`, `README.md`, `CHANGELOG.md` to exclude list — eliminates false positives on documentation files
- **Agent timeouts**: 180s timeout per agent with `TIMED_OUT` status tracking
- **Protocol timing**: Agents target < 2 min execution
- **Enriched reports**: Scan duration, agent summary (OK/timeout/error), top 5 findings table
- **Delta reports**: Compare with previous SARIF scan — shows new, resolved, unchanged findings
- **`.sentinel.json`**: Per-project config for excluding agents, paths, false positives, severity overrides
- **`.gitignore`**: CVE caches excluded (regenerable via `cve-sync.py`)
