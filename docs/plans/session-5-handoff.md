# Lab-30 Sentinel — Session 5 : MCP Server Implementation

## Context

Sessions 1-4 complete (`f413bf7`). KB is fully populated (8/8 domains, 100 rules, 122 patterns). The MCP server skeleton exists with 6 tools, all returning `not_implemented`. Session 5 implements the actual scanning logic.

## What exists (skeletons from Session 1)

All files in `mcp-servers/sentinel-scanner/src/`:

| File | Status | Notes |
|------|--------|-------|
| `index.ts` | Skeleton | MCP server with 6 tool registrations, all returning placeholders |
| `tools/scan-project.ts` | Skeleton | Has `ScanResult` interface, calls `detectStack()` but no scanning |
| `tools/scan-secrets.ts` | Skeleton | Has `SECRET_PATTERNS` regex map (8 types), empty `scanSecrets()` |
| `tools/scan-dependencies.ts` | Skeleton | Has interfaces, empty `scanDependencies()` |
| `tools/scan-headers.ts` | Skeleton | Has `SECURITY_HEADERS` config (9 headers), empty `scanHeaders()` |
| `tools/query-cve.ts` | Skeleton | Has interfaces, empty `queryCVE()` |
| `tools/query-kb.ts` | Skeleton | Has interfaces, empty `queryKB()` — planned for Session 6 (RAG) |
| `utils/stack-detector.ts` | **COMPLETE** | 30+ indicator rules, package.json heuristics, version extraction |
| `utils/types.ts` | **COMPLETE** | `Finding`, `ScanSummary` interfaces |
| `utils/risk-scorer.ts` | **COMPLETE** | CVSS v4 + EPSS composite scoring + sort |
| `utils/sarif-generator.ts` | **COMPLETE** | Full SARIF 2.1.0 generator from `Finding[]` |
| `utils/sbom-generator.ts` | Skeleton | For Session 8 |

## Session 5 Scope

### 1. Implement `scan-project.ts` — Core scanner engine

The main tool. Must:
1. Call `detectStack()` (already works)
2. Load KB rules for detected domains (read `knowledge-base/domains/*/rules.json`)
3. Walk project files (respecting `exclude` dirs and `file_types` filters)
4. Match `detect.patterns` regex against file contents
5. Filter out matches that hit `negative_patterns`
6. Build `Finding[]` with file/line locations
7. Score each finding with `calculateCompositeRisk()`
8. Return structured results

Key design decisions:
- Use Node's `fs` + `path` (no external deps needed beyond what's in package.json)
- Stream large files line-by-line to avoid memory issues
- Respect `depth` param: quick (first 100 files), standard (all files), deep (all + git history)

### 2. Implement `scan-secrets.ts` — Secret detector

The `SECRET_PATTERNS` regex map is already defined. Needs:
1. Walk project files (skip binaries, node_modules, .git)
2. Apply each regex pattern per line
3. Redact matched values in output (`sk-****...****`)
4. Optionally scan git history (`git log -p`) if `includeGitHistory=true`
5. Return `SecretScanResult`

### 3. Implement `scan-dependencies.ts` — Dependency scanner

1. Auto-detect ecosystem from lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, go.sum, Cargo.lock, Gemfile.lock)
2. Parse lockfile to extract package names + versions
3. Query OSV API (`https://api.osv.dev/v1/query`) for each package
4. Optionally call external wrappers (`mcp-servers/external-integrations/osv-scanner-wrapper.sh`)
5. Map results to `DependencyVulnerability[]`

### 4. Implement `scan-headers.ts` — HTTP header checker

1. `fetch(url)` and collect response headers
2. Check presence/value of each `SECURITY_HEADERS` entry
3. Evaluate CSP strength (no `unsafe-inline`, `unsafe-eval`)
4. Calculate score (0-100) and grade (A+ to F)
5. Return `HeaderScanResult`

### 5. Implement `query-cve.ts` — CVE cache query

1. Load local cache files (`knowledge-base/cve-feed/nvd-cache.json`, `osv-cache.json`, `github-advisories.json`)
2. Filter by component name, version range, ecosystem
3. Return matching `CVEEntry[]`
4. Note: caches are currently empty `{}` — real data comes from crons (Session 9), but the query logic should work

### 6. Wire implementations into `index.ts`

Replace all placeholder callbacks with actual function calls. Import from tool modules.

### 7. Build & test

- `npm install` + `npm run build` must succeed
- Manual test: `echo '{"method":"initialize"}' | npx tsx src/index.ts` (stdio transport)
- Create `tests/` with at least basic validation

## Dependencies

```json
{
  "@modelcontextprotocol/sdk": "^1.0.0",
  "zod": "^3.22.0"
}
```
No new deps needed. Use only Node built-ins (`fs`, `path`, `readline`, `child_process` for git).

## KB path resolution

The KB is at `../../knowledge-base/` relative to the MCP server src. Use `__dirname` or `import.meta.url` to resolve:
```typescript
const KB_ROOT = path.resolve(new URL('.', import.meta.url).pathname, '../../..', 'knowledge-base');
```

## Conventions

- TypeScript strict mode (tsconfig.json already configured)
- ESM modules (`"type": "module"` in package.json)
- Import with `.js` extension (TypeScript ESM convention)
- All existing interfaces/types are stable — don't change them
- Keep the `index.ts` tool registration structure (just wire real functions)

## Verification

```bash
cd mcp-servers/sentinel-scanner
npm install && npm run build
# Test scan-project against sentinel itself:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan-project","arguments":{"projectPath":"/path/to/any/project"}}}' | npx tsx src/index.ts
```

## Out of scope (later sessions)

- `query-kb` RAG implementation → Session 6
- `sbom-generator` → Session 8
- Cron jobs for CVE feed updates → Session 9
- Agent dispatching logic (SKILL.md orchestrator) → Session 7
