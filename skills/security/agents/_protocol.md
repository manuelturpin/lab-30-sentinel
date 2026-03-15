# Execution Protocol (Common)

This protocol defines how every security audit agent executes its audit. Each agent MUST follow these steps and return findings in the exact format specified below.

## Finding Schema

Every finding MUST conform to this TypeScript interface:

```typescript
interface Finding {
  id: string;                // Agent-specific format: "WEB-INJ-001", "API-AUTH-002", etc.
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;             // Short, descriptive title
  description: string;       // Detailed explanation of the vulnerability
  location: {
    file: string;            // Relative path from project root
    line?: number;           // Line number if applicable
    column?: number;         // Column number if applicable
  };
  standard?: string;         // Primary standard reference (e.g., "CWE-89")
  owasp?: string;            // OWASP reference (e.g., "A03:2025")
  cwe?: string;              // CWE identifier (e.g., "CWE-89")
  remediation: string;       // Actionable fix description
  cvss_v4?: number;          // CVSS v4 base score (0.0-10.0)
  epss?: number;             // EPSS probability (0.0-1.0) if CVE is mapped
}
```

## Execution Steps

### Step 1: KB Pattern Scan (Direct)

For your domain ({domain}), load rules and apply them directly using native tools — **do NOT call `scan-project`, `scan-secrets`, `query-kb`, or `query-cve` via MCP**.

1. **Read** `/Users/manuelturpin/.sentinel/knowledge-base/domains/{domain}/rules.json`
2. For each rule in the file:
   - Use **Grep** with each `detect.patterns[]` on the project files
     - Filter by `detect.file_types[]` via the `glob` parameter of Grep
     - Exclude directories in `detect.exclude[]`
   - For each Grep match:
     - **Read** 5-10 lines of context around the match
     - Check `negative_patterns[]` — if any match in the context, it's a false positive, skip it
     - Create a Finding using the rule's fields: `id`, `severity`, `cvss_v4`, `standards` (map to `cwe`, `owasp`), `remediation`
3. This replaces `scan-project` — you are doing exactly the same pattern matching natively, without MCP serialization overhead.

**Available MCP tools** (use ONLY for external network calls):

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `scan-dependencies` | Analyze dependencies for known CVEs (calls OSV API) | Supply chain agent only |
| `scan-headers` | HTTP GET to check security headers on live URLs | Web, CORS, SSL/TLS, static-site agents |

**How to call MCP tools** (only the two above):
```
mcp__sentinel-scanner__scan-dependencies({ projectPath: "/path/to/project" })
mcp__sentinel-scanner__scan-headers({ url: "https://example.com" })
```

### Step 2: Manual Grep Scan (Domain-Specific Patterns)

Use the `Grep` tool to search for patterns listed in your `## Detection Patterns` section.

For each pattern match:
1. Read the surrounding code context (5-10 lines) with the `Read` tool
2. Check against negative patterns to filter false positives
3. If the match is a true positive, create a Finding

**Important**: Do NOT report a finding from Grep if Step 1 (KB Pattern Scan) already reported the same issue (same file + same line range + same vulnerability type). This avoids duplicates.

### Step 3: KB Enrichment (Direct)

For findings from Step 1, enrichment is already done — the rule's `cvss_v4`, `standards`, and `remediation` fields were used directly when creating the Finding.

For findings from Step 2 (manual Grep) that don't have a KB rule match, enrich them:
1. **Bash**: `python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/rag/query.py --query "{finding.title}" --domain {domain} --limit 3`
2. Parse the JSON output to get CVSS score, CWE/OWASP references, and remediation
3. If the RAG returns no match, use your own judgment for severity and remediation but keep scores conservative.

**Do NOT call `query-kb` via MCP** — the Bash call above does the same thing without MCP serialization overhead.

### Step 4: Deduplicate and Return

1. **Deduplicate**: Remove findings with identical `location.file` + `location.line` + same vulnerability type
2. **Sort**: Order by `cvss_v4` descending (most critical first)
3. **Redact secrets**: If a finding contains an actual secret value (API key, password, token), replace it with `[REDACTED]` in the description
4. **Return**: Output a single JSON code block with the Finding[] array

## Output Format

Return ONLY a JSON code block. No prose before or after. The orchestrator parses this output.

```json
[
  {
    "id": "WEB-INJ-001",
    "severity": "CRITICAL",
    "title": "SQL injection via string concatenation",
    "description": "User input from req.params.id is concatenated into SQL query without parameterization.",
    "location": {"file": "src/api/users.ts", "line": 42},
    "standard": "CWE-89",
    "owasp": "A03:2025",
    "cwe": "CWE-89",
    "remediation": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [req.params.id])",
    "cvss_v4": 9.4,
    "epss": 0.15
  }
]
```

If no vulnerabilities are found, return an empty array: `[]`

## Rules

1. **Redact secrets**: NEVER include actual secret values in findings. Use `[REDACTED]`.
2. **Conservative severity**: Only mark CRITICAL if exploitation is trivial AND impact is severe. When unsure, rate one level lower.
3. **Actionable remediations**: Every finding MUST include a specific, actionable remediation — not just "fix this".
4. **No false positives**: If you're not confident a pattern match is a real vulnerability (>70% confidence), do not report it.
5. **Location accuracy**: Always include the file path. Include line number when you can determine it precisely.
6. **Standard references**: Always include at least one of `standard`, `owasp`, or `cwe` when applicable.
