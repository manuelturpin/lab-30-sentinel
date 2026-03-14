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

### Step 1: MCP Scan (Automated Pattern Matching)

Call the appropriate MCP tools for your domain. These tools scan the project using KB pattern matching and return automated findings.

**Available MCP tools** (use only those listed in your `## MCP Tools to Use` section):

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `scan-project` | Full security scan with KB pattern matching | Most agents — primary scanning tool |
| `scan-secrets` | Detect hardcoded API keys, tokens, credentials | Agents handling secrets/credentials |
| `scan-dependencies` | Analyze dependencies for known CVEs | Supply chain agent |
| `scan-headers` | Check HTTP security headers | Web, CORS, SSL/TLS, static-site agents |
| `query-kb` | Semantic search the Knowledge Base | All agents — for enrichment |
| `query-cve` | Query CVE database by component/version | Supply chain agent |

**How to call MCP tools**: Use the sentinel-scanner MCP tools directly. Example:
```
mcp__sentinel-scanner__scan-project({ projectPath: "/path/to/project", depth: "standard" })
mcp__sentinel-scanner__query-kb({ query: "SQL injection prevention", domain: "web-app" })
```

### Step 2: Manual Grep Scan (Domain-Specific Patterns)

Use the `Grep` tool to search for patterns listed in your `## Detection Patterns` section.

For each pattern match:
1. Read the surrounding code context (5-10 lines) with the `Read` tool
2. Check against negative patterns to filter false positives
3. If the match is a true positive, create a Finding

**Important**: Do NOT report a finding from Grep if `scan-project` already reported the same issue (same file + same line range + same vulnerability type). This avoids duplicates.

### Step 3: KB Enrichment

For each finding (from both Step 1 and Step 2), call `query-kb` to enrich it:
- Match the finding to a KB rule ID for consistent identification
- Get the CVSS v4 score from the KB rule
- Get standard references (CWE, OWASP) from the KB rule
- Get remediation description and code examples from the KB rule
- Get EPSS score if a CVE is mapped

If `query-kb` returns no match, use your own judgment for severity and remediation but keep scores conservative.

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
