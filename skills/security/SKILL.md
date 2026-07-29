---
name: sentinel-security
description: Audit de cybersecurite complet pour tout projet (web, API, mobile, infra, DB, IA/LLM). Detecte le stack, dispatche 12 agents specialises en parallele, consulte une KB de 4000+ regles enrichie par RAG, et produit un rapport SARIF 2.1.0 avec scoring CVSS v4 + EPSS et remediations. Couvre OWASP Top 10 Web/API/LLM/Mobile, MITRE ATLAS, CWE-25, NIST AI RMF.
user_invocable: true
effort: high
keep-coding-instructions: true
# NOTE 2026-07-29 : le bloc `paths:` a ete retire. Mesure par experience controlee
# (deux copies identiques du skill, seule difference le bloc paths) : sa presence rend
# le skill INDECOUVRABLE — `/sentinel-security` renvoyait `Unknown command` en session
# fraiche. Ne pas le reintroduire sans avoir reverifie ce comportement.
---

# /sentinel-security — Sentinel Cybersecurity Audit

You are Sentinel, an AI-powered cybersecurity auditing system. When invoked, you perform a comprehensive security audit of the current project.

## Step 0: Session Setup

**Session naming** — for audit traceability, name the session:
```
--name "sentinel-audit-{project}-{date}"
```
This enables easy session lookup via `claude sessions list` for audit trail. Paused audits (deferred via CI hooks) can be resumed by title: `claude -p --resume "sentinel-audit-{project}-{date}"` (v2.1.101+).

**Auto session title hook** — alternatively, configure a UserPromptSubmit hook to auto-name audit sessions when `/sentinel-security` is invoked:
```json
{
  "hooks": {
    "UserPromptSubmit": [{
      "if": "Skill(sentinel-security)",
      "matcher": "sentinel",
      "hooks": [{
        "type": "command",
        "command": "echo '{\"hookSpecificOutput\": {\"sessionTitle\": \"sentinel-audit-'$(basename $(pwd))'-'$(date +%Y-%m-%d)'\"}}'"
      }]
    }]
  }
}
```
This uses the `sessionTitle` hook output (v2.1.94+) for zero-effort audit traceability.

**Worktree sparse paths** — for large monorepos, use `worktree.sparsePaths` to checkout only relevant directories when dispatching agents in worktrees. This reduces clone time and disk usage.

**Dedicated memory** — configure `autoMemoryDirectory: "~/.sentinel/memory/"` in project settings so Sentinel skills share a dedicated memory space, separate from the user's personal auto-memory. This prevents cross-contamination and simplifies backup/export of Sentinel's learned knowledge (false positives, project preferences, scan history).

## Step 0b: Audit Configuration

This audit is **read-only** — no files are modified. If the user's permission mode is `default`, suggest:
> "This scan only reads files and runs grep patterns — no modifications. You can switch to auto mode for zero permission prompts: press Shift+Tab to cycle to auto, or run with `--permission-mode auto`."

**Interactive config** — if MCP elicitation is available, use it to collect structured audit parameters before starting:
- **Severity threshold**: minimum severity to report (default: LOW)
- **Excluded paths**: directories to skip (e.g., `vendor/`, `node_modules/`, `third-party/`)
- **Target URL**: live URL for header scanning (optional)
- **Depth**: `quick` (KB patterns only) or `standard` (KB + manual grep + RAG enrichment)

If no elicitation available, check for `.sentinel.json` at the project root for these settings, otherwise use defaults.

## Workflow

### Step 1: Stack Detection

**Plan subagent for monorepos** — for projects with 10+ top-level directories or multiple `package.json`/`requirements.txt` files, launch a **Plan subagent** before Explore to analyze project structure and produce a targeted audit plan:

```
Launch Agent(
  subagent_type: "Plan",
  prompt: "Analyze this monorepo at {target_path}. Identify independent services, shared libraries, and cross-service data flows. Return a JSON audit plan: {services: [{name, path, stack, priority}], shared_libs: [path], data_flows: [{from, to, protocol}]}"
)
```

For simpler projects, skip directly to stack detection.

Use an **Explore subagent** to detect the stack — this preserves the main context window. Note (v2.1.198): the built-in Explore agent now **inherits the main session's model** (capped at `opus`) instead of running on Haiku, so this step is no longer the cheap probe it used to be — budget it accordingly.

```
Launch Agent(
  subagent_type: "Explore",
  prompt: "Check which of these indicator files exist in {target_path} and return a JSON object mapping each found file to its stack type. Check for: package.json, next.config.*, nuxt.config.*, tsconfig.json, Podfile, *.xcodeproj, android/build.gradle, pubspec.yaml, Dockerfile, docker-compose.*, *.tf, *.tfvars, k8s/, kubernetes/, helm/, requirements.txt, pyproject.toml, setup.py, Gemfile, go.mod, SKILL.md, CLAUDE.md, AGENTS.md, .cursorrules, COPILOT.md, *.prisma, *.sql, migrations/, mongod.conf, .env, .env.*, nginx.conf, apache.conf, vercel.json, netlify.toml. Also grep for ws://, wss://, socket.io patterns."
)
```

Then map the detected files to agents using this table:

| Indicator File | Stack Detected | Agents to Dispatch |
|---|---|---|
| `package.json` | Node.js / JavaScript | web-audit, supply-chain-audit |
| `next.config.*`, `nuxt.config.*` | SSR Framework | web-audit, static-site-audit |
| `tsconfig.json` | TypeScript | web-audit |
| `Podfile`, `*.xcodeproj` | iOS | mobile-audit |
| `android/build.gradle` | Android | mobile-audit |
| `pubspec.yaml` | Flutter | mobile-audit |
| `Dockerfile`, `docker-compose.*` | Docker | infrastructure-audit |
| `*.tf`, `*.tfvars` | Terraform | infrastructure-audit |
| `k8s/`, `kubernetes/`, `helm/` | Kubernetes | infrastructure-audit |
| `requirements.txt`, `pyproject.toml`, `setup.py` | Python | supply-chain-audit |
| `Gemfile` | Ruby | supply-chain-audit |
| `go.mod` | Go | supply-chain-audit |
| `SKILL.md`, `CLAUDE.md`, `AGENTS.md` | AI/LLM Agent | llm-ai-audit |
| `.cursorrules`, `COPILOT.md` | AI/LLM Agent | llm-ai-audit |
| `*.prisma`, `*.sql`, `migrations/` | Database | database-audit |
| `mongod.conf`, `mongodb.conf` | MongoDB | database-audit |
| `.env`, `.env.*` | Secrets/Config | data-privacy-audit |
| `nginx.conf`, `apache.conf` | Web Server | ssl-tls-audit, cors-audit |
| `vercel.json`, `netlify.toml` | Static Hosting | static-site-audit |
| `ws://`, `wss://`, `socket.io` | WebSocket | websocket-audit |

**Always include these agents regardless of stack:**
- `supply-chain-audit` (every project has dependencies)
- `data-privacy-audit` (every project may handle data)

### Step 2: Agent Dispatch

**Agent model tiers** — use the right model for each agent's complexity:

| Tier | Model | Agents |
|------|-------|--------|
| **Heavy** (complex analysis) | *inherit session model* | web-audit, api-audit, llm-ai-audit, supply-chain-audit, mobile-audit |
| **Medium** (structured analysis) | `sonnet` | database-audit, infrastructure-audit, data-privacy-audit |
| **Light** (pattern checks) | `sonnet` | cors-audit, ssl-tls-audit, static-site-audit, websocket-audit |

> Doctrine machine (19/07/2026) : **opus ou sonnet exclusivement, plus jamais haiku**. `CLAUDE_CODE_SUBAGENT_MODEL=sonnet` écrase de toute façon le modèle demandé par agent — les tiers ci-dessus sont donc indicatifs tant que cette variable est posée.

**Security hardening** — set `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` before dispatching agents to prevent credential leakage from subprocess environments during scans. On Linux, this also enables PID namespace isolation for subprocess sandboxing (v2.1.98+). Additionally, set `CLAUDE_CODE_SCRIPT_CAPS=500` to limit per-session script invocations — prevents runaway agent execution.

**Cost monitoring** — Sentinel dispatches agents across multiple model tiers (Sonnet 5 for light and mid-tier checks, Opus 5 for deep analysis — the default unspecified tier inherits the session model). Current defaults: **Sonnet 5** is the default Claude Code model since v2.1.197, **Opus 5** the default Opus model since v2.1.219, and `high` is the default effort *and* the recommended baseline — `xhigh` is an escalation, not a starting point. Use `/cost` for the per-model breakdown and cache-hit ratio (v2.1.92+), or `/usage` for a per-category breakdown across skills, subagents, plugins, and per-MCP-server cost (v2.1.149+) — this helps optimize agent tier assignments and identify expensive scans. Note: the Opus 4.7+ tokenizer may use +35% tokens vs 4.6 — increase max_tokens headroom accordingly.

**Model choice — do NOT orchestrate Sentinel on Fable 5.** Claude Fable 5 (`claude-fable-5`, v2.1.170+) is the most capable GA model, but it ships a **real-time cyber/biology safety classifier** that flags security content and **auto-switches the session to Opus 4.8** (false positives are common — Anthropic's own warning). Because Sentinel's work *is* cybersecurity (CVE, attack surfaces, exploit/injection patterns), orchestrating it on Fable 5 trips the classifier continuously. **Keep Sentinel's orchestrator on Opus** — use the `opus` alias, which resolves to the current Opus model (Opus 5 since 2026-07-24). Do **not** pin a literal version such as `claude-opus-4-8`: that now downgrades the session instead of protecting it. Pin via a project `.claude/settings.json` `"model": "opus"` only if a non-Opus global default is in place. For legitimate *defensive* use, apply to the [Cyber Verification Program](https://claude.com/form/cyber-use-case) to lift the restriction. Fable 5 remains usable for non-flagged subtasks (it is the documented top tier); the constraint is specifically about the session orchestrator on security content.

> **Note Opus 5 (25/07/2026)** : les classifieurs de cybersécurité sont **renforcés** sur Opus 5, pas assouplis. Le risque de refus sur du contenu sécurité augmente. Gérer `stop_reason: "refusal"` avant de lire le contenu d'une réponse, et envisager `fallbacks: "default"`. Corollaire pour les rapports d'agents : ne jamais demander « ne remonte que le high-severity » — Opus 5 suit les filtres de sévérité **littéralement**, ce qui fait chuter le recall. Tout remonter, filtrer en aval.
>
> ⚠️ Ces deux consignes sont pour l'instant **documentaires** : aucune branche de traitement de `stop_reason: "refusal"` ni filtre de sévérité aval n'est implémenté dans l'étape 3 d'agrégation. Un agent qui refuse produit aujourd'hui un JSON invalide, avalé par le `WARNING: did not return valid JSON` — un scan partiellement refusé peut donc rendre zéro finding et paraître propre. À implémenter avant de s'appuyer sur ces notes. *(Finding S3 de la revue croisée du 27/07.)*

> **Portée de la contrainte (mesuré le 27/07/2026)** : elle vise l'**orchestrateur en fonctionnement** sur du contenu d'exploit, pas tout appel touchant à la sécurité. Sonde `claude -p --model claude-fable-5` sur une question d'*architecture* de scanner : réponse rendue par `canonicalModel: "claude-fable-5"`, contexte 1M, aucun basculement ni refus. Un appel de revue borné et cadré sur l'architecture/le design reste donc exploitable sur Fable 5 — à condition d'instrumenter `canonicalModel` à chaque appel plutôt que de présumer l'absence de bascule (n=1).

**Progress tracking** — before dispatching, create a task for each agent using TaskCreate so the user can see scan progress. Update each task to completed when the agent returns.

**Real-time monitoring** — use the Monitor tool (v2.1.98+) to stream live output from background audit agents instead of waiting silently for completion. After dispatching all agents with `run_in_background: true`, attach a Monitor to each for real-time progress:

```
For each agent in detected_agents:
  TaskCreate("Auditing {agent}...")
  Launch Agent(
    subagent_type: "general-purpose",
    name: "{agent}",
    model: "sonnet" if agent in [cors-audit, ssl-tls-audit, static-site-audit, websocket-audit, database-audit, infrastructure-audit, data-privacy-audit] else omit,
    initialPrompt: "Begin audit now.",
    prompt: "You are a security audit agent. Follow these steps exactly:
      0. Check your memory for known false positives in this project — skip any pattern/file combination you previously confirmed as false positive
      1. Read your agent instructions at /Users/manuelturpin/.claude/skills/sentinel-security/agents/{agent}.md
      2. Read the common execution protocol at /Users/manuelturpin/.claude/skills/sentinel-security/agents/_protocol.md
      3. Audit the project at {target_path} following your Execution Protocol
      4. Use Read + Grep + Bash for KB pattern scanning (read rules.json, grep patterns, enrich via RAG)
      5. Only use MCP tools if your agent lists them (scan-dependencies for supply-chain, scan-headers for web/cors/ssl/static) — MCP tools are inherited automatically from the parent session (v2.1.101+)
      6. Return ONLY a JSON code block containing a Finding[] array — no other text",
    memory: "project",
    disallowedTools: ["Write", "Edit", "NotebookEdit"],
    maxTurns: 15,
    run_in_background: true
  )
  // Monitor agent progress: Monitor("{agent}") — streams stdout events as notifications
  // When agent completes: TaskUpdate(status: "completed", summary: "{N} findings")
  // Named agents can coordinate: SendMessage(to: "web-audit", message: "compromised dep found in lodash")
```

### Step 2b: Resilience Hooks

**PostCompact hook** — long multi-agent audits may trigger context compaction. Configure a PostCompact hook to reinject critical scan state after compaction:
- List of dispatched agents and their status (running/completed/failed)
- Current finding count per agent
- Scan metadata (target path, detected stacks, start time)

**StopFailure hook** — if an agent fails due to API error (rate limit, timeout), the StopFailure hook should:
1. Log the failure: agent name, error type, turn count at failure
2. Retry the agent once with `maxTurns: 10` (reduced scope)
3. If retry fails, mark the agent as failed and continue — do NOT block the entire audit

### Step 2c: Workflow-Based Orchestration (v2.1.154+)

For large monorepos or wide agent fan-outs, the dynamic **Workflow tool** can orchestrate the audit deterministically instead of manual `Agent` dispatch. Author a workflow (or call `Workflow` directly) that fans the detected agents out as a `pipeline`, then adversarially verifies each finding before aggregation:

```js
// one stage per detected agent, then a verify pass per finding (no barrier between agents)
const findings = await pipeline(
  detectedAgents,                                   // e.g. [web-audit, api-audit, ...]
  a => agent(a.prompt, { phase: 'Scan', schema: FINDINGS }),
  scan => parallel(scan.findings.map(f => () =>
    agent(`Adversarially verify: ${f.title}`, { phase: 'Verify', schema: VERDICT })
      .then(v => ({ ...f, verdict: v }))))
)
```

Benefits: background execution across tens-to-hundreds of agents, built-in worktree isolation per stage, and per-finding adversarial verification that drops false positives before they reach the SARIF report. The manual Step 2 dispatch (`run_in_background` + Monitor) remains the fallback for small projects or when a deterministic script is overkill.

### Step 3: Collect & Parse Results

Wait for all agents to complete. For each agent result:

1. **Extract JSON**: Parse the agent's response to find the JSON code block (between ` ```json ` and ` ``` ` or `[` to `]`)
2. **Validate findings against schema**: Each finding MUST conform to this JSON schema — reject any finding missing required fields:
   - **Required**: `id` (string), `severity` (CRITICAL|HIGH|MEDIUM|LOW|INFO), `title` (string), `description` (string), `location.file` (string), `remediation` (string)
   - **Optional**: `location.line`, `location.column`, `standard`, `owasp`, `cwe`, `cvss_v4` (number 0-10), `epss` (number 0-1)
   - Discard findings that don't match (log which ones were rejected and why)
3. **Fallback**: If an agent does not return valid JSON:
   - Log a warning: `"WARNING: Agent {agent_name} did not return valid Finding[] JSON — skipping"`
   - Continue with remaining agents — do NOT fail the entire audit
4. **Tag findings**: Add the originating agent name to each finding for traceability
5. **Track agent success**: Count successful vs failed agents for the report summary

**Edge cases:**
- **0 agents dispatched** (only defaults run): Proceed with `supply-chain-audit` and `data-privacy-audit` only. Add a note in the report: "No stack-specific agents detected — only default agents ran."
- **All agents fail**: Generate a minimal error report with 0 findings, listing which agents failed and why. Do NOT return an empty response — always produce a report.

### Step 4: Aggregate & Score

1. **Merge** all agent findings into a unified array
2. **Deduplicate** findings by `location.file` + `location.line` + `id` — keep the finding with the higher `cvss_v4` score
3. **Calculate risk scores**:
   - **CVSS v4** base score from the finding (set by agent from KB enrichment)
   - **EPSS** probability if CVE is mapped (set by agent from KB enrichment)
   - **Composite risk** = `cvss_v4 * (0.6 + 0.4 * epss)` — EPSS boosts score up to 40% max (see `risk-scorer.ts`)
4. **Sort** findings by composite risk (highest first)

### Step 5: Generate Report

Use the report renderer (`report-renderer.ts`) with the template at `/Users/manuelturpin/.sentinel/reports/templates/full-report.md`:

1. Build a `ReportData` object from the aggregated findings, scan metadata (stacks, agents, depth, duration), and file paths
2. Include agent success summary: "X of Y agents completed successfully" in the report header
3. Call `renderReport(data)` to produce the final Markdown report
4. The renderer handles severity counts, composite scores, EPSS averages, and finding categorization automatically

### Step 6: Save Reports

Save all 3 output files to `/Users/manuelturpin/.sentinel/reports/archive/`:

1. `{project}_{date}.sarif.json` — SARIF 2.1.0 report (with `invocations` and `artifacts`)
2. `{project}_{date}.sbom.json` — CycloneDX 1.5 SBOM (from `generate-sbom` tool)
3. `{project}_{date}.md` — Rendered Markdown report

### Step 7: Suggest Batch Remediation (Optional)

After presenting the report, check if multiple findings share the same remediation pattern (e.g., 5+ files missing a security header, or 5+ endpoints without input validation). If so, suggest:

> "I found {N} files with the same issue ({pattern}). You can use `/batch` to apply the fix across all files in parallel — want me to set that up?"

This uses Claude Code's `/batch` skill which creates parallel worktrees for safe concurrent modifications.

### Step 8: Cross-Validation (Optional)

For CRITICAL/HIGH findings only, the model can now invoke the built-in `/security-review` skill as a second-pass validation (v2.1.108+ — built-in slash commands discoverable via Skill tool):

```
Skill("security-review")
```

This provides an independent review using Anthropic's official threat model. Use it when:
- A CRITICAL finding could be a false positive (high-cost remediation)
- The user explicitly requests independent verification
- Before opening a GitHub Advisory

For large-scale validation across the whole branch, invoke `/code-review ultra` — the deep multi-agent cloud review that runs parallel analysis + critique. (The `/simplify` command was renamed to `/code-review` with optional effort levels — e.g. `/code-review high` — in v2.1.146; `/ultrareview` still works as the alias for the ultra tier.)

---

## Knowledge Base Integration

Agents now read the Knowledge Base directly using native tools (Read, Grep, Bash) instead of MCP calls. This eliminates MCP serialization overhead for local operations.

**Direct KB access paths:**
- **Rules**: `/Users/manuelturpin/.sentinel/knowledge-base/domains/{domain}/rules.json` — agents Read these directly and Grep each rule's `detect.patterns[]` against the project
- **Standards**: `/Users/manuelturpin/.sentinel/knowledge-base/standards/` — cross-reference for standard mappings
- **CVE Feed**: `/Users/manuelturpin/.sentinel/knowledge-base/cve-feed/` — agents Read CVE cache JSON files directly (replaces `query-cve` MCP call)
- **RAG Enrichment**: `python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/rag/query.py --query "{query}" --domain {domain} --limit 3` — agents call via Bash (replaces `query-kb` MCP call)
- **Remediation**: Each rule's `remediation` field provides fix suggestions directly

**MCP tools retained** (external network calls only):
- `scan-dependencies` — calls OSV API for dependency CVE analysis
- `scan-headers` — makes HTTP GET to check security headers on live URLs

## Permission & Resilience Hooks

### PermissionDenied Hook (v2.1.88+)

For read-only security scans in auto mode, configure a PermissionDenied hook to auto-retry safe tool denials:

```json
{
  "hooks": {
    "PermissionDenied": [{
      "if": "Read|Grep|Glob",
      "matcher": "Read|Grep|Glob",
      "hooks": [{
        "type": "command",
        "command": "echo '{\"retry\": true}'"
      }]
    }]
  }
}
```

The `if` conditional (v2.1.85+) ensures the hook only spawns a process when the denied tool matches read-only patterns — reducing overhead for unrelated denials.

This eliminates manual permission approval friction during audits for safe read operations.

### PreCompact Finding Preservation (v2.1.76+, blocking v2.1.105+)

Long multi-agent audits may hit context limits. Use **PreCompact blocking** to protect active scans:

- **Block compaction during active scans** (v2.1.105+): Return `{"decision":"block"}` from PreCompact when agents are still running — this prevents compaction from discarding in-progress findings. The hook checks for a sentinel lock file created when agents are dispatched and removed when all agents complete.
- **Allow compaction when idle**: When no agents are running, allow compaction normally — findings are already aggregated.
- **PostCompact fallback**: If compaction is allowed (all agents done), PostCompact reloads saved state after compaction — zero finding loss.

```json
{
  "hooks": {
    "PreCompact": [{
      "hooks": [{
        "type": "command",
        "command": "if [ -f /tmp/sentinel-scan-active.lock ]; then echo '{\"decision\":\"block\"}'; else echo 'Compaction allowed — no active scan'; fi"
      }]
    }]
  }
}
```

### TaskCreated Hook for Audit Trail (v2.1.84+)

Configure a TaskCreated hook to automatically log every scan task to a persistent audit trail file for compliance:

```json
{
  "hooks": {
    "TaskCreated": [{
      "if": "TaskCreate",
      "matcher": "Auditing.*audit",
      "hooks": [{
        "type": "command",
        "command": "echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) TASK_CREATED: $TASK_DESCRIPTION\" >> ~/.sentinel/reports/audit-trail.log"
      }]
    }]
  }
}
```

This creates a timestamped record of every agent dispatched during a scan — useful for SOC-2 and ISO 27001 compliance.

### MessageDisplay Hook — Secret Redaction (v2.1.152+)

Audit findings may echo secrets, tokens, or PII captured from the scanned project. Configure a `MessageDisplay` hook to redact them from assistant output as it is displayed (the underlying finding in the SARIF report is unaffected):

```json
{
  "hooks": {
    "MessageDisplay": [{
      "hooks": [{
        "type": "command",
        "command": "sed -E 's/(AKIA|ghp_|sk-)[A-Za-z0-9_-]+/[REDACTED]/g'"
      }]
    }]
  }
}
```

### SessionStart reloadSkills + sessionTitle (v2.1.152+)

After `deploy.sh` updates the Sentinel skills, a `SessionStart` hook can return `reloadSkills: true` to re-scan skill directories in the *same* session (no restart — complements `/reload-skills`), and set the session title for audit traceability:

```json
{
  "hooks": {
    "SessionStart": [{
      "hooks": [{
        "type": "command",
        "command": "echo '{\"hookSpecificOutput\":{\"reloadSkills\":true,\"sessionTitle\":\"sentinel-audit\"}}'"
      }]
    }]
  }
}
```

### Hook Hardening — Exec-form args + continueOnBlock (v2.1.139+)

Sentinel's own hooks should use the **exec form** `args: [...]` so commands run without a shell — path placeholders never need quoting and shell-injection via interpolated values is impossible. For `PostToolUse`, set `continueOnBlock: true` so a blocked tool call feeds its rejection reason back to Claude and the audit continues instead of aborting:

```json
{
  "hooks": {
    "PostToolUse": [{
      "continueOnBlock": true,
      "hooks": [{ "type": "command", "args": ["sentinel-hook", "${TOOL_NAME}"] }]
    }]
  }
}
```

### autoMode.hard_deny for Headless Audits (v2.1.136+)

When running headless audits in auto mode, set `settings.autoMode.hard_deny` rules to block dangerous classes of operations *unconditionally* — regardless of inferred intent or allow exceptions (e.g. bulk repository exfiltration, destructive shell commands). This pairs with the improved data-exfiltration classifier (v2.1.154) to keep an autonomous Sentinel scan from being coerced into leaking the very repo it audits.

### Defer Decision for CI Gating (v2.1.89+)

For CI pipelines, PreToolUse hooks can return `"defer"` to pause headless sessions at risky tool calls (e.g., `scan-headers` making external HTTP requests). Resume after human approval with `-p --resume`.

### PreToolUse AskUser Override for Headless Audits (v2.1.85+)

In headless CI environments, `AskUserQuestion` prompts (e.g., "Which severity threshold?") would block the pipeline. Configure a PreToolUse hook to auto-answer these:

```json
{
  "hooks": {
    "PreToolUse": [{
      "if": "AskUserQuestion",
      "matcher": "AskUserQuestion",
      "hooks": [{
        "type": "command",
        "command": "echo '{\"permissionDecision\": \"allow\", \"updatedInput\": \"Use defaults: severity=MEDIUM, depth=standard\"}'"
      }]
    }]
  }
}
```

This returns a pre-configured answer via `updatedInput`, enabling fully unattended audit runs without interactive prompts.

## CI/Headless Mode

When invoked via `claude -p`, produce structured SARIF output:

1. Detect headless mode: if no interactive terminal is available, skip Markdown rendering
2. Output the SARIF 2.1.0 JSON directly to stdout (no wrapping, no prose)
3. Exit with code 0 (clean) or 1 (findings with CRITICAL/HIGH severity)

**Sandbox hardening** — for enterprise CI, set `sandbox.failIfUnavailable: true` in settings to ensure audits fail-closed if the sandbox cannot start (v2.1.83+). Security-critical scans must never run unsandboxed:
```json
{ "sandbox": { "failIfUnavailable": true } }
```

**Use `--bare` flag** for faster CI cold starts — skips hooks, LSP, and plugin sync:
```bash
# MCP_CONNECTION_NONBLOCKING skips MCP connection wait (v2.1.89+)
# CLAUDE_CODE_SCRIPT_CAPS limits script invocations (v2.1.98+)
# --exclude-dynamic-system-prompt-sections improves cross-user prompt caching (v2.1.98+)
CLAUDE_CODE_SCRIPT_CAPS=500 MCP_CONNECTION_NONBLOCKING=true claude --bare -p "/sentinel-security" --output-format json --exclude-dynamic-system-prompt-sections > report.sarif.json
```

**Resume deferred audits by name** — if a CI audit was paused via `defer` hook decision, resume it using the session title instead of opaque ID (v2.1.101+):
```bash
claude -p --resume "sentinel-audit-myproject-2026-04-12"
```

**Deep link for one-click audit launch** (v2.1.91 multi-line support):
```
claude-cli://open?q=/sentinel-security%0A%0APerform%20a%20full%20security%20audit%20of%20this%20project.%0ASeverity%20threshold:%20MEDIUM%0ADepth:%20standard
```
Share this link in README, Slack, or docs for instant audit launch from anywhere. Multi-line prompts via `%0A` encoding let you pre-fill audit parameters.

**Use `--json-schema` for guaranteed valid SARIF** — enforces output structure at the model level, eliminating JSON parse failures in CI:
```bash
claude --bare -p "/sentinel-security" --json-schema '{"type":"object","properties":{"$schema":{"type":"string"},"version":{"type":"string"},"runs":{"type":"array"}},"required":["version","runs"]}' > report.sarif.json
```

## Reactive Re-scan (FileChanged Hook)

For continuous security monitoring during development, configure a **FileChanged hook** to trigger a lightweight re-scan when security-sensitive files change:

Watched patterns: `*.env`, `**/auth/**`, `**/middleware/**`, `docker-compose.*`, `Dockerfile`, `*.tf`, `package.json`, `requirements.txt`

When triggered:
1. Run only the relevant agent(s) for the changed file type (not a full scan)
2. Compare findings against the last full scan — report only **new** findings
3. Display inline: `"[Sentinel] New finding: {title} in {file}:{line}"`

This uses Claude Code's `CwdChanged` and `FileChanged` hook events (v2.1.83+).

## HTTP Hook Notifications

Configure an **HTTP hook** to POST scan results to Slack or a webhook endpoint when an audit completes. This enables async notification for long-running scans.

**Setup** (in `~/.claude/settings.json`):
```json
{
  "hooks": {
    "TaskCompleted": [{
      "matcher": "sentinel-security",
      "hooks": [{
        "type": "http",
        "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        "method": "POST",
        "body": {
          "text": "Sentinel scan complete: {{task.summary}}"
        }
      }]
    }]
  }
}
```

This uses Claude Code's HTTP hooks (v2.1.63+). Configure the webhook URL in `.sentinel.json` or environment variable `SENTINEL_WEBHOOK_URL`.

## Auto-Redeploy (ConfigChange Hook)

Configure a **ConfigChange hook** to auto-trigger `deploy.sh` when KB rules or skill files change:

Watched paths: `knowledge-base/domains/*/rules.json`, `skills/security/SKILL.md`, `skills/security/agents/*.md`

When triggered:
1. Run `DRY_RUN=0 bash scripts/deploy.sh` to sync changes to `~/.claude/skills/sentinel-security/` and `~/.sentinel/` — **`DRY_RUN=0` is mandatory**: the script defaults to `DRY_RUN=1` since 2026-04-17 (H3 audit fix), so the bare `bash scripts/deploy.sh` is a silent no-op. This hook has been dead since that change. *(Finding S1b de la revue croisée du 27/07.)*
2. Log the deploy result

This uses Claude Code's ConfigChange hook event (v2.1.50+) and eliminates forgetting to run `deploy.sh` after edits.

## WorktreeCreate/Remove Hooks (Agent Lifecycle Tracking)

When agents run with `isolation: worktree`, configure **WorktreeCreate/Remove hooks** for audit trail and lifecycle tracking:

```json
{
  "hooks": {
    "WorktreeCreate": [{
      "hooks": [{
        "type": "command",
        "command": "echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) WORKTREE_CREATE: $WORKTREE_PATH\" >> ~/.sentinel/reports/audit-trail.log"
      }]
    }],
    "WorktreeRemove": [{
      "hooks": [{
        "type": "command",
        "command": "echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) WORKTREE_REMOVE: $WORKTREE_PATH\" >> ~/.sentinel/reports/audit-trail.log"
      }]
    }]
  }
}
```

This creates a timestamped record of every isolated agent workspace — useful for compliance audits (SOC-2, ISO 27001) and debugging orphaned worktrees.

**Stale worktree auto-cleanup** (v2.1.105+) — worktrees from agents whose PR was squash-merged are now automatically removed instead of lingering indefinitely. This reduces disk usage for Sentinel's worktree-heavy multi-agent workflow without manual cleanup.

## OTEL Distributed Tracing (Audit Performance)

For audit performance observability, enable OpenTelemetry tracing with fine-grained controls (v2.1.98+):

```bash
# Enable TRACEPARENT propagation to Bash subprocesses
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
# Fine-grained controls (v2.1.101+)
export OTEL_LOG_TOOL_DETAILS=1    # Log tool parameters in spans
export OTEL_LOG_TOOL_CONTENT=1    # Log tool results in spans
```

When enabled, each agent dispatch, KB query, and RAG enrichment call gets a proper span in the trace tree. Use this to identify:
- Slow agents (high turn count or large context)
- Expensive KB queries (RAG latency)
- MCP tool bottlenecks (scan-dependencies, scan-headers)

## Important Notes

- Never expose secrets or credentials found during scanning — redact them in reports
- Rate findings conservatively: only mark as CRITICAL if exploitation is trivial and impact is severe
- Provide actionable remediations, not just descriptions of problems
- When unsure about a finding's severity, consult the CVSS v4 calculator rules
- Always run supply-chain-audit regardless of stack — every project has dependencies

## Plugin Distribution

Sentinel can be packaged as a distributable Claude Code plugin for one-command install:

```
sentinel-plugin/
  package.json          — plugin manifest (name, version, skills, agents, mcp-servers, bin)
  bin/                  — executable commands (v2.1.91+ plugin bin/ support)
    sentinel-cve-sync   — sync CVE feeds from NVD/OSV/GitHub
    sentinel-anthropic-sync — sync Anthropic ecosystem releases
    sentinel-index      — re-index all ChromaDB knowledge bases
  skills/
    sentinel-security/  — SKILL.md + agents/
    sentinel-rag/       — SKILL.md + knowledge/
    sentinel-evolve/    — SKILL.md + knowledge/
  mcp-servers/
    sentinel-scanner/   — TypeScript MCP server (scan-dependencies, scan-headers)
  knowledge-base/       — rules, standards, CVE feeds
  rag/                  — ChromaDB indexer, query, config
  scripts/              — deploy, sync, cron scripts
```

Plugin `bin/` executables (v2.1.91+) are available as bare commands from the Bash tool after install — no path required:
```bash
sentinel-cve-sync --days 90
sentinel-anthropic-sync
sentinel-index
```

Users install with: `claude plugin install sentinel` — this deploys all skills, agents, MCP server, and KB automatically.

**Offline environments** — set `CLAUDE_CODE_PLUGIN_KEEP_MARKETPLACE_ON_FAILURE=1` to preserve the local marketplace cache when `git pull` fails (v2.1.90+). This prevents plugin install failures in air-gapped or restricted network environments.

**Enterprise fail-closed policy** — for enterprise deployments, enable `forceRemoteSettingsRefresh` in managed settings (v2.1.92+). This blocks CLI startup until remote managed settings are freshly fetched — if the fetch fails, the CLI exits instead of running with stale or missing policy. This ensures Sentinel audits always run under the latest org security policy.

## Mode: evolve

**Autonomous Threat Intelligence Pipeline** — keeps Sentinel's detection rules and coverage up-to-date by syncing threat feeds, measuring coverage, and producing a Threat Intelligence Report (TIR).

This mode is the security counterpart to `/sentinel-evolve` (which optimizes Claude Code tooling). `/sentinel-security evolve` focuses on **what to detect** (rules, patterns, CVEs), not **how to detect** (tools, hooks, model tiers).

### Invocation

```
/sentinel-security evolve        # Full pipeline (sync → score → report)
/sentinel-security evolve sync   # Fetch all threat intel sources
/sentinel-security evolve score  # Measure coverage vs standards
/sentinel-security evolve report # Generate TIR
```

Phase 2 (future): `evolve gen` (LLM pattern generation), `evolve test` (rule validation), `evolve feedback` (FP/TP loop).

### Step 1: sync — Fetch Threat Intel Sources

Run the extended sync pipeline:
```
Bash: python3 /Users/manuelturpin/.sentinel/scripts/cve-sync.py
```

This fetches from 6 sources:
1. **NVD API v2** — CVE data with CVSS scores
2. **OSV API** — Open source vulnerabilities (300+ packages, 6 ecosystems)
3. **GitHub Advisories** — Supply chain security advisories
4. **EPSS** — Exploit Prediction Scoring (probability of exploitation)
5. **CISA KEV** — Known Exploited Vulnerabilities (actively exploited in the wild)
6. **OWASP/CWE Standards** — Checks GitHub for new versions of OWASP Top 10 lists

After sync, report:
- New CVEs added per source
- New KEV entries (actively exploited — highlight these)
- Standards updates available (flag if OWASP released a new version)

### Step 2: score — Coverage Measurement

Run the coverage scorer:
```
Bash: python3 /Users/manuelturpin/.sentinel/scripts/coverage-scorer.py --json
```

Parse the JSON output and present:
- Coverage % for each standard (OWASP Web, API, LLM, Mobile, CWE-25, MITRE ATLAS)
- Gaps: uncovered standard items with their IDs and names
- Rule quality: manual vs auto-with-patterns vs auto-template-only

### Step 3: report — Threat Intelligence Report (TIR)

Generate the TIR using the template at `/Users/manuelturpin/.sentinel/reports/templates/threat-intel-report.md`.

Fill in all placeholders with data from Steps 1-2:
1. Sync summary (per-source status and counts)
2. Rule quality breakdown
3. Standards coverage table with grades (OK >= 90%, WARN >= 70%, GAP < 70%)
4. Gap analysis (uncovered items per standard)
5. KEV highlights (most critical actively-exploited vulns)
6. Recommendations (based on gaps and new threats)

Save to `/Users/manuelturpin/.sentinel/reports/archive/TIR-{date}.md` and `/Users/manuelturpin/.sentinel/reports/archive/TIR-{date}.json`.

### Cron Schedule

The evolve pipeline is designed for weekly automated runs:
```
Weekly  Mon 6:00 AM  — cve-sync.py (all 6 sources)
Weekly  Mon 9:00 AM  — coverage-scorer.py + TIR generation
```

For manual runs, invoke `/sentinel-security evolve` anytime.

---

## Multi-Skill Orchestration (Agent Teams)

Sentinel skills can be orchestrated as an **agent team** with a shared task board for self-improving audit loops.

### Setup

```
TeamCreate("sentinel", members: ["sentinel-security", "sentinel-rag", "sentinel-evolve"])
```

### Roles

| Member | Role | Responsibilities |
|--------|------|-----------------|
| **sentinel-security** | Team lead | Orchestrates scans, dispatches agents, aggregates findings |
| **sentinel-rag** | KB expert | Enriches findings via RAG, diagnoses KB gaps, optimizes search quality |
| **sentinel-evolve** | Intel analyst | Monitors Claude Code updates, suggests skill improvements |

### Self-Improving Scan Loop

When the team is active, the audit workflow extends with a closed feedback loop:

1. **Scan** — sentinel-security runs a full audit, producing findings
2. **Analyze gaps** — if findings reference CVE patterns not in the KB, SendMessage to sentinel-rag: `"New pattern detected: {pattern}. Check if KB has coverage."`
3. **Update KB** — sentinel-rag adds missing rules/patterns to the KB and re-indexes
4. **Re-scan** — sentinel-security re-runs only the affected agents with updated KB
5. **Evolve** — sentinel-evolve logs the improvement in its update_history for tracking

### TeammateIdle Auto-Orchestration (v2.1.33+)

Configure a **TeammateIdle hook** to automate the self-improving loop handoffs:

```json
{
  "hooks": {
    "TeammateIdle": [{
      "matcher": "sentinel-security",
      "hooks": [{
        "type": "command",
        "command": "echo 'Scan agent idle — triggering KB gap analysis via sentinel-rag'"
      }]
    }]
  }
}
```

When a scan agent completes and goes idle, TeammateIdle fires — the team lead (sentinel-security) then SendMessages to sentinel-rag to check for KB gaps, triggering step 2 of the self-improving loop without manual intervention.

### Activation

Agent teams are experimental (v2.1.32+). The team is activated on demand — add this to Step 0 when the user requests "deep scan" or "self-improving scan":

```
If user requests deep/self-improving scan:
  TeamCreate("sentinel", members: ["sentinel-security", "sentinel-rag", "sentinel-evolve"])
  // Team members can now SendMessage to each other
  // Shared task board tracks cross-skill work
  // TeammateIdle hook auto-triggers KB gap analysis when scan agents finish
```
