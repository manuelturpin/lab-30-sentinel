# Sentinel Evolve Audit Mode — Design Spec

**Date**: 2026-04-12
**Author**: Manuel + Claude
**Status**: Draft
**Scope**: New `audit` mode for `/sentinel-evolve` skill

---

## Problem

Sentinel Evolve tracks 84+ Claude Code features and optimizes Sentinel skills against them. But there is no way to audit how a user actually leverages Claude Code across their projects. Users don't know what features they're missing, which projects are under-optimized, or how their usage patterns evolve over time.

## Solution

Add an `audit` mode to `/sentinel-evolve` that analyzes Claude Code usage at 3 levels (project, cross-project, global) by combining session history analysis, static config inspection, and CLAUDE.md quality grading. A Python script handles heavy JSONL parsing; the SKILL.md orchestrates analysis, gap detection, and interactive remediation.

## Architecture

```
/sentinel-evolve audit [--all] [--global]
        |
        v
+---------------------------+
|   SKILL.md (orchestrator) |
|                           |
|  1. Detect scope          |
|  2. Call analyzer.py      |
|  3. Gap analysis features |
|  4. Grade CLAUDE.md       |
|  5. Generate report .md   |
|  6. Guided remediation    |
+----------+----------------+
           | Bash call
           v
+---------------------------+
|  session-analyzer.py      |
|                           |
|  Parse JSONL sessions     |
|  Aggregate metrics        |
|  Return structured JSON   |
+---------------------------+
           | JSON stdout
           v
+---------------------------+
|  feature-inventory.json   |
|  (84+ tracked features)   |
+---------------------------+
```

### Separation of concerns

| Component | Role | Input | Output |
|-----------|------|-------|--------|
| **SKILL.md** | Orchestrate, reason, recommend, remediate | JSON from analyzer + feature inventory + project CLAUDE.md | Markdown report + remediation actions |
| **session-analyzer.py** | Parse, count, aggregate | Path to `~/.claude/projects/` | Structured JSON (metrics per project, per tool, temporal) |
| **feature-inventory.json** | Feature reference | Maintained by sentinel-evolve sync | Consumed by SKILL.md for gap analysis |

## Audit Modes

| Command | Scope | Behavior |
|---------|-------|----------|
| `/sentinel-evolve audit` | Current project | Analyze sessions + config + CLAUDE.md of cwd |
| `/sentinel-evolve audit --all` | Cross-project | Analyze all projects, compare, rank |
| `/sentinel-evolve audit --global` | User profile | Global profile, trends, all-time stats (includes --all) |

Cumulative: `--global` includes `--all` which includes current project.

## session-analyzer.py

### Invocation

```bash
python3 ~/.sentinel/scripts/session-analyzer.py [--project <path>] [--all] [--global]
```

Outputs JSON to stdout. The SKILL.md captures it via Bash.

### Privacy

The script reads ONLY metadata from JSONL sessions:
- Message types (`user`, `assistant`, `system`, `attachment`)
- Tool use names and parameter keys (NOT values)
- Agent tool parameters: `subagent_type`, `name`, `model`, `isolation`, `run_in_background`
- Timestamps
- Session IDs and project directory names

It does NOT read:
- Message content (user prompts, assistant responses)
- File contents from Read/Edit operations
- Bash command strings or output
- Any actual code or text

**Filtering rules**: Agent tool parameters are extracted by whitelisted keys only (`subagent_type`, `name`, `model`, `isolation`, `run_in_background`, `mode`). All other parameter values are ignored. Bash tool entries are counted but their `command` field is never read. Any value matching `(key|secret|token|password|credential)` patterns encountered during parsing is replaced with `[REDACTED]`. Corrupted or truncated JSONL lines are skipped with `json.JSONDecodeError` handling — partial sessions produce partial results rather than failures.

### Output JSON Schema

```json
{
  "generated_at": "ISO-8601",
  "period": {
    "first_session": "YYYY-MM-DD",
    "last_session": "YYYY-MM-DD",
    "total_days": 0
  },
  "global": {
    "total_sessions": 0,
    "total_messages": 0,
    "total_projects": 0,
    "active_projects_30d": 0,
    "avg_session_duration_min": 0,
    "avg_messages_per_session": 0
  },
  "tools": {
    "<tool_name>": { "count": 0, "pct": 0.0 }
  },
  "skills_used": {
    "<skill_name>": 0
  },
  "agent_patterns": {
    "total_dispatched": 0,
    "with_background": 0,
    "with_worktree": 0,
    "with_named": 0,
    "with_model_override": 0,
    "subagent_types": {
      "<type>": 0
    }
  },
  "features_detected": ["<feature_key>", "..."],
  "projects": [
    {
      "id": "<project-dir-hash>",
      "path": "<resolved-path>",
      "sessions_count": 0,
      "last_active": "YYYY-MM-DD",
      "tools": { "<tool_name>": 0 },
      "skills_used": ["<skill_name>"],
      "has_claude_md": false,
      "has_settings": false,
      "has_hooks": false,
      "has_rules": false,
      "has_memory": false
    }
  ],
  "temporal": {
    "weekly_sessions": [
      { "week": "YYYY-WNN", "sessions": 0, "tool_calls": 0 }
    ],
    "feature_adoption": [
      { "feature": "<key>", "first_used": "YYYY-MM-DD", "last_used": "YYYY-MM-DD", "use_count": 0, "status": "active|abandoned|one-time" }
    ]
  }
}
```

### Feature detection from sessions

The script detects feature usage by scanning tool calls and their parameters:

| Feature | Detection signal |
|---------|-----------------|
| `git_worktrees` | Agent tool with `isolation: "worktree"` |
| `agent_teams` | TeamCreate tool call |
| `auto_memory` | Write tool to `*/memory/*.md` |
| `named_subagents` | Agent tool with `name` parameter |
| `background_agents` | Agent tool with `run_in_background: true` |
| `model_alias_override` | Agent tool with `model` parameter |
| `skills_system` | Skill tool call |
| `task_create_update` | TaskCreate/TaskUpdate tool calls |
| `web_fetch_search` | WebFetch/WebSearch tool calls |
| `browser_automation` | `mcp__claude-in-chrome__*` tool calls |
| `mcp_servers` | Any `mcp__*` tool call |
| `structured_outputs` | `--json-schema` in Bash commands (parameter key only) |
| `plan_subagent` | Agent with `subagent_type: "Plan"` |
| `explore_subagent` | Agent with `subagent_type: "Explore"` |
| `monitor_tool` | Monitor tool call |

### Static config detection

For each project, the script also checks file existence:

| File | Feature signal |
|------|---------------|
| `CLAUDE.md` | Project context configured |
| `.claude/settings.json` | Project-level settings |
| `.claude/rules/*.md` | Rules files configured |
| `<project-dir>/memory/` | Auto-memory active |
| `.sentinel.json` | Sentinel audit config |

Global config (`~/.claude/settings.json`):
- `hooks` key → hooks configured (list which events)
- `env` key → environment variables set
- `permissions` key → permission rules
- `mcpServers` key → MCP servers registered

## SKILL.md Audit Logic

### Step 1: Scope Detection

```
If argument is "audit":
  If --global flag: scope = "global"
  Else if --all flag: scope = "cross-project"  
  Else: scope = "project" (use cwd)
```

### Step 2: Run Analyzer

```bash
python3 ~/.sentinel/scripts/session-analyzer.py [flags based on scope]
```

Capture JSON output. If script fails, report error and fall back to static-only analysis.

### Step 3: Feature Gap Analysis

For each feature in `feature-inventory.json`:
1. Check if `feature.key` is in `features_detected` from analyzer → USED
2. Check if feature is partially present (e.g., Agent used but never with worktree) → PARTIAL
3. Check if feature is applicable to the project's stack → NOT_USED or NOT_APPLICABLE
4. Compute exploitation score: `USED / (USED + PARTIAL + NOT_USED) * 100`

### Step 4: CLAUDE.md Grading

For each project in scope, Read its CLAUDE.md and grade on 100:

| Criterion | Points | Detection |
|-----------|--------|-----------|
| Existence | 10 | File exists → 10 pts. Missing → 0 pts. |
| Role/Description | 10 | Dedicated section (`## Role`, `## Description`, `## Projet`) → 10 pts. Mentioned but no section → 5 pts. Absent → 0 pts. |
| Structure | 10 | Directory tree in code block → 10 pts. Partial mention → 5 pts. Absent → 0 pts. |
| Conventions | 15 | Dedicated section with naming/language/stack rules → 15 pts. Partial → 8 pts. Absent → 0 pts. |
| Commands | 15 | 3+ documented commands with backtick blocks → 15 pts. 1-2 commands → 8 pts. Absent → 0 pts. |
| Relations | 10 | Links to deps/other projects → 10 pts. Partial → 5 pts. Absent → 0 pts. |
| Current state | 10 | Status + last activity → 10 pts. Only status → 5 pts. Absent → 0 pts. |
| Secrets/Security | 10 | Mentions .gitignore + env vars → 10 pts. Partial → 5 pts. Absent → 0 pts. |
| Adequate size | 10 | 30-300 lines → 10 pts. 10-29 or 301-500 → 5 pts. <10 or >500 → 0 pts. |

Grade thresholds: A >= 85, B >= 70, C >= 55, D >= 40, F < 40.

### Step 5: Report Generation

Generate Markdown report to `~/.sentinel/reports/archive/audit-{scope}-{date}.md`:

```markdown
# Claude Code Health Audit

**Date**: {date}
**Scope**: {scope}
**Period**: {first} - {last} ({days} days)
**Sessions analyzed**: {count}

## Health Score: {score}/100

| Dimension           | Score | Grade |
|---------------------|-------|-------|
| Config & Context    |       |       |
| Tool Usage          |       |       |
| Skills & Plugins    |       |       |
| Hooks & Automation  |       |       |
| Memory Hygiene      |       |       |
| Agent Patterns      |       |       |
| Feature Exploitation|       |       |

## Top Recommendations
(prioritized P1/P2/P3 with estimated impact)

## Project Ranking (cross-project/global)
(table: project, score, CLAUDE.md grade, sessions, feature %)

## Feature Gap Analysis
(NOT_USED and PARTIAL features with recommendations)

## CLAUDE.md Grades
(per-project grades with specific improvement suggestions)

## Temporal Analysis
(trends, adopted/abandoned features)

## User Profile (global)
(strengths, weaknesses, style characterization)
```

### Step 6: Guided Remediation

After displaying the report, present numbered actions:

```
Actions I can perform now:

 [1] Create/improve CLAUDE.md for lab-25 (D → B)
 [2] Add PreToolUse hook for auto-allow Read/Grep
 [3] Create .claude/rules/ for current project
 [4] Configure autoMemoryDirectory
 [5] Propagate hooks from lab-30 to lab-13

Which ones? (e.g., 1,3,5 or "all")
```

Each action is executed interactively with confirmation before modification.

Remediation categories:
- **CLAUDE.md creation/improvement** — generate or restructure based on grading criteria
- **Hook configuration** — add hooks to settings.json (project or global)
- **Rules creation** — create .claude/rules/*.md files
- **Settings optimization** — adjust env vars, permissions, MCP config
- **Cross-project propagation** — copy proven patterns from high-scoring projects to low-scoring ones

### Step 7: Save Results

- Report to `~/.sentinel/reports/archive/audit-{scope}-{date}.md`
- Score history appended to metadata.json `audit_history` array
- Auto-memory: save detected user preferences and patterns

## Dimension Scoring

Each of the 7 dimensions is scored 0-100:

### Config & Context (weight: 15%)
- CLAUDE.md grade (from Step 4)
- Project settings presence
- .gitignore configured

### Tool Usage (weight: 15%)
- Diversity: uses 80%+ of available tool types → high
- Efficiency: Grep/Glob vs excessive Bash for search → high
- Read vs cat-in-Bash → high

### Skills & Plugins (weight: 15%)
- Skills installed vs used ratio
- Plugins installed vs used ratio
- Skill invocation frequency

### Hooks & Automation (weight: 15%)
- Hook events configured (PreToolUse, PostCompact, FileChanged, etc.)
- Crons configured (CronCreate calls in sessions)
- Automation maturity

### Memory Hygiene (weight: 10%)
- Memory files exist
- Memory files are not stale (< 30 days old)
- No duplicates
- Reasonable count (not 0, not 100+)

### Agent Patterns (weight: 15%)
- Uses subagents
- Uses specialized types (Explore, Plan, not just general-purpose)
- Uses isolation (worktree)
- Uses named agents
- Uses background agents
- Uses model overrides for cost optimization

### Feature Exploitation (weight: 15%)
- Exploitation score from gap analysis
- Trend: improving or declining over time

**Final score** = weighted average of all dimensions.

## Integration in sentinel-evolve

### SKILL.md changes

Add to Step 1 (Mode Detection):
```
Available modes: scan, analyze, recommend, apply, maintain, auto, audit
```

Add full `## Mode: audit` section after `## Mode: auto` with the 7 steps above.

### evolve-targets.json changes

Add `audit_config` section:
```json
{
  "audit_config": {
    "sessions_dir": "~/.claude/projects/",
    "settings_global": "~/.claude/settings.json",
    "skills_dir": "~/.claude/skills/",
    "plugins_dir": "~/.claude/plugins/",
    "analyzer_script": "~/.sentinel/scripts/session-analyzer.py",
    "claude_md_grading": {
      "max_score": 100,
      "grade_thresholds": { "A": 85, "B": 70, "C": 55, "D": 40, "F": 0 }
    },
    "dimensions": [
      "config_context",
      "tool_usage",
      "skills_plugins",
      "hooks_automation",
      "memory_hygiene",
      "agent_patterns",
      "feature_exploitation"
    ],
    "dimension_weights": {
      "config_context": 0.15,
      "tool_usage": 0.15,
      "skills_plugins": 0.15,
      "hooks_automation": 0.15,
      "memory_hygiene": 0.10,
      "agent_patterns": 0.15,
      "feature_exploitation": 0.15
    },
    "temporal_thresholds": {
      "active_days": 30,
      "abandoned_days": 30,
      "one_time_max_uses": 1
    }
  }
}
```

Temporal status definitions:
- **active**: `last_used` within `active_days` of analysis date (default: 30 days)
- **abandoned**: `use_count > 1` AND `last_used` older than `abandoned_days` (used regularly then stopped)
- **one-time**: `use_count <= one_time_max_uses` (tried once, never came back)
```

### New files

| File | Location (repo) | Location (deployed) | Role |
|------|----------------|---------------------|------|
| `session-analyzer.py` | `scripts/session-analyzer.py` | `~/.sentinel/scripts/` | Parse JSONL, produce JSON |
| Audit section in SKILL.md | `skills/sentinel-evolve/SKILL.md` | `~/.claude/skills/sentinel-evolve/SKILL.md` | ~200 lines for audit mode |
| Report template | `reports/templates/audit-report.md` | `~/.sentinel/reports/templates/` | Markdown template |

### deploy.sh

No changes needed. `scripts/` and `reports/templates/` are already copied by deploy.sh.

## Non-Goals

- No web dashboard (Markdown only, per user request)
- No cloud/remote analysis (local only, per privacy preference)
- No content analysis of sessions (metadata only)
- No comparison with other users (single-user tool)
- No auto-remediation without user confirmation (guided mode only)

## Testing

- `session-analyzer.py` unit tests: mock JSONL files, verify JSON output schema
- SKILL.md integration: run audit on lab-30 (known good) and verify scores match expectations
- Cross-project: verify all 47 projects are discovered and ranked
- Remediation: test CLAUDE.md generation on a project with no CLAUDE.md
