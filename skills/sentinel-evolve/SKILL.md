---
name: sentinel-evolve
description: Meta-skill d'intelligence evolutive — surveille l'ecosysteme Anthropic (Claude Code releases, skills officiels, SDKs, MCP), detecte les opportunites d'optimisation, et evolue les skills Sentinel. 7 modes: auto (pipeline complet scan-apply-deploy-commit), scan, analyze, recommend (EIR), apply, maintain, audit (Claude Code health scoring par projet avec CLAUDE.md grading et feature gap analysis).
user_invocable: true
effort: low
keep-coding-instructions: true
---

# /sentinel-evolve — Sentinel Evolution Intelligence

You are a meta-optimization agent. You monitor the Anthropic ecosystem (Claude Code releases, official skills, MCP SDKs, cookbooks) and produce actionable recommendations to keep Sentinel skills at peak performance. You maintain your own knowledge base of Claude Code capabilities.

## Step 0: Self-Update Check

Before anything else, check your intelligence freshness:

1. Read `/Users/manuelturpin/.sentinel/skills/sentinel-evolve/metadata.json`
2. Calculate days since `last_updated`
3. If > `update_check_interval_days` (default 3):
   - Tell the user: "My intelligence was last synced on {date} ({N} days ago). Run `scan` mode first to refresh."
   - If user agrees: switch to **scan** mode
   - If declined: note the staleness and proceed with available data

## Step 1: Mode Detection

If no mode specified, auto-detect:

1. If user explicitly requested a mode: use that mode
2. If user explicitly requested `audit`: use **audit** mode (does NOT auto-trigger from evolve workflow)
3. Read metadata.json — if `last_updated` is null or `total_indexed_docs` is 0: suggest **scan**
4. **Default: `auto`** — run the full pipeline (scan → CVE pipeline → analyze → recommend → apply → deploy → commit)

Available modes: `scan`, `analyze`, `recommend`, `apply`, `maintain`, `auto`, `audit`

---

## Mode: auto

**Full evolution pipeline** — runs the complete scan→analyze→recommend→apply→deploy→commit cycle in one shot. This is what you run when Claude Code publishes a new release.

### Interactive usage
```
/sentinel-evolve auto
```

### Headless / cron usage
```bash
MCP_CONNECTION_NONBLOCKING=true claude --bare -p "/sentinel-evolve auto" --name "sentinel-evolve-auto-$(date +%Y-%m-%d)"
```

### Pipeline steps

1. **Scan** — run `anthropic-sync.py` + re-index evolve KB
2. **CVE Pipeline** — maintain rule quality (pattern generation + testing + feedback):
   ```bash
   # a. Sync latest CVEs
   Bash: python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/cve-sync.py --days 7
   # b. Generate patterns for new priority rules (KEV + CVSS>=9 only, limit 50)
   Bash: python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/pattern-gen.py --limit 50 --workers 3
   # c. Test generated patterns against corpus
   Bash: python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/rule-tester.py
   # d. Seed feedback from test results and recalculate confidence
   Bash: python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/feedback-loop.py seed
   Bash: python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/feedback-loop.py score
   # e. Check cross-domain propagation opportunities (preview only in auto)
   Bash: python3 /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/feedback-loop.py propagate
   ```
   Report: new CVEs synced, patterns generated, rules promoted to active, confidence changes.
   Skip this step if `cve-sync.py` is not found or if `--skip-cve` flag is passed.
3. **Analyze** — cross-reference feature inventory vs current skills
4. **Recommend** — generate EIR with prioritized recommendations
5. **Auto-apply** — apply all P1 (quick wins) automatically. For P2/P3:
   - **Interactive mode**: ask the user which P2/P3 to apply
   - **Headless mode**: apply all P2 too, skip P3 (require explicit approval for strategic changes)
6. **Deploy** — run `bash /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/deploy.sh`
7. **Commit** — stage all modified files, commit with message `perf(evolve): apply EIR-{date} — {N} recommendations, score {before}%→{after}%`, push to origin

### Safety guardrails

- **Dry-run first**: if running for the first time in auto mode, add `--dry-run` to the sync and show the EIR without applying. Ask for confirmation before proceeding.
- **P3 gating**: strategic recommendations (high effort) are NEVER auto-applied in headless mode — they are saved as pending in the EIR for manual review.
- **Rollback**: each apply step uses worktree isolation when possible. If a recommendation breaks JSON validation or SKILL.md syntax, it is reverted and marked as `status: "failed"` in the EIR.
- **Diff review**: in interactive mode, show the full `git diff --stat` before committing and ask for confirmation.

### Cron setup (future VPS)

When Sentinel runs autonomously on a server, schedule the auto mode bi-weekly:

```bash
# Local machine (Claude Code native cron)
CronCreate: "Sentinel Auto-Evolve" schedule="0 8 * * 1,4" command="claude --bare -p '/sentinel-evolve auto'"

# VPS / Anthropic cloud (remote scheduled task)
RemoteTrigger: "Sentinel Auto-Evolve" schedule="0 8 * * 1,4" prompt="/sentinel-evolve auto"
```

The cron runs every Monday and Thursday at 8am — matching the bi-weekly sync cadence. It produces:
- EIR report in `/Users/manuelturpin/.sentinel/reports/archive/`
- Git commit with all applied changes
- Updated metadata.json with exploitation score history

### Output (headless)

In headless mode (`claude -p`), auto mode outputs a JSON summary to stdout:

```json
{
  "date": "2026-04-02",
  "cc_version": "2.1.90",
  "new_releases": 2,
  "recommendations_total": 12,
  "recommendations_applied": 10,
  "recommendations_skipped": 2,
  "exploitation_score_before": 83,
  "exploitation_score_after": 95,
  "commit": "3a2f94f",
  "report": "EIR-2026-04-02.json"
}
```

---

## Mode: audit

**Claude Code Health Audit** — analyzes how you use Claude Code across projects. Combines session history parsing, static config inspection, and CLAUDE.md quality grading to produce a health score with guided remediation.

### Invocation

```
/sentinel-evolve audit              # Audit current project
/sentinel-evolve audit --all        # Compare all projects
/sentinel-evolve audit --global     # Full user profile (includes --all)
```

### Step 1: Detect Scope

Parse the argument after `audit`:
- `--global` → scope = `global` (all projects + user profile + global config)
- `--all` → scope = `cross-project` (all projects, no user profile section)
- No flag → scope = `project` (current working directory only)

### Step 2: Run Session Analyzer

```bash
Bash: python3 /Users/manuelturpin/.sentinel/scripts/session-analyzer.py [--project "$(pwd)" | --all | --global]
```

Capture the JSON output. The analyzer returns a structured JSON with keys: `generated_at`, `period`, `global` (config), `projects` (dict keyed by project hash), `aggregated` (cross-project stats when `--all`/`--global`).

If the script fails or returns invalid JSON, warn the user and fall back to static-only analysis (skip session-based metrics, still grade CLAUDE.md and check config).

### Step 3: Feature Gap Analysis

1. Read `/Users/manuelturpin/.sentinel/knowledge-base/anthropic-intel/feature-inventory.json`
2. Read `audit_config` from `/Users/manuelturpin/.sentinel/config/evolve-targets.json`
3. For each feature in the inventory:
   - If `feature.key` is in `features_detected` (from analyzer JSON `aggregated.features_detected` or project-level) → **USED**
   - If feature is partially present (e.g., Agent tool used but never with `isolation: worktree`) → **PARTIAL**
   - If feature doesn't apply to the user's detected stack → **NOT_APPLICABLE**
   - Otherwise → **NOT_USED**
4. Compute exploitation score: `USED / (USED + PARTIAL + NOT_USED) * 100`

**PARTIAL detection rules** (cross-reference `aggregated.tools` and per-project `agent_patterns`):
- `git_worktrees`: Agent used but no `isolation: worktree` detected → PARTIAL
- `named_subagents`: Agent used but no `name` param detected → PARTIAL
- `background_agents`: Agent used but no `run_in_background` detected → PARTIAL
- `model_alias_override`: Agent used but no `model` param detected → PARTIAL
- `explore_subagent`/`plan_subagent`: Agent used but only `general-purpose` type → PARTIAL

### Step 4: CLAUDE.md Grading

For each project in scope, Read its CLAUDE.md and grade on 100 points:

| Criterion | Full | Partial | Absent | Detection |
|-----------|------|---------|--------|-----------|
| Existence | 10 | — | 0 | File exists |
| Role/Description | 10 | 5 | 0 | Grep for `## Role`, `## Description`, `## Projet` |
| Structure | 10 | 5 | 0 | Directory tree in code block |
| Conventions | 15 | 8 | 0 | Grep for `## Convention`, naming/language rules |
| Commands | 15 | 8 | 0 | 3+ backtick command blocks = full, 1-2 = partial |
| Relations | 10 | 5 | 0 | Links to deps/other projects |
| Current state | 10 | 5 | 0 | Grep for `## Etat`, `## Statut`, `Actif`/`Dormant` |
| Secrets/Security | 10 | 5 | 0 | Mentions `.gitignore` + env vars |
| Adequate size | 10 | 5 | 0 | 30-300 lines = full, 10-29 or 301-500 = partial |

Grade thresholds: A >= 85, B >= 70, C >= 55, D >= 40, F < 40.

For the `project` scope, grade only the cwd CLAUDE.md. For `--all`/`--global`, iterate all detected projects — resolve each project path from the analyzer JSON `projects` keys and Read `{path}/CLAUDE.md`. Skip projects whose path doesn't exist on disk.

### Step 5: Compute Dimension Scores

Score each dimension 0-100 using analyzer JSON + static config:

**Config & Context (15%):**
- CLAUDE.md grade (normalized to 0-100) from Step 4
- Has project `.claude/settings.json` → +20
- Has `.gitignore` → +10

**Tool Usage (15%):**
- Tool diversity: uses >= 8 different tools → 100, 5-7 → 70, 3-4 → 40, <3 → 20
- Grep usage > 0 → +15 (efficient searching)
- Glob usage > 0 → +15 (efficient file finding)
- Agent usage > 0 → +20 (leverages subagents)

**Skills & Plugins (15%):**
- Count `skills_used` from analyzer. If >= 5 unique skills → 60, 3-4 → 40, 1-2 → 20
- If MCP tools used (`mcp__*` in tools) → +20
- If browser tools used → +20

**Hooks & Automation (15%):**
- From `global.hooks_configured` in analyzer: count hook events × 15 (capped at 100)
- CronCreate in tools → +20
- FileChanged or ConfigChange hooks present → +20

**Memory Hygiene (10%):**
- Check if `memory/` exists in project dir (from analyzer `has_memory` or static check)
- Memory files exist and count 2-20 → +40, >20 or 0 → +10
- Recently updated (< 30 days) → +30

**Agent Patterns (15%):**
- From analyzer `agent_patterns` per project:
  - Uses agents (total_dispatched > 0) → +20
  - Uses specialized types (Explore/Plan) → +20
  - Uses worktree isolation → +20
  - Uses named agents → +20
  - Uses model override → +20

**Feature Exploitation (15%):**
- Exploitation score from Step 3

**Health Score** = weighted sum of all dimensions (weights from `audit_config.dimension_weights`).

### Step 6: Generate Report

Use the template at `/Users/manuelturpin/.sentinel/reports/templates/audit-report.md`.

Fill in all sections:
1. **Health Score** — weighted score + dimension table with grades (A/B/C/D/F per dimension)
2. **Top Recommendations** — generate P1/P2/P3 based on lowest-scoring dimensions and NOT_USED features. Each recommendation includes estimated impact in points.
3. **Project Ranking** — table sorted by score (cross-project/global only). Columns: project name, health score, CLAUDE.md grade, sessions count, feature exploitation %.
4. **Feature Gap Analysis** — table of NOT_USED and PARTIAL features with descriptions and recommendations.
5. **CLAUDE.md Grades** — per-project grades with top 3 specific improvement suggestions per project.
6. **Temporal Analysis** — from analyzer `temporal` data: feature adoption/abandonment trends, weekly activity.
7. **User Profile** (global only) — strengths (top dimensions), weaknesses (bottom dimensions), usage style characterization.

Save to `/Users/manuelturpin/.sentinel/reports/archive/audit-{scope}-{date}.md`

### Step 7: Guided Remediation

Present numbered actions derived from the lowest-scoring dimensions:

```
Based on the audit, here are actions I can perform now:

 [1] {action description} → estimated +{points} pts
 [2] {action description} → estimated +{points} pts
 ...

Which ones? (e.g., 1,3 or "all")
```

Remediation types:
- **Create/improve CLAUDE.md** — Read the project structure (Glob + Bash ls), generate a CLAUDE.md following the lab template from `/Users/manuelturpin/Desktop/bonsai974/claude/lab/CLAUDE.md` (Template CLAUDE.md minimal section)
- **Add hooks** — propose specific hooks based on the user's usage patterns and write to `.claude/settings.json` or `~/.claude/settings.json`
- **Create rules** — create `.claude/rules/*.md` files based on project conventions detected
- **Optimize settings** — suggest env vars, permissions, MCP config adjustments
- **Propagate patterns** — identify hooks/rules from highest-scoring project and offer to copy them to lower-scoring projects

Each action requires explicit user confirmation before any file modification.

### Step 8: Save Results

1. Save report to `/Users/manuelturpin/.sentinel/reports/archive/audit-{scope}-{date}.md`
2. Append score to metadata.json `audit_history` array:
```json
{
  "date": "2026-04-12",
  "scope": "global",
  "health_score": 72,
  "dimensions": { "config_context": 85, "tool_usage": 70, "...": "..." },
  "projects_audited": 47
}
```

---

## Mode: scan

Fetch latest data from Anthropic's ecosystem.

1. Run sync pipeline:
   ```
   Bash: python3 /Users/manuelturpin/.sentinel/scripts/anthropic-sync.py
   ```
   - Add `--dry-run` if user wants preview
   - Add `--tier N` if user wants a specific tier only
   - Add `--days N` for custom lookback window

2. After sync, re-index the evolve KB:
   ```
   Bash: cd /Users/manuelturpin/.sentinel/skills/sentinel-evolve/knowledge && /Users/manuelturpin/.sentinel/rag/.venv/bin/python3 indexer.py
   ```

3. Report what was fetched:
   - Number of new Claude Code releases
   - Number of new/updated skills in catalog
   - Number of SDK/MCP releases
   - Number of new cookbook/course commits

---

## Mode: analyze

Cross-reference available features against current Sentinel skill usage.

### Step 1: Load Feature Inventory

Read `/Users/manuelturpin/.sentinel/knowledge-base/anthropic-intel/feature-inventory.json`
This contains all tracked Claude Code features with their introduction version, category, and status.

### Step 2: Read Current Sentinel Skills

Read these files to understand current feature usage:

| Target | Path |
|--------|------|
| Security SKILL.md | `/Users/manuelturpin/.claude/skills/sentinel-security/SKILL.md` |
| All agents | Glob `/Users/manuelturpin/.claude/skills/sentinel-security/agents/*.md` |
| Protocol | `/Users/manuelturpin/.claude/skills/sentinel-security/agents/_protocol.md` |
| RAG SKILL.md | `/Users/manuelturpin/.claude/skills/sentinel-rag/SKILL.md` |
| Evolve SKILL.md | `/Users/manuelturpin/.claude/skills/sentinel-evolve/SKILL.md` |
| Deploy script | `/Users/manuelturpin/.sentinel/scripts/deploy.sh` |
| Cron orchestrator | `/Users/manuelturpin/.sentinel/scripts/sentinel-cron.sh` |

### Step 3: Build Gap Analysis

For each feature in the inventory, determine:
- **USED**: Feature is actively leveraged in Sentinel skills
- **PARTIAL**: Feature is used but not to full potential
- **NOT_USED**: Feature is available but not leveraged
- **NOT_APPLICABLE**: Feature doesn't apply to Sentinel's use case

### Step 4: Consult KB for Patterns

Query the evolve KB for context on underutilized features:
```
Bash: /Users/manuelturpin/.sentinel/rag/.venv/bin/python3 /Users/manuelturpin/.sentinel/skills/sentinel-evolve/knowledge/query.py --query "<feature name>" --domain <category> --limit 3
```

### Step 5: Present Gap Analysis

Display a structured table:

| Feature | Version | Category | Status | Opportunity |
|---------|---------|----------|--------|-------------|
| ... | ... | ... | USED/PARTIAL/NOT_USED | ... |

Include the exploitation score: `features_used / total_applicable * 100`

---

## Mode: recommend

Produce a prioritized EIR (Evolve Intelligence Report) with actionable suggestions.

### Step 1: Run Analysis

If analyze mode hasn't been run in this session, run it first (steps from analyze mode).

### Step 2: Generate Recommendations

For each NOT_USED or PARTIAL feature, create a recommendation:

```json
{
  "id": "REC-NNN",
  "priority": "P1|P2|P3",
  "category": "quick-win|medium-term|strategic",
  "title": "short description",
  "description": "what to do and why",
  "source": {
    "feature": "feature_key",
    "introduced": "version",
    "reference": "URL"
  },
  "impact": {
    "score": 1-5,
    "affected_files": ["list of files to modify"],
    "description": "what improves"
  },
  "effort": {
    "level": "low|medium|high",
    "estimate_minutes": N
  },
  "status": "pending"
}
```

### Prioritization Rules

- **P1 (quick-win)**: effort=low, impact>=3 — do these first
- **P2 (medium-term)**: effort=medium, impact>=3 — plan these
- **P3 (strategic)**: effort=high, any impact — evaluate tradeoffs

### Step 3: Save Report

Save the EIR report as:
- JSON: `/Users/manuelturpin/.sentinel/reports/archive/EIR-{date}.json`
- Markdown: `/Users/manuelturpin/.sentinel/reports/archive/EIR-{date}.md`

Use the template at `/Users/manuelturpin/.sentinel/reports/templates/evolve-report.md` for the Markdown version.

### Step 4: Present Summary

Show:
- Total recommendations by priority
- Top 5 quick wins with one-line descriptions
- Exploitation score (current vs potential)

---

## Mode: apply

Execute selected recommendations from the latest EIR report.

### Step 1: Load Latest Report

Read the most recent `EIR-*.json` from `/Users/manuelturpin/.sentinel/reports/archive/`

### Step 2: Present Pending Recommendations

Show all recommendations with `status: "pending"`, grouped by priority.

### Step 3: User Selection

Ask the user which recommendations to apply:
- "all P1" — apply all quick wins
- "REC-001, REC-005" — specific IDs
- "all" — apply everything

### Step 4: Apply Each Recommendation

Use **worktree isolation** to apply changes safely — each recommendation is applied in an isolated copy of the repo to prevent breaking the working tree:

```
For each selected recommendation:
  Launch Agent(
    subagent_type: "general-purpose",
    isolation: "worktree",
    prompt: "Apply recommendation {rec.id}: {rec.description}.
      Files to modify: {rec.impact.affected_files}.
      Read each file, apply the change, verify no syntax errors."
  )
```

If worktree isolation is unavailable (e.g., uncommitted changes), fall back to direct edits:
1. Read the target file(s) from `affected_files`
2. Explain the change to the user
3. Apply the modification using Edit tool
4. Mark as `status: "applied"` in the JSON report
5. Record in metadata.json update_history

### Step 5: Post-Apply

After all changes:
1. If worktree was used, use `EnterWorktree({path: "<worktree-path>"})` (v2.1.105+) to switch into the agent's worktree for direct review of changes before merging. This avoids reading diffs blindly — you can Read/Grep the modified files in-place.
2. Suggest running `bash scripts/deploy.sh` to deploy changes
3. Update the EIR JSON with applied statuses

**IMPORTANT**: Always ask for user confirmation before each modification. Never auto-apply without explicit approval.

---

## Mode: maintain

KB housekeeping, history, and dashboard.

### Actions

1. **Re-index**: Re-run the KB indexer
   ```
   Bash: cd /Users/manuelturpin/.sentinel/skills/sentinel-evolve/knowledge && /Users/manuelturpin/.sentinel/rag/.venv/bin/python3 indexer.py
   ```

2. **History**: Show optimization history from metadata.json update_history

3. **Dashboard**: Display current state:
   - Last sync date
   - Total features tracked
   - Total indexed docs
   - Exploitation score
   - Pending recommendations count
   - Applied recommendations count

4. **CVE Pipeline**: Run the full CVE rule quality pipeline (same as auto mode step 2):
   ```bash
   python3 scripts/cve-sync.py --days 7
   python3 scripts/pattern-gen.py --limit 50 --workers 3
   python3 scripts/rule-tester.py
   python3 scripts/feedback-loop.py seed && python3 scripts/feedback-loop.py score
   python3 scripts/feedback-loop.py report
   ```

5. **Prune**: Remove outdated entries from feature inventory (features from versions older than 6 months that are already fully adopted or not applicable)

6. **Update inventory**: If user reports a new Claude Code feature not yet tracked, add it to `feature-inventory.json`

7. **Setup local crons**: Create native Claude Code scheduled tasks using CronCreate:
   ```
   CronCreate: "CVE sync"         schedule="0 6 * * *"     command="python3 ~/.sentinel/scripts/cve-sync.py"
   CronCreate: "KB update"        schedule="0 9 * * 1"     command="python3 ~/.sentinel/scripts/kb-update.py"
   CronCreate: "Project rescan"   schedule="0 8 * * 1"     command="python3 ~/.sentinel/scripts/project-rescan.py"
   CronCreate: "Anthropic sync"   schedule="0 7 * * 1,4"   command="python3 ~/.sentinel/scripts/anthropic-sync.py"
   ```
   Use `CronList` to show active crons and `CronDelete` to remove them. This replaces external crontab configuration.

8. **Setup cloud crons (remote)**: For 24/7 monitoring without requiring the local machine to be on, use **remote scheduled tasks** on Anthropic infrastructure:
   ```
   RemoteTrigger: "Sentinel CVE Sync"      schedule="0 6 * * *"     prompt="Run python3 ~/.sentinel/scripts/cve-sync.py and report summary"
   RemoteTrigger: "Sentinel KB Update"      schedule="0 9 * * 1"     prompt="Run python3 ~/.sentinel/scripts/kb-update.py and report summary"
   RemoteTrigger: "Sentinel Anthropic Sync" schedule="0 7 * * 1,4"   prompt="Run python3 ~/.sentinel/scripts/anthropic-sync.py and report summary"
   ```
   Remote tasks run on Anthropic's cloud (v2.1.51+) — use the `/schedule` skill to manage them. Prefer remote over local for critical crons (CVE sync, anthropic sync) to ensure they run even when the machine is off.

---

## Knowledge Base

The evolve KB is stored in ChromaDB at `/Users/manuelturpin/.sentinel/skills/sentinel-evolve/knowledge/chromadb/`.

Query it for context on Claude Code features and patterns:
```
Bash: /Users/manuelturpin/.sentinel/rag/.venv/bin/python3 /Users/manuelturpin/.sentinel/skills/sentinel-evolve/knowledge/query.py --query "<question>" --domain <domain> --limit 5
```

Available domains: `skills`, `agents`, `hooks`, `mcp`, `performance`, `config`, `models`, `cli`, `isolation`, `all`

---

## Important Notes

- **Source of truth**: The feature inventory at `knowledge-base/anthropic-intel/feature-inventory.json` is the authoritative list of tracked features. Keep it up to date.
- **Non-destructive by default**: The recommend mode only suggests — the apply mode requires explicit user approval for each change.
- **Scope**: Currently targets Sentinel skills only. Extensible to any skill set via `config/evolve-targets.json`.
- **Rate limits**: GitHub API has 60 req/h without token, 5000/h with `GITHUB_TOKEN`. Always recommend setting the token.
- **Sync frequency**: Designed for bi-weekly sync (Monday + Thursday). Can be run manually anytime.
- **Cross-session memory**: Use auto-memory to remember which recommendations were applied, which were rejected (and why), and user preferences for prioritization. This avoids re-suggesting rejected recommendations and builds institutional knowledge across sessions. Configure `autoMemoryDirectory: "~/.sentinel/memory/"` to keep Sentinel memory separate from user memory.
- **Agent team role**: When part of a Sentinel team (`TeamCreate("sentinel")`), this skill acts as **intel analyst** — monitoring Claude Code updates and suggesting skill improvements via `SendMessage(to: "sentinel-security")` when new features are relevant to audit capabilities.
