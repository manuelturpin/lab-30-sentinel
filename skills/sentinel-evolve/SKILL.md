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
6. **Commit** — versionner AVANT de déployer. `CLAUDE.md` du dépôt fixe cet ordre (« 1. Commit + push vers GitHub · 2. Deployer sur la machine locale ») et ce pipeline le violait jusqu'au 2026-07-27 : il déployait un état non commité, mettant le runtime en avance sur git — c'est-à-dire recréant exactement le drift que le cycle prétend réparer. *(Finding S1, blocker, revue croisée GPT-5.6-Sol du 27/07.)* En ordre strict, sans raccourci :
   ```bash
   # a. Pre-commit assertion: EIR report must exist on disk in the source repo.
   Bash: test -f reports/archive/EIR-{date}.json && test -f reports/archive/EIR-{date}.md || { echo "ABORT: EIR file missing — do not commit"; exit 1; }
   # b. Stage the EIR explicitly (don't rely on "git add -A" — templates are gitignored, EIR-*.md uses a negation rule).
   Bash: git add reports/archive/EIR-{date}.json reports/archive/EIR-{date}.md
   # c. Stage the files touched by applied recommendations (SKILL.md edits, config JSON, scripts, etc.). Use "git add -u" to pick up only modifications — never stage untracked files blindly.
   Bash: git add -u
   # d. Commit with the canonical message.
   Bash: git commit -m "perf(evolve): apply EIR-{date} — {N} recommendations, score {before}%→{after}%"
   # e. Push.
   Bash: git push
   ```
7. **Deploy** — une fois, et une fois seulement, que le commit est poussé :
   ```bash
   # DRY_RUN=0 est obligatoire : deploy.sh vaut DRY_RUN=1 par défaut depuis 2026-04-17 (H3 audit fix),
   # donc `bash scripts/deploy.sh` nu est un no-op silencieux.
   Bash: DRY_RUN=0 bash /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/scripts/deploy.sh
   # Contrôle de santé : le déploiement doit avoir produit les 3 skills. Échec fermé si l'un manque.
   Bash: for s in sentinel-security sentinel-rag sentinel-evolve; do test -f ~/.claude/skills/$s/SKILL.md || { echo "ABORT: $s non déployé"; exit 1; }; done
   ```

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
- EIR report in `lab-30-sentinel/reports/archive/` (source repo — tracked by git, then mirrored to `~/.sentinel/reports/archive/` by `deploy.sh`)
- Git commit with all applied changes (including the EIR JSON and Markdown)
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

Save the EIR report **in the source repo** so it can be committed by git and mirrored to runtime by `deploy.sh`:

- JSON: `/Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/reports/archive/EIR-{date}.json`
- Markdown: `/Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/reports/archive/EIR-{date}.md`

Use the template at `/Users/manuelturpin/.sentinel/reports/templates/evolve-report.md` for the Markdown version.

**Verification (mandatory before Step 4)** — after Write, run:

```bash
Bash: ls -la /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/reports/archive/EIR-{date}.json /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/reports/archive/EIR-{date}.md
```

If either file is missing, **abort** and re-issue the Write. Never proceed to commit if the EIR files aren't on disk. Historical note: pre-2026-04-17, EIRs were written to `~/.sentinel/reports/archive/` which is wiped by `deploy.sh --delete`; this silently lost 9 reports (H4 audit finding).

### Step 4: Present Summary

Show:
- Total recommendations by priority
- Top 5 quick wins with one-line descriptions
- Exploitation score (current vs potential)

---

## Mode: apply

Execute selected recommendations from the latest EIR report.

### Step 1: Load Latest Report

Read the most recent `EIR-*.json` from `/Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/reports/archive/` (source repo — authoritative location since 2026-04-17). Fall back to `/Users/manuelturpin/.sentinel/reports/archive/` only if the source repo location has no EIR files.

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

---

## Model Migration Notes

### Fable 5 (released 2026-06-09, Claude Code v2.1.170)

Claude **Fable 5** (`claude-fable-5`) is a **Mythos-class model above Opus 4.8** — the most capable GA model (1M context, 128K output, **$10/$50 per MTok**). CLI accepts both `fable` (alias) and `claude-fable-5` (full id) for `--model` / `/model`. SDK support landed in anthropic-sdk-python v0.108.0 (+ server-side fallbacks on refusal).

- **Same breaking-change surface as Opus 4.7/4.8** (no `temperature`/`top_p`/`top_k`, `budget_tokens`→adaptive) **plus one new break**: adaptive thinking is **always-on**, so `thinking:{type:"disabled"}` returns **HTTP 400** — omit the `thinking` param entirely. Refusals return `stop_reason:"refusal"` as **HTTP 200** (not an error) — handle accordingly. Cache minimum prefix is 512 tokens (vs 4096 on Opus).
- **⚠️ Do NOT default-orchestrate Sentinel on Fable 5.** Fable 5 has a **real-time cyber/biology safety classifier** that flags security content and **auto-switches the session to Opus 4.8** (false positives common). Sentinel's domain *is* cybersecurity, so it trips the classifier continuously. Keep the orchestrator on **`opus`** (alias, résolu vers Opus 5 — ne jamais épingler `claude-opus-4-8` littéralement), ou candidater au [Cyber Verification Program](https://claude.com/form/cyber-use-case) pour un usage défensif légitime. Verified empirically during EIR-2026-06-10 (the cycle integrating Fable 5 itself auto-switched off Fable 5).
- **Portée de cette contrainte, mesurée le 27/07/2026** : elle vise l'orchestrateur *en fonctionnement* sur du contenu d'exploit, pas tout appel touchant à la sécurité. Sonde `claude -p --model claude-fable-5` sur une question d'architecture de scanner : `canonicalModel: "claude-fable-5"`, contexte 1M, aucun basculement ni refus. Un appel de revue borné, cadré architecture/design, reste donc exploitable — mais instrumenter `canonicalModel` à chaque appel plutôt que présumer (n=1).
- Fable 5 is still the right pick for **non-security** labs and for individual non-flagged subtasks.

### Opus 5 (released 2026-07-24) — CURRENT DEFAULT

Opus 5 (`claude-opus-5`) is the current default Opus model since Claude Code **v2.1.219**. The `opus` alias resolves to it on Max/Team/Enterprise. **Never pin a literal `claude-opus-4-8`** — that downgrades the session.

What changes for Sentinel:

- **Effort : `high` est le défaut ET le point de départ recommandé sur Opus 5.** ✅ **Vérifié sur source primaire** ([docs effort](https://platform.claude.com/docs/en/build-with-claude/effort.md)) : « **Start with `high`, the default**, and adjust based on your evals: step up to `xhigh` for demanding coding and agentic work […] and use `low` and `medium` liberally as your primary control for token cost and response time ». Le passage de `xhigh` → `high` sur `sentinel-security` le 25/07 est donc **correct**.
  > ⚠️ **Piège de génération** : la recommandation diffère selon le modèle. Pour **Opus 4.7 et 4.8**, la même page dit l'inverse — « **Start with `xhigh` for coding and agentic use cases** ». Ne pas transposer la consigne 4.7/4.8 à Opus 5 : c'est précisément la confusion que porte le skill interne `claude-api`. La doc ajoute pour Opus 5 : « If you carried effort settings over from an earlier model, run a fresh effort sweep on your evals rather than reusing them. »
  >
  > Corollaire mesuré : « Effort controls thinking volume, not visible response length: on Claude Opus 5, changing effort does **not** reliably shorten responses » — pour de la concision, prompter explicitement, ne pas baisser l'effort. Et à `xhigh`/`max`, `thinking:{type:"disabled"}` renvoie **HTTP 400**, avec un `max_tokens` d'au moins 64 K recommandé.
- **✅ Les classifieurs cyber d'Opus 5 sont NETTEMENT MOINS restrictifs — pas plus.** *(Corrigé le 27/07/2026 sur source primaire : [anthropic.com/news/claude-opus-5](https://www.anthropic.com/news/claude-opus-5).)* Citation : « proportionally less restrictive than those on Fable 5 […] we expect the classifiers to **intervene around 85% less often** than they do for Fable 5 ». Le régime est **similaire à Opus 4.8**, avec un durcissement limité à une gamme étroite de tâches cyber.
- **✅ La recherche de vulnérabilités dans du code source est explicitement AUTORISÉE sur Opus 5** — c'est-à-dire le cœur d'activité de Sentinel. Ce qui reste bloqué par défaut ([support.claude.com](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude)) : *Prohibited use* (exfiltration massive de données, développement de ransomware) et *High-Risk Dual use* (exploitation de vulnérabilités, outillage offensif). Sentinel ne fait ni l'un ni l'autre : il lit du source et applique des règles.
- Un refus revient en **HTTP 200** avec `stop_reason: "refusal"` et un `stop_details` portant la catégorie (`"cyber"`, `"bio"`, `null`…), **pas** une erreur : toujours tester `stop_reason` **avant** de lire `response.content`, sinon un accès direct à `content[0]` casse. `stop_details` n'est peuplé que sur un refus — le garder derrière une garde.
- **Cyber Verification Program** : portail [portal.anthropic.com/programs/cvp](http://portal.anthropic.com/programs/cvp), décision sous **2 jours ouvrés**. ⚠️ Le CVP **exige la rétention de données activée** — un compte en Zero Data Retention doit créer un workspace séparé. Vu le régime déjà permissif d'Opus 5 sur l'audit de source, le CVP n'est **pas nécessaire** pour Sentinel en l'état ; il ne le deviendrait que pour de l'exploitation ou de l'outillage offensif, hors périmètre.
- **Activer `fallbacks` par défaut, pas « envisager ».** La consigne interne est explicite : tout code Opus 5 ou Fable 5 doit embarquer le paramètre `fallbacks` d'emblée. Forme la plus simple : beta `server-side-fallback-2026-07-01` + `fallbacks: "default"`, qui route **par catégorie de refus** — les refus de catégorie `cyber` partent vers **Opus 4.8**, ce qui rattrape réellement la requête au lieu de renommer l'échec. Ne pas épingler un modèle de repli à la main : la forme `"default"` évite la migration quand le modèle épinglé est déprécié.
- ❌ **Affirmation retirée (27/07/2026)** : « les classifieurs sont renforcés sur Opus 5, les refus sont *plus* probables, et le System Card note que les benchmarks multi-agents ont été mesurés sans safeguards actifs ». Recherche sur sources primaires : l'annonce Opus 5 ne mentionne **ni** benchmarks sans safeguards, **ni** délégation multi-agents, **ni** lien entre classifieurs et contextes parallèles. Et la direction est inversée — les classifieurs interviennent 85 % *moins* souvent que sur Fable 5. Le System Card complet (PDF > 10 Mo) n'a pas pu être fetché : la partie « benchmarks sans safeguards » reste donc **non réfutée formellement**, mais elle n'est corroborée par aucune source accessible et la thèse qu'elle soutenait l'est encore moins. Ce que le System Card rapporte au contraire, via recherche : Opus 5 montre **les plus forts gains en robustesse aux prompt injections** sur coding, computer use et browser use.
- **Conséquence pour Sentinel** : la note antérieure poussait à une sur-ingénierie défensive (gestion de refus, fallbacks, prudence sur le fan-out) calibrée sur un risque qui n'existe pas à ce niveau. Garder la garde `stop_reason` (bon réflexe, coût nul) ; abandonner l'idée qu'Opus 5 serait hostile au scan de sécurité.
- ⚠️ **Le même claim non sourcé vit dans `lab-35-deep-research/skill/SKILL.md`** (§ Agent spawning discipline), où il justifie le cap à 12 agents par wave. Le cap reste défendable pour d'autres raisons — limite matérielle Claude Code, et Opus 5 délègue plus volontiers — mais sa justification « classifieurs renforcés » est à corriger là-bas aussi.
- **⚠️ Severity filters are followed literally.** An agent prompt saying "only report high-severity" measurably lowers recall. Ask agents to report everything and filter downstream — this directly affects Sentinel's `Finding[]` contracts.
- **Self-verification is native.** Remove inherited "double-check your findings before returning" instructions from agent prompts; keep only instructions that replay a *named external tool* (KB grep, MCP scanner).
- **Delegation increased** and subagent nesting depth went from 1 to 3 by default (v2.1.219). Cap agent spawning explicitly in Step 2 rather than relying on the model's restraint.
- **Context**: 1M by default and maximum, no surcharge on Max. The `[1m]` suffix is a no-op.
- **⚠️ Breaking change propre à Opus 5 — le thinking est ACTIF par défaut.** Omettre le paramètre `thinking` faisait tourner sans thinking sur Opus 4.8/4.7 ; sur Opus 5 cela lance l'adaptive. Et `max_tokens` plafonne **thinking + texte de réponse ensemble** : une route qui ne posait jamais `thinking` et dimensionnait `max_tokens` au plus juste peut désormais tronquer en plein milieu. Second breaking : `thinking: {type:"disabled"}` n'est accepté qu'à effort **`high` ou moins** — combiné à `xhigh`/`max`, c'est un **400**, validé requête par requête.
- Reste du surface API identique à 4.7/4.8 (pas de `temperature`/`top_p`/`top_k`, `budget_tokens` → adaptive). Cache minimum abaissé à **512 tokens** (contre 1024 sur Opus 4.8) — des prompts jugés trop courts pour être cachés le deviennent, sans changement de code.
- **Priority Tier ne couvre pas Opus 5** (ni Sonnet 5) — une requête Priority Tier nommant Opus 5 échoue à la validation. En revanche **web fetch EST disponible** : `web_fetch_20260209` liste explicitement Opus 5. *(Correction du 27/07 : ce fichier affirmait l'inverse — erreur factuelle rapatriée du runtime du 25/07, jamais sourcée.)*
- À `xhigh`/`max`, prévoir un `max_tokens` large — **au moins 64K** — pour laisser la place au thinking et aux appels d'outils.

### Opus 4.8 (released 2026-05-28) — superseded

Historical. Was the default until v2.1.219 (2026-07-24).

- **Defaulted to `high` effort** — the old advice was `/effort xhigh` for the hardest deep-dive audits. Superseded: see Opus 5 above.
- **Fast mode** on Opus 4.8 is now available at 2x the standard rate for 2.5x the speed (down from its previous premium) — useful for light/breadth scans.
- **Lean system prompt is now the default** for all models except Haiku, Sonnet, and Opus 4.7-and-earlier — this frees context budget for audit findings; keep agent prompts tight.
- **AskUserQuestion is reserved for genuine decisions** — Claude no longer asks when it already has enough context to proceed. Headless audits should drive behaviour from `.sentinel.json` rather than relying on interactive prompts.
- **4.7→4.8 migration guidance** was added to the built-in `/claude-api` skill — consult it when evolving Sentinel code that calls the Anthropic API directly.
- All the Opus 4.7 breaking API changes below (no `temperature`/`top_p`/`top_k`, `budget_tokens`→adaptive, new tokenizer) still apply on 4.8.

### Opus 4.7 (released 2026-04-16)

Opus 4.7 introduces breaking API changes. When evolving Sentinel skills or generating recommendations that touch model config, apply these rules:

- **`temperature`, `top_p`, `top_k` removed** — passing them returns HTTP 400. Rely on prompting for determinism instead.
- **`thinking.budget_tokens` removed** — use `thinking: {"type": "adaptive"}` plus `output_config: {"effort": "high" | "xhigh" | "max"}`. Adaptive outperforms bounded thinking.
- **Thinking content omitted by default** — set `display: "summarized"` if reasoning output is required (e.g., for audit traceability).
- **New `xhigh` effort level** — sits between `high` and `max`. Recommended default for Sentinel deep-dive audit agents (+13% coding, +14% agentic vs `high` on 4.6).
- **Task budgets (beta)** — advisory token cap across full agentic loop (min 20k); useful for capping long audit sessions.
- **New tokenizer: +35% tokens possible** — raise `max_tokens` headroom ~15-20% and re-tune MCP `maxResultSizeChars` (current 500K may need downsize).
- **Cyber safeguards** — 4.7 adds real-time cybersecurity refusals on high-risk topics. Sentinel agents that analyze malware/exploit samples should apply for the [Cyber Verification Program](https://claude.com/form/cyber-use-case).
- **Auto mode for Opus 4.7 Max** (v2.1.111) — `--enable-auto-mode` flag is no longer required; auto mode activates automatically when on Opus 4.7 with a Max subscription.
