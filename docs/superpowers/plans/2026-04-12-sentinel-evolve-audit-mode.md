# Sentinel Evolve Audit Mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `audit` mode to `/sentinel-evolve` that analyzes Claude Code usage across projects via session parsing, config inspection, and CLAUDE.md grading — producing a health score report with guided remediation.

**Architecture:** A Python script (`session-analyzer.py`) handles heavy JSONL parsing and outputs structured JSON. The SKILL.md orchestrates gap analysis, CLAUDE.md grading, report generation, and interactive remediation. Configuration lives in `evolve-targets.json`.

**Tech Stack:** Python 3 (session-analyzer.py), Markdown (SKILL.md, report template)

**Spec:** `docs/superpowers/specs/2026-04-12-sentinel-evolve-audit-mode-design.md`

---

### Task 1: session-analyzer.py — Core JSONL Parser

**Files:**
- Create: `scripts/session-analyzer.py`
- Test: `tests/test-session-analyzer.sh`

This is the heavy-lifting script. It parses all JSONL session files and outputs structured JSON to stdout.

- [ ] **Step 1: Create the script with argument parsing and project discovery**

```python
#!/usr/bin/env python3
"""Sentinel Evolve — Session Analyzer

Parses Claude Code session JSONL files and outputs structured usage metrics.
Privacy: reads only metadata (tool names, timestamps, agent params). Never reads
message content, bash commands, or file contents.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SESSIONS_DIR = Path.home() / ".claude" / "projects"

# Whitelisted Agent tool parameter keys
AGENT_PARAM_WHITELIST = {"subagent_type", "name", "model", "isolation", "run_in_background", "mode"}

# Skill tool parameter keys
SKILL_PARAM_KEYS = {"skill", "args"}

# Secret patterns to redact
SECRET_PATTERNS = ("key", "secret", "token", "password", "credential")


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze Claude Code session usage")
    parser.add_argument("--project", type=str, help="Analyze only this project path")
    parser.add_argument("--all", action="store_true", help="Analyze all projects")
    parser.add_argument("--global", dest="global_mode", action="store_true",
                        help="Global user profile (includes --all)")
    return parser.parse_args()


def discover_projects(sessions_dir: Path, project_filter: str = None) -> list[dict]:
    """Discover all project directories in ~/.claude/projects/."""
    projects = []
    if not sessions_dir.exists():
        return projects
    for entry in sorted(sessions_dir.iterdir()):
        if not entry.is_dir():
            continue
        dir_name = entry.name
        # Convert dir hash back to path: -Users-foo-bar → /Users/foo/bar
        resolved = "/" + dir_name.lstrip("-").replace("-", "/")
        if project_filter and resolved != project_filter:
            continue
        jsonl_files = sorted(entry.glob("*.jsonl"))
        if not jsonl_files:
            continue
        projects.append({
            "id": dir_name,
            "path": resolved,
            "dir": entry,
            "jsonl_files": jsonl_files,
        })
    return projects
```

- [ ] **Step 2: Add JSONL parsing with privacy filtering**

Add after the `discover_projects` function:

```python
def safe_value(val):
    """Redact values that look like secrets."""
    if isinstance(val, str):
        for pat in SECRET_PATTERNS:
            if pat in val.lower():
                return "[REDACTED]"
    return val


def parse_session(jsonl_path: Path) -> dict:
    """Parse a single JSONL session file. Returns session metrics."""
    tools = defaultdict(int)
    skills_used = defaultdict(int)
    agent_params = []
    msg_count = 0
    first_ts = None
    last_ts = None

    with open(jsonl_path, "r") as f:
        for line in f:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("type")
            timestamp = msg.get("timestamp")

            if timestamp:
                if first_ts is None or timestamp < first_ts:
                    first_ts = timestamp
                if last_ts is None or timestamp > last_ts:
                    last_ts = timestamp

            if msg_type in ("user", "assistant"):
                msg_count += 1

            if msg_type != "assistant":
                continue

            # Extract tool uses from assistant messages
            content = msg.get("message", {}).get("content", [])
            if not isinstance(content, list):
                continue

            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_use":
                    continue

                tool_name = block.get("name", "unknown")
                tools[tool_name] += 1
                tool_input = block.get("input", {})

                # Extract Skill invocations
                if tool_name == "Skill" and isinstance(tool_input, dict):
                    skill_name = tool_input.get("skill", "unknown")
                    skills_used[skill_name] += 1

                # Extract Agent parameters (whitelisted keys only)
                if tool_name == "Agent" and isinstance(tool_input, dict):
                    agent_info = {}
                    for k in AGENT_PARAM_WHITELIST:
                        if k in tool_input:
                            agent_info[k] = safe_value(tool_input[k])
                    agent_params.append(agent_info)

    duration_min = 0
    if first_ts and last_ts:
        try:
            t1 = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            duration_min = max(0, (t2 - t1).total_seconds() / 60)
        except (ValueError, TypeError):
            pass

    return {
        "messages": msg_count,
        "tools": dict(tools),
        "skills_used": dict(skills_used),
        "agent_params": agent_params,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_min": round(duration_min, 1),
    }
```

- [ ] **Step 3: Add feature detection logic**

Add after `parse_session`:

```python
# Map of feature_key → detection function(tool_name, agent_params_list, tools_dict)
FEATURE_DETECTORS = {
    "git_worktrees": lambda t, ap, td: any(p.get("isolation") == "worktree" for p in ap),
    "agent_teams": lambda t, ap, td: "TeamCreate" in td,
    "auto_memory": lambda t, ap, td: any(
        k.startswith("mcp__") or "memory" in str(td.get("Write", ""))
        for k in td
    ),
    "named_subagents": lambda t, ap, td: any("name" in p for p in ap),
    "background_agents": lambda t, ap, td: any(p.get("run_in_background") for p in ap),
    "model_alias_override": lambda t, ap, td: any("model" in p for p in ap),
    "skills_system": lambda t, ap, td: "Skill" in td,
    "task_create_update": lambda t, ap, td: "TaskCreate" in td or "TaskUpdate" in td,
    "web_fetch_search": lambda t, ap, td: "WebFetch" in td or "WebSearch" in td,
    "browser_automation": lambda t, ap, td: any(k.startswith("mcp__claude-in-chrome__") for k in td),
    "mcp_servers": lambda t, ap, td: any(k.startswith("mcp__") for k in td),
    "plan_subagent": lambda t, ap, td: any(p.get("subagent_type") == "Plan" for p in ap),
    "explore_subagent": lambda t, ap, td: any(p.get("subagent_type") == "Explore" for p in ap),
    "monitor_tool": lambda t, ap, td: "Monitor" in td,
}


def detect_features(tools: dict, agent_params: list) -> list[str]:
    """Detect which Claude Code features are being used."""
    detected = []
    for feature_key, detector in FEATURE_DETECTORS.items():
        try:
            if detector(None, agent_params, tools):
                detected.append(feature_key)
        except Exception:
            pass
    return detected
```

- [ ] **Step 4: Add static config detection**

Add after `detect_features`:

```python
def detect_static_config(project_path: str, project_dir: Path) -> dict:
    """Check for static config files in project and ~/.claude/."""
    p = Path(project_path)
    config = {
        "has_claude_md": (p / "CLAUDE.md").exists(),
        "has_settings": (p / ".claude" / "settings.json").exists(),
        "has_rules": any((p / ".claude" / "rules").glob("*.md")) if (p / ".claude" / "rules").exists() else False,
        "has_memory": (project_dir / "memory").exists(),
        "has_sentinel_config": (p / ".sentinel.json").exists(),
    }
    return config


def detect_global_config() -> dict:
    """Inspect ~/.claude/settings.json for global features."""
    settings_path = Path.home() / ".claude" / "settings.json"
    result = {
        "hooks_configured": [],
        "env_vars": [],
        "mcp_servers": [],
        "permissions_configured": False,
    }
    if not settings_path.exists():
        return result
    try:
        with open(settings_path) as f:
            settings = json.load(f)
        if "hooks" in settings:
            result["hooks_configured"] = list(settings["hooks"].keys())
        if "env" in settings:
            result["env_vars"] = list(settings["env"].keys())
        if "mcpServers" in settings:
            result["mcp_servers"] = list(settings["mcpServers"].keys())
        if "permissions" in settings:
            result["permissions_configured"] = True
    except (json.JSONDecodeError, KeyError):
        pass
    return result
```

- [ ] **Step 5: Add temporal analysis and aggregation**

Add after `detect_global_config`:

```python
def compute_temporal(all_sessions: list[dict], analysis_date: str) -> dict:
    """Compute weekly session counts and feature adoption timeline."""
    weekly = defaultdict(lambda: {"sessions": 0, "tool_calls": 0})
    feature_timeline = defaultdict(lambda: {"first": None, "last": None, "count": 0})

    for sess in all_sessions:
        if not sess.get("first_ts"):
            continue
        try:
            dt = datetime.fromisoformat(sess["first_ts"].replace("Z", "+00:00"))
            week_key = dt.strftime("%G-W%V")
            weekly[week_key]["sessions"] += 1
            weekly[week_key]["tool_calls"] += sum(sess["tools"].values())
        except (ValueError, TypeError):
            pass

        # Track feature adoption dates
        features = detect_features(sess["tools"], sess["agent_params"])
        date_str = sess["first_ts"][:10] if sess["first_ts"] else None
        if date_str:
            for f in features:
                ft = feature_timeline[f]
                ft["count"] += 1
                if ft["first"] is None or date_str < ft["first"]:
                    ft["first"] = date_str
                if ft["last"] is None or date_str > ft["last"]:
                    ft["last"] = date_str

    # Determine adoption status
    adoption = []
    for feature, ft in feature_timeline.items():
        if ft["count"] <= 1:
            status = "one-time"
        elif ft["last"] and ft["last"] >= (
            datetime.now(timezone.utc).strftime("%Y-%m-%d")[:8]  # last 30 days approx
        ):
            status = "active"
        else:
            status = "abandoned"
        adoption.append({
            "feature": feature,
            "first_used": ft["first"],
            "last_used": ft["last"],
            "use_count": ft["count"],
            "status": status,
        })

    weekly_sorted = [
        {"week": k, "sessions": v["sessions"], "tool_calls": v["tool_calls"]}
        for k, v in sorted(weekly.items())
    ]

    return {"weekly_sessions": weekly_sorted, "feature_adoption": adoption}
```

- [ ] **Step 6: Add main function that assembles everything**

Add at end:

```python
def main():
    args = parse_args()
    now = datetime.now(timezone.utc)

    # Determine scope
    if args.global_mode or getattr(args, "all"):
        project_filter = None
    elif args.project:
        project_filter = args.project
    else:
        project_filter = os.getcwd()

    projects = discover_projects(SESSIONS_DIR, project_filter if not (args.global_mode or getattr(args, "all")) else None)

    # Parse all sessions
    all_tools = defaultdict(int)
    all_skills = defaultdict(int)
    all_agent_params = []
    all_features = set()
    all_sessions = []
    project_results = []
    total_messages = 0
    total_duration = 0

    for proj in projects:
        proj_tools = defaultdict(int)
        proj_skills = set()
        proj_sessions = 0
        proj_last_active = None

        for jsonl_file in proj["jsonl_files"]:
            sess = parse_session(jsonl_file)
            all_sessions.append(sess)
            proj_sessions += 1
            total_messages += sess["messages"]
            total_duration += sess["duration_min"]

            for t, c in sess["tools"].items():
                all_tools[t] += c
                proj_tools[t] += c
            for s, c in sess["skills_used"].items():
                all_skills[s] += c
                proj_skills.add(s)
            all_agent_params.extend(sess["agent_params"])

            if sess["last_ts"]:
                if proj_last_active is None or sess["last_ts"] > proj_last_active:
                    proj_last_active = sess["last_ts"]

        features = detect_features(dict(proj_tools), [
            p for s in all_sessions[-proj_sessions:] for p in s["agent_params"]
        ])
        all_features.update(features)

        static = detect_static_config(proj["path"], proj["dir"])

        project_results.append({
            "id": proj["id"],
            "path": proj["path"],
            "sessions_count": proj_sessions,
            "last_active": proj_last_active[:10] if proj_last_active else None,
            "tools": dict(proj_tools),
            "skills_used": sorted(proj_skills),
            **static,
        })

    # Compute percentages for tools
    total_tool_calls = sum(all_tools.values()) or 1
    tools_pct = {
        name: {"count": count, "pct": round(count / total_tool_calls * 100, 1)}
        for name, count in sorted(all_tools.items(), key=lambda x: -x[1])
    }

    # Agent patterns
    agent_pats = {
        "total_dispatched": len(all_agent_params),
        "with_background": sum(1 for p in all_agent_params if p.get("run_in_background")),
        "with_worktree": sum(1 for p in all_agent_params if p.get("isolation") == "worktree"),
        "with_named": sum(1 for p in all_agent_params if "name" in p),
        "with_model_override": sum(1 for p in all_agent_params if "model" in p),
        "subagent_types": dict(defaultdict(int, {
            p.get("subagent_type", "general-purpose"): 0 for p in all_agent_params
        })),
    }
    for p in all_agent_params:
        st = p.get("subagent_type", "general-purpose")
        agent_pats["subagent_types"][st] = agent_pats["subagent_types"].get(st, 0) + 1

    # Period
    dates = [s["first_ts"][:10] for s in all_sessions if s.get("first_ts")]
    first_date = min(dates) if dates else now.strftime("%Y-%m-%d")
    last_date = max(dates) if dates else now.strftime("%Y-%m-%d")
    try:
        total_days = (datetime.fromisoformat(last_date) - datetime.fromisoformat(first_date)).days + 1
    except ValueError:
        total_days = 1

    # Active projects in last 30 days
    thirty_days_ago = (now.replace(tzinfo=None) - __import__("datetime").timedelta(days=30)).strftime("%Y-%m-%d")
    active_30d = sum(1 for p in project_results if p.get("last_active") and p["last_active"] >= thirty_days_ago)

    # Temporal
    temporal = compute_temporal(all_sessions, now.strftime("%Y-%m-%d"))

    # Global config
    global_config = detect_global_config()

    # Build output
    output = {
        "generated_at": now.isoformat(),
        "period": {
            "first_session": first_date,
            "last_session": last_date,
            "total_days": total_days,
        },
        "global": {
            "total_sessions": len(all_sessions),
            "total_messages": total_messages,
            "total_projects": len(project_results),
            "active_projects_30d": active_30d,
            "avg_session_duration_min": round(total_duration / max(len(all_sessions), 1), 1),
            "avg_messages_per_session": round(total_messages / max(len(all_sessions), 1), 1),
        },
        "tools": tools_pct,
        "skills_used": dict(sorted(all_skills.items(), key=lambda x: -x[1])),
        "agent_patterns": agent_pats,
        "features_detected": sorted(all_features),
        "global_config": global_config,
        "projects": sorted(project_results, key=lambda p: p["sessions_count"], reverse=True),
        "temporal": temporal,
    }

    json.dump(output, sys.stdout, indent=2, default=str)


if __name__ == "__main__":
    main()
```

- [ ] **Step 7: Run the script on the current project to verify output**

Run: `python3 scripts/session-analyzer.py --project /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel 2>/dev/null | python3 -m json.tool | head -60`

Expected: Valid JSON with `period`, `global`, `tools`, `projects` keys populated.

- [ ] **Step 8: Run with --all to verify cross-project**

Run: `python3 scripts/session-analyzer.py --all 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Projects: {d[\"global\"][\"total_projects\"]}, Sessions: {d[\"global\"][\"total_sessions\"]}, Tools: {len(d[\"tools\"])}')" `

Expected: `Projects: 47` (approximately), Sessions > 100, Tools > 5.

- [ ] **Step 9: Create test script**

Create `tests/test-session-analyzer.sh`:

```bash
#!/bin/bash
set -e
PASS=0; FAIL=0; TOTAL=0

check() {
  TOTAL=$((TOTAL + 1))
  if eval "$2" > /dev/null 2>&1; then
    echo "[PASS] $1"; PASS=$((PASS + 1))
  else
    echo "[FAIL] $1"; FAIL=$((FAIL + 1))
  fi
}

echo "=== Session Analyzer Tests ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

# Script exists and runs
check "script exists" "test -f $SCRIPT_DIR/scripts/session-analyzer.py"
check "script runs without error" "python3 $SCRIPT_DIR/scripts/session-analyzer.py --project $SCRIPT_DIR 2>/dev/null"

# Single project output
OUTPUT=$(python3 $SCRIPT_DIR/scripts/session-analyzer.py --project "$SCRIPT_DIR" 2>/dev/null)
check "outputs valid JSON" "echo '$OUTPUT' | python3 -m json.tool > /dev/null"
check "has period key" "echo '$OUTPUT' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"period\" in d'"
check "has global key" "echo '$OUTPUT' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"global\" in d'"
check "has tools key" "echo '$OUTPUT' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"tools\" in d'"
check "has projects key" "echo '$OUTPUT' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"projects\" in d'"
check "has temporal key" "echo '$OUTPUT' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"temporal\" in d'"
check "has features_detected" "echo '$OUTPUT' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"features_detected\" in d'"

# Cross-project
ALL_OUTPUT=$(python3 $SCRIPT_DIR/scripts/session-analyzer.py --all 2>/dev/null)
check "all mode outputs valid JSON" "echo '$ALL_OUTPUT' | python3 -m json.tool > /dev/null"
check "all mode finds multiple projects" "echo '$ALL_OUTPUT' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"global\"][\"total_projects\"] > 1'"

echo ""
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
exit $FAIL
```

- [ ] **Step 10: Run tests**

Run: `bash tests/test-session-analyzer.sh`
Expected: All checks PASS.

- [ ] **Step 11: Commit**

```bash
git add scripts/session-analyzer.py tests/test-session-analyzer.sh
git commit -m "feat(evolve): add session-analyzer.py for audit mode"
```

---

### Task 2: Report Template

**Files:**
- Create: `reports/templates/audit-report.md`

- [ ] **Step 1: Create the template**

```markdown
# Claude Code Health Audit

**Date**: {date}
**Scope**: {scope}
**Period**: {first_session} — {last_session} ({total_days} days)
**Sessions analyzed**: {total_sessions}

---

## Health Score: {health_score}/100

| Dimension            | Score  | Grade |
|----------------------|--------|-------|
| Config & Context     | {d_config}% | {g_config} |
| Tool Usage           | {d_tools}% | {g_tools} |
| Skills & Plugins     | {d_skills}% | {g_skills} |
| Hooks & Automation   | {d_hooks}% | {g_hooks} |
| Memory Hygiene       | {d_memory}% | {g_memory} |
| Agent Patterns       | {d_agents}% | {g_agents} |
| Feature Exploitation | {d_features}% | {g_features} |

---

## Top Recommendations

{recommendations}

---

## Project Ranking

{project_ranking}

---

## Feature Gap Analysis

{gap_analysis}

---

## CLAUDE.md Grades

{claude_md_grades}

---

## Temporal Analysis

{temporal_analysis}

---

## User Profile

{user_profile}

---

*Generated by `/sentinel-evolve audit` — Sentinel Evolution Intelligence*
```

- [ ] **Step 2: Commit**

```bash
git add reports/templates/audit-report.md
git commit -m "feat(evolve): add audit report template"
```

---

### Task 3: Update evolve-targets.json

**Files:**
- Modify: `config/evolve-targets.json`

- [ ] **Step 1: Add audit_config section**

Read `config/evolve-targets.json`, then add the `audit_config` block after `infrastructure`:

```json
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
    "config_context", "tool_usage", "skills_plugins",
    "hooks_automation", "memory_hygiene", "agent_patterns",
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
```

- [ ] **Step 2: Commit**

```bash
git add config/evolve-targets.json
git commit -m "feat(evolve): add audit_config to evolve-targets.json"
```

---

### Task 4: Update SKILL.md — Mode Detection + Audit Section

**Files:**
- Modify: `skills/sentinel-evolve/SKILL.md` (insert after `## Mode: auto` section, before `## Mode: scan`)

This is the core SKILL.md logic. Insert the full `## Mode: audit` section (~200 lines).

- [ ] **Step 1: Update available modes list (line 32)**

Change `Available modes: \`scan\`, \`analyze\`, \`recommend\`, \`apply\`, \`maintain\`, \`auto\`` to add `, \`audit\``.

After line 30 (`4. Default: **recommend**`), add: `5. If user explicitly requested \`audit\`: use **audit** mode (does NOT auto-trigger from evolve workflow)`

- [ ] **Step 2: Add the Mode: audit section**

Insert after the end of `## Mode: auto` (after the `### Output (headless)` JSON block and closing `---`), before `## Mode: scan`:

```markdown
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
- `--global` → scope = `global` (all projects + user profile)
- `--all` → scope = `cross-project` (all projects, no user profile section)
- No flag → scope = `project` (current working directory only)

### Step 2: Run Session Analyzer

```bash
Bash: python3 /Users/manuelturpin/.sentinel/scripts/session-analyzer.py [--project "$(pwd)" | --all | --global]
```

Capture the JSON output. If the script fails or returns invalid JSON, warn the user and fall back to static-only analysis (skip session-based metrics, still grade CLAUDE.md and check config).

### Step 3: Feature Gap Analysis

1. Read `/Users/manuelturpin/.sentinel/knowledge-base/anthropic-intel/feature-inventory.json`
2. Read the `audit_config` from `/Users/manuelturpin/.sentinel/config/evolve-targets.json`
3. For each feature in the inventory:
   - If `feature.key` is in `features_detected` from analyzer JSON → **USED**
   - If feature is partially present (e.g., Agent tool used but never with `isolation: worktree`) → **PARTIAL**
   - If feature doesn't apply to the user's detected stack → **NOT_APPLICABLE**
   - Otherwise → **NOT_USED**
4. Compute exploitation score: `USED / (USED + PARTIAL + NOT_USED) * 100`

**PARTIAL detection rules:**
- `git_worktrees`: Agent used but `with_worktree` = 0 → PARTIAL
- `named_subagents`: Agent used but `with_named` = 0 → PARTIAL
- `background_agents`: Agent used but `with_background` = 0 → PARTIAL
- `model_alias_override`: Agent used but `with_model_override` = 0 → PARTIAL
- `explore_subagent`/`plan_subagent`: Agent used but only `general-purpose` type → PARTIAL

### Step 4: CLAUDE.md Grading

For each project in scope, Read its CLAUDE.md and grade on 100 points:

| Criterion | Full (pts) | Partial (pts) | Absent (pts) | Detection |
|-----------|-----------|---------------|-------------|-----------|
| Existence | 10 | — | 0 | File exists |
| Role/Description | 10 | 5 | 0 | Grep for `## Role`, `## Description`, `## Projet` |
| Structure | 10 | 5 | 0 | Directory tree in code block |
| Conventions | 15 | 8 | 0 | Grep for `## Convention`, naming/language/stack rules |
| Commands | 15 | 8 | 0 | 3+ backtick command blocks = full, 1-2 = partial |
| Relations | 10 | 5 | 0 | Links to other projects or dependencies |
| Current state | 10 | 5 | 0 | Grep for `## Etat`, `## Statut`, `Actif`/`Dormant` |
| Secrets/Security | 10 | 5 | 0 | Mentions `.gitignore` + env vars |
| Adequate size | 10 | 5 | 0 | 30-300 lines = full, 10-29 or 301-500 = partial, else 0 |

Grade thresholds: A >= 85, B >= 70, C >= 55, D >= 40, F < 40.

For projects without a CLAUDE.md, assign grade F (score 0) and flag for remediation.

### Step 5: Compute Dimension Scores

Score each dimension 0-100 using the analyzer JSON + static config:

**Config & Context (15%):**
- CLAUDE.md grade (normalized to 0-100)
- Has project settings.json → +20
- Has .gitignore → +10
- Final = min(100, sum)

**Tool Usage (15%):**
- Tool diversity: uses >= 8 different tools → 100, 5-7 → 70, 3-4 → 40, <3 → 20
- Grep usage > 0 → +15 (efficient searching)
- Glob usage > 0 → +15 (efficient file finding)
- Agent usage > 0 → +20 (leverages subagents)

**Skills & Plugins (15%):**
- Skills used / skills installed ratio × 100
- If skills_used > 5 → +20
- If plugin MCP tools used → +20

**Hooks & Automation (15%):**
- Hook events count × 15 (max 100)
- CronCreate in sessions → +20
- FileChanged/ConfigChange hooks → +20

**Memory Hygiene (10%):**
- Has memory dir → +30
- Memory files exist and < 30 days old → +40
- Reasonable count (2-20 files) → +30

**Agent Patterns (15%):**
- Uses agents → +20
- Uses specialized types (Explore/Plan) → +20
- Uses worktree isolation → +20
- Uses named agents → +20
- Uses model override → +20

**Feature Exploitation (15%):**
- Exploitation score from Step 3

**Health Score** = weighted sum of all dimensions (rounded to integer).

### Step 6: Generate Report

Use the template at `/Users/manuelturpin/.sentinel/reports/templates/audit-report.md`.

Fill in all sections:
1. **Health Score** — the weighted score + dimension table
2. **Top Recommendations** — generate P1/P2/P3 recommendations based on lowest-scoring dimensions and NOT_USED features. Each recommendation includes estimated impact in points.
3. **Project Ranking** — table sorted by score (cross-project/global only)
4. **Feature Gap Analysis** — table of NOT_USED and PARTIAL features with descriptions
5. **CLAUDE.md Grades** — per-project grades with specific suggestions
6. **Temporal Analysis** — feature adoption/abandonment trends
7. **User Profile** — strengths, weaknesses, usage style characterization (global only)

Save to `/Users/manuelturpin/.sentinel/reports/archive/audit-{scope}-{date}.md`

### Step 7: Guided Remediation

Present numbered actions derived from the lowest-scoring dimensions:

```
Based on the audit, here are actions I can perform now:

 [1] {action description} → +{points} pts
 [2] {action description} → +{points} pts
 ...

Which ones? (e.g., 1,3 or "all")
```

Remediation types:
- **Create/improve CLAUDE.md** — generate based on grading criteria, reading the project structure
- **Add hooks** — write hook config to `.claude/settings.json` or `~/.claude/settings.json`
- **Create rules** — create `.claude/rules/*.md` files for the project
- **Optimize settings** — adjust env vars, permissions, MCP config
- **Propagate patterns** — copy hooks/rules/settings from high-scoring projects

Each action requires user confirmation before any file modification.

### Step 8: Save Results

1. Save report to archive
2. Append score to metadata.json `audit_history`:
```json
{
  "date": "2026-04-12",
  "scope": "global",
  "health_score": 72,
  "dimensions": { ... },
  "projects_audited": 47
}
```
```

- [ ] **Step 3: Verify SKILL.md is valid (no syntax issues)**

Run: `head -5 skills/sentinel-evolve/SKILL.md && echo "---" && wc -l skills/sentinel-evolve/SKILL.md`
Expected: Frontmatter intact, ~560 lines total.

- [ ] **Step 4: Commit**

```bash
git add skills/sentinel-evolve/SKILL.md
git commit -m "feat(evolve): add Mode: audit to SKILL.md — detection + full section"
```

---

### Task 5: Deploy and Integration Test

**Files:**
- No new files — uses existing `scripts/deploy.sh`

- [ ] **Step 1: Run deploy.sh**

Run: `bash scripts/deploy.sh`
Expected: All components deployed successfully. Session-analyzer.py copied to `~/.sentinel/scripts/`.

- [ ] **Step 2: Verify deployment**

Run: `test -f ~/.sentinel/scripts/session-analyzer.py && echo "OK" || echo "MISSING"`
Expected: `OK`

Run: `test -f ~/.sentinel/reports/templates/audit-report.md && echo "OK" || echo "MISSING"`
Expected: `OK`

- [ ] **Step 3: Run session-analyzer.py from deployed location**

Run: `python3 ~/.sentinel/scripts/session-analyzer.py --project "$(pwd)" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'OK: {d[\"global\"][\"total_sessions\"]} sessions, {len(d[\"tools\"])} tools')"`
Expected: `OK: N sessions, N tools`

- [ ] **Step 4: Run session-analyzer.py with --global**

Run: `python3 ~/.sentinel/scripts/session-analyzer.py --global 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Global: {d[\"global\"][\"total_projects\"]} projects, {d[\"global\"][\"total_sessions\"]} sessions, features={len(d[\"features_detected\"])}')" `
Expected: `Global: ~47 projects, ~N sessions, features=N`

- [ ] **Step 5: Run existing tests to verify no regressions**

Run: `bash scripts/test-sentinel.sh 2>&1 | tail -5`
Expected: All checks pass.

- [ ] **Step 6: Run audit mode test**

Run: `bash tests/test-session-analyzer.sh`
Expected: All checks pass.

- [ ] **Step 7: Final commit with all changes**

```bash
git add -A
git commit -m "feat(evolve): complete audit mode — session analyzer + SKILL.md + config + template"
git push
```

---

### Task 6: Live Validation — Run First Audit

**Files:** None (execution only)

- [ ] **Step 1: Run audit on current project**

Invoke: `/sentinel-evolve audit`

Expected: Report generated with health score, dimension breakdown, CLAUDE.md grade, feature gap analysis, and remediation suggestions for lab-30-sentinel.

- [ ] **Step 2: Run cross-project audit**

Invoke: `/sentinel-evolve audit --all`

Expected: All projects discovered, ranked by score, with CLAUDE.md grades for each.

- [ ] **Step 3: Run global audit**

Invoke: `/sentinel-evolve audit --global`

Expected: Full user profile with temporal analysis, feature adoption trends, and overall health score.

- [ ] **Step 4: Verify report was saved**

Run: `ls -la ~/.sentinel/reports/archive/audit-*`
Expected: Report files exist with today's date.
