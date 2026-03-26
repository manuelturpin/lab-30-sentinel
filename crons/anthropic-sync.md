---
name: anthropic-sync
description: Synchronise bi-hebdomadairement l'intelligence ecosysteme Anthropic (Claude Code, Skills, MCP, SDKs)
schedule: "0 7 * * 1,4"
---

# Anthropic Sync — Bi-Weekly Ecosystem Intelligence

## Purpose

Keep the Sentinel Evolve intelligence base up to date by fetching changes from:
1. **Claude Code Releases** — New features, deprecations, breaking changes
2. **Official Skills Repo** — New skill patterns, frontmatter conventions
3. **SDK Releases** — Python, TypeScript, Go, Java, Ruby SDK changes
4. **MCP SDK Releases** — Protocol changes, new transports
5. **Cookbooks/Courses** — New best practices and patterns (weekly only)

## Process

1. Fetch new releases from GitHub API for all configured sources
2. Parse release notes, extract features/deprecations/breaking changes
3. Update JSON caches in `knowledge-base/anthropic-intel/`
4. Generate markdown source for RAG indexing
5. Re-index the evolve KB in ChromaDB
6. Update sync timestamp in sync-config.json

## Implementation

**Script:** `scripts/anthropic-sync.py`

```bash
# Manual run
python3 scripts/anthropic-sync.py

# Dry run (preview only)
python3 scripts/anthropic-sync.py --dry-run

# Sync only Claude Code releases
python3 scripts/anthropic-sync.py --tier 1

# Custom lookback window
python3 scripts/anthropic-sync.py --days 30
```

## Automated Installation

The sync runs as part of the unified cron pipeline (Monday + Thursday at 7 AM):

```bash
# Install via crontab
crontab -e
0 6 * * * cd /path/to/lab-30-sentinel && bash scripts/sentinel-cron.sh >> logs/sentinel-cron.log 2>&1
```

## Environment Variables

- `GITHUB_TOKEN` — Recommended. Increases GitHub API rate limit from 60 to 5000 req/h.
