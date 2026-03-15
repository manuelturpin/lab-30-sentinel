---
name: project-rescan
description: Re-scanne hebdomadairement les projets surveilles pour detecter de nouvelles vulnerabilites
schedule: "0 8 * * 1"
---

# Project Rescan — Weekly Security Re-scan

## Purpose

Automatically re-scan monitored projects to detect:
- New vulnerabilities in existing dependencies (from updated CVE feeds)
- Configuration drift introducing security issues
- New code introducing vulnerabilities since last scan

## Process

1. Read list of monitored projects from config
2. For each project, run a standard `/security` scan
3. Compare results with previous scan (diff findings)
4. Alert on new CRITICAL/HIGH findings
5. Archive results in `reports/archive/`

## Implementation

**Script:** `scripts/project-rescan.py`

```bash
# Rescan all monitored projects
python3 scripts/project-rescan.py

# Rescan a specific project
python3 scripts/project-rescan.py --project vulnerable-app

# Dry run
python3 scripts/project-rescan.py --dry-run
```

## Configuration

Projects to monitor are configured in `config/monitored-projects.json`.

## Automated Installation

Runs weekly (Monday, after KB update) as part of the unified cron pipeline:

```bash
crontab -e
0 6 * * * cd /path/to/lab-30-sentinel && bash scripts/sentinel-cron.sh >> logs/sentinel-cron.log 2>&1
```

## Dependencies

- MCP server must be built: `cd mcp-servers/sentinel-scanner && npm run build`
- KB should be up to date (run after `kb-update.py`)
