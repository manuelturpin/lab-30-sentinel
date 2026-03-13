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

Pending — Session 9.
