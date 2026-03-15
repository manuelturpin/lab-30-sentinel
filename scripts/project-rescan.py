#!/usr/bin/env python3
"""
Sentinel Project Rescan — Re-scans monitored projects and generates delta reports.

Usage:
    python3 scripts/project-rescan.py                     # Rescan all monitored projects
    python3 scripts/project-rescan.py --project my-app    # Rescan a specific project
    python3 scripts/project-rescan.py --dry-run            # Preview without scanning
"""

import argparse
import glob
import json
import os
import ssl
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

# SSL context for HTTPS requests (macOS certificate compatibility)
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX.load_verify_locations(certifi.where())
except ImportError:
    print("WARNING: certifi not installed — SSL verification disabled for webhooks.",
          file=sys.stderr)
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "monitored-projects.json")
MCP_SERVER_DIR = os.path.join(PROJECT_ROOT, "mcp-servers", "sentinel-scanner")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def resolve_project_path(project_path):
    """Resolve relative paths against PROJECT_ROOT."""
    if os.path.isabs(project_path):
        return project_path
    return os.path.normpath(os.path.join(PROJECT_ROOT, project_path))


def call_mcp_tool(tool_name, params):
    """Invoke the MCP server via stdio JSON-RPC."""
    built_index = os.path.join(MCP_SERVER_DIR, "dist", "index.js")

    if not os.path.exists(built_index):
        print(f"  Error: MCP server not built. Run 'npm run build' in {MCP_SERVER_DIR}")
        return None

    # JSON-RPC 2.0 request
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": params,
        },
    }

    # MCP requires initialization handshake
    init_request = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "sentinel-rescan", "version": "1.0"},
        },
    }

    initialized_notification = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }

    stdin_data = (
        json.dumps(init_request) + "\n"
        + json.dumps(initialized_notification) + "\n"
        + json.dumps(request) + "\n"
    )

    try:
        result = subprocess.run(
            ["node", built_index],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=PROJECT_ROOT,
        )

        if result.returncode != 0 and not result.stdout:
            print(f"  MCP server error: {result.stderr[:500]}", file=sys.stderr)
            return None

        # Parse JSON-RPC responses (one per line)
        responses = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    responses.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        # Find the response to our tool call (id=1)
        for resp in responses:
            if resp.get("id") == 1:
                if "result" in resp:
                    content = resp["result"].get("content", [])
                    if content and content[0].get("type") == "text":
                        return json.loads(content[0]["text"])
                elif "error" in resp:
                    print(f"  MCP error: {resp['error']}", file=sys.stderr)
                    return None

        return None

    except subprocess.TimeoutExpired:
        print("  MCP server timed out (300s)", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  MCP invocation failed: {e}", file=sys.stderr)
        return None


def find_latest_report(archive_path, project_name):
    """Find the most recent SARIF report for a project."""
    pattern = os.path.join(archive_path, f"{project_name}_*.sarif.json")
    reports = sorted(glob.glob(pattern), reverse=True)
    if reports:
        return reports[0]
    return None


def extract_finding_key(result):
    """Generate a unique key for a SARIF result for delta comparison."""
    rule_id = result.get("ruleId", "")
    locations = result.get("locations", [{}])
    loc = locations[0] if locations else {}
    phys = loc.get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri", "")
    line = phys.get("region", {}).get("startLine", 0)
    return f"{rule_id}|{uri}|{line}"


def compute_delta(old_sarif, new_sarif):
    """Compare two SARIF reports and identify new/resolved findings."""
    old_results = []
    new_results = []

    for run in old_sarif.get("runs", []):
        old_results.extend(run.get("results", []))
    for run in new_sarif.get("runs", []):
        new_results.extend(run.get("results", []))

    old_keys = {extract_finding_key(r): r for r in old_results}
    new_keys = {extract_finding_key(r): r for r in new_results}

    new_findings = [new_keys[k] for k in new_keys if k not in old_keys]
    resolved_findings = [old_keys[k] for k in old_keys if k not in new_keys]
    unchanged = [k for k in new_keys if k in old_keys]

    return {
        "new": new_findings,
        "resolved": resolved_findings,
        "unchanged_count": len(unchanged),
        "total_old": len(old_results),
        "total_new": len(new_results),
    }


def severity_of(result):
    """Extract severity from a SARIF result."""
    props = result.get("properties", {})
    return props.get("severity", result.get("level", "unknown")).upper()


def generate_delta_report(project_name, delta, scan_date):
    """Generate a Markdown delta report."""
    lines = [
        f"# Sentinel Delta Report — {project_name}",
        f"",
        f"**Date:** {scan_date}",
        f"**Previous findings:** {delta['total_old']}",
        f"**Current findings:** {delta['total_new']}",
        f"**Unchanged:** {delta['unchanged_count']}",
        f"",
    ]

    # New findings
    if delta["new"]:
        lines.append(f"## New Findings ({len(delta['new'])})")
        lines.append("")
        for r in delta["new"]:
            rule_id = r.get("ruleId", "?")
            severity = severity_of(r)
            msg = r.get("message", {}).get("text", "").split("\n")[0]
            locs = r.get("locations", [{}])
            loc = locs[0] if locs else {}
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "?")
            line = loc.get("physicalLocation", {}).get("region", {}).get("startLine", "?")
            lines.append(f"- **[{severity}]** `{rule_id}` in `{uri}:{line}` — {msg[:120]}")
        lines.append("")

    # Resolved findings
    if delta["resolved"]:
        lines.append(f"## Resolved Findings ({len(delta['resolved'])})")
        lines.append("")
        for r in delta["resolved"]:
            rule_id = r.get("ruleId", "?")
            severity = severity_of(r)
            locs = r.get("locations", [{}])
            loc = locs[0] if locs else {}
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "?")
            lines.append(f"- ~~[{severity}] `{rule_id}` in `{uri}`~~ (resolved)")
        lines.append("")

    if not delta["new"] and not delta["resolved"]:
        lines.append("## No Changes")
        lines.append("")
        lines.append("No new or resolved findings since last scan.")
        lines.append("")

    # Alert section for critical/high new findings
    critical_new = [r for r in delta["new"] if severity_of(r) in ("CRITICAL", "HIGH")]
    if critical_new:
        lines.append(f"## ⚠ ALERT: {len(critical_new)} new CRITICAL/HIGH findings")
        lines.append("")
        for r in critical_new:
            lines.append(f"- `{r.get('ruleId', '?')}`: {r.get('message', {}).get('text', '').split(chr(10))[0][:150]}")
        lines.append("")

    return "\n".join(lines)


def notify_webhook(webhook_url, project_name, delta):
    """Send notification to webhook if configured."""
    if not webhook_url:
        return

    critical_new = [r for r in delta["new"] if severity_of(r) in ("CRITICAL", "HIGH")]
    if not critical_new:
        return

    payload = {
        "text": (
            f"🚨 Sentinel Alert: {len(critical_new)} new CRITICAL/HIGH findings "
            f"in {project_name} ({delta['total_new']} total)"
        ),
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10, context=_SSL_CTX)
        print(f"  Notification sent to webhook")
    except Exception as e:
        print(f"  Webhook notification failed: {e}", file=sys.stderr)


def rescan_project(project, archive_path, notifications, dry_run=False):
    """Rescan a single project and generate delta report."""
    name = project["name"]
    path = resolve_project_path(project["path"])
    depth = project.get("depth", "standard")

    print(f"\n{'=' * 50}")
    print(f"Project: {name}")
    print(f"Path: {path}")
    print(f"Depth: {depth}")
    print(f"{'=' * 50}")

    if not os.path.isdir(path):
        print(f"  Error: project path does not exist: {path}")
        return False

    if dry_run:
        print(f"  [dry-run] Would scan {name} at {path}")
        return True

    # Run scan-project
    print("  Running scan-project...")
    scan_result = call_mcp_tool("scan-project", {
        "projectPath": path,
        "depth": depth,
    })

    if scan_result is None:
        print("  Error: scan-project failed")
        return False

    sarif = scan_result.get("sarif")
    if sarif is None:
        print("  Error: no SARIF in scan result")
        return False

    # Run generate-sbom
    print("  Running generate-sbom...")
    sbom = call_mcp_tool("generate-sbom", {
        "projectPath": path,
        "projectName": name,
    })

    # Find previous report for delta
    abs_archive = os.path.join(PROJECT_ROOT, archive_path)
    os.makedirs(abs_archive, exist_ok=True)

    latest_report_path = find_latest_report(abs_archive, name)
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if latest_report_path:
        print(f"  Comparing with: {os.path.basename(latest_report_path)}")
        with open(latest_report_path) as f:
            old_sarif = json.load(f)
        delta = compute_delta(old_sarif, sarif)
    else:
        print("  No previous report found — full baseline scan")
        new_results = []
        for run in sarif.get("runs", []):
            new_results.extend(run.get("results", []))
        delta = {
            "new": new_results,
            "resolved": [],
            "unchanged_count": 0,
            "total_old": 0,
            "total_new": len(new_results),
        }

    # Generate delta report
    md_report = generate_delta_report(name, delta, scan_date)

    # Save files
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    sarif_path = os.path.join(abs_archive, f"{name}_{timestamp}.sarif.json")
    sbom_path = os.path.join(abs_archive, f"{name}_{timestamp}.sbom.json")
    md_path = os.path.join(abs_archive, f"{name}_{timestamp}_delta.md")

    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"  Saved: {os.path.basename(sarif_path)}")

    if sbom:
        with open(sbom_path, "w") as f:
            json.dump(sbom, f, indent=2)
        print(f"  Saved: {os.path.basename(sbom_path)}")

    with open(md_path, "w") as f:
        f.write(md_report)
    print(f"  Saved: {os.path.basename(md_path)}")

    # Summary
    print(f"\n  Delta: +{len(delta['new'])} new, -{len(delta['resolved'])} resolved, "
          f"={delta['unchanged_count']} unchanged")

    critical_new = [r for r in delta["new"] if severity_of(r) in ("CRITICAL", "HIGH")]
    if critical_new:
        print(f"  ⚠ ALERT: {len(critical_new)} new CRITICAL/HIGH findings!")

    # Notify
    notify_webhook(notifications.get("slack_webhook"), name, delta)

    return True


def main():
    parser = argparse.ArgumentParser(description="Sentinel Project Rescan")
    parser.add_argument("--project", type=str, help="Rescan a specific project by name")
    parser.add_argument("--dry-run", action="store_true", help="Preview without scanning")
    args = parser.parse_args()

    print("=" * 60)
    print("Sentinel Project Rescan")
    print("=" * 60)

    config = load_config()
    projects = config.get("projects", [])
    archive_path = config.get("archive_path", "reports/archive")
    notifications = config.get("notifications", {})

    if args.project:
        projects = [p for p in projects if p["name"] == args.project]
        if not projects:
            print(f"Error: project '{args.project}' not found in {CONFIG_PATH}")
            return 1

    if not projects:
        print("No projects configured. Edit config/monitored-projects.json")
        return 1

    print(f"Projects to scan: {len(projects)}")

    if args.dry_run:
        print("[DRY RUN — no scans will be executed]\n")

    success = 0
    failed = 0
    for project in projects:
        if rescan_project(project, archive_path, notifications, args.dry_run):
            success += 1
        else:
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"Rescan complete: {success} succeeded, {failed} failed")
    print(f"{'=' * 60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
