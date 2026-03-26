#!/usr/bin/env python3
"""
Sentinel Evolve — Anthropic Ecosystem Sync

Fetches releases and changes from Anthropic's GitHub repos to keep
the feature inventory and evolve KB up to date.

Usage:
    python3 scripts/anthropic-sync.py              # Full sync
    python3 scripts/anthropic-sync.py --dry-run     # Preview without writing
    python3 scripts/anthropic-sync.py --tier 1      # Sync only tier 1 (claude-code)
    python3 scripts/anthropic-sync.py --days 90     # Look back N days on first run
"""

import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# SSL context (reuse pattern from cve-sync.py)
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX.load_verify_locations(certifi.where())
except ImportError:
    print("WARNING: certifi not installed — SSL verification disabled.", file=sys.stderr)
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
INTEL_DIR = os.path.join(PROJECT_ROOT, "knowledge-base", "anthropic-intel")
CONFIG_PATH = os.path.join(INTEL_DIR, "sync-config.json")
EVOLVE_SOURCES_DIR = os.path.join(
    PROJECT_ROOT, "skills", "sentinel-evolve", "knowledge", "sources"
)


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")


def load_cache(filename):
    path = os.path.join(INTEL_DIR, filename)
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def save_cache(filename, data):
    path = os.path.join(INTEL_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def api_request(url, headers=None, timeout=30):
    """Make a GitHub API request with auth and ETag support."""
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", "Sentinel-Evolve/1.0")
    headers.setdefault("Accept", "application/vnd.github+json")

    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining and int(remaining) < 10:
                print(f"  WARNING: GitHub API rate limit low ({remaining} remaining)", file=sys.stderr)
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  Rate limited by GitHub API. Use GITHUB_TOKEN for 5000 req/h.", file=sys.stderr)
        elif e.code == 304:
            return None  # Not Modified (ETag hit)
        else:
            print(f"  HTTP {e.code} from {url}", file=sys.stderr)
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"  Request failed for {url}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Tier 1: Claude Code Releases
# ---------------------------------------------------------------------------
def parse_release_notes(body):
    """Extract features, deprecations, and breaking changes from release notes."""
    if not body:
        return [], [], []

    features = []
    deprecations = []
    breaking = []

    lines = body.split("\n")
    current_section = "features"

    for line in lines:
        line_lower = line.lower().strip()

        # Detect section headers
        if any(kw in line_lower for kw in ["deprecat", "removed", "dropped"]):
            current_section = "deprecations"
        elif any(kw in line_lower for kw in ["breaking", "migration"]):
            current_section = "breaking"
        elif any(kw in line_lower for kw in ["feature", "added", "new", "improvement", "enhance"]):
            current_section = "features"
        elif any(kw in line_lower for kw in ["fix", "bug", "patch", "resolved"]):
            current_section = "fixes"  # skip fixes

        # Extract bullet points
        bullet_match = re.match(r"^\s*[-*]\s+(.+)", line)
        if bullet_match:
            text = bullet_match.group(1).strip()
            # Remove markdown formatting
            text = re.sub(r"`([^`]+)`", r"\1", text)
            text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
            text = text[:200]  # cap length

            if current_section == "features":
                features.append(text)
            elif current_section == "deprecations":
                deprecations.append(text)
            elif current_section == "breaking":
                breaking.append(text)

    return features, deprecations, breaking


def sync_claude_code(config, start_date, dry_run=False):
    """Fetch releases from anthropics/claude-code."""
    source = config["sync_sources"]["claude_code"]
    if not source.get("enabled"):
        print("  claude-code: disabled, skipping")
        return 0

    max_pages = config.get("max_pages_per_source", 5)
    rate_limit = config.get("rate_limit_ms", 1000) / 1000.0

    cache = load_cache("claude-code-releases.json")
    existing = {r["version"]: r for r in cache.get("releases", [])}
    added = 0

    for page in range(1, max_pages + 1):
        url = f"{source['api_url']}?per_page=100&page={page}"
        print(f"  claude-code: fetching releases (page {page})...")

        if dry_run:
            print(f"  claude-code: [dry-run] would fetch {url}")
            # Still fetch in dry-run to show what we'd get, just don't save
            resp = api_request(url)
            if resp:
                for release in resp:
                    tag = release.get("tag_name", "")
                    pub = release.get("published_at", "")[:10]
                    if tag not in existing:
                        print(f"    NEW: {tag} ({pub})")
                        added += 1
            break

        resp = api_request(url)
        if resp is None or not resp:
            break

        for release in resp:
            tag = release.get("tag_name", "").lstrip("v")
            if not tag:
                continue

            pub_date = release.get("published_at", "")
            if pub_date:
                release_date = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
                if release_date < start_date:
                    continue

            features, deprecations, breaking = parse_release_notes(
                release.get("body", "")
            )

            entry = {
                "version": tag,
                "tag": release.get("tag_name", ""),
                "date": pub_date[:10] if pub_date else "",
                "features": features,
                "deprecations": deprecations,
                "breaking_changes": breaking,
                "url": release.get("html_url", ""),
                "prerelease": release.get("prerelease", False),
            }

            if tag not in existing:
                added += 1
            existing[tag] = entry

        # If we got less than 100, no more pages
        if len(resp) < 100:
            break
        time.sleep(rate_limit)

    if not dry_run:
        # Sort by version (newest first)
        releases = sorted(existing.values(), key=lambda r: r.get("date", ""), reverse=True)
        cache["releases"] = releases
        cache["last_modified"] = datetime.now(timezone.utc).isoformat()
        cache["total_releases"] = len(releases)
        save_cache("claude-code-releases.json", cache)

    print(f"  claude-code: +{added} new releases")
    return added


# ---------------------------------------------------------------------------
# Tier 2: Official Skills Repo
# ---------------------------------------------------------------------------
def sync_skills_repo(config, start_date, dry_run=False):
    """Fetch skill catalog from anthropics/skills."""
    source = config["sync_sources"]["skills"]
    if not source.get("enabled"):
        print("  skills: disabled, skipping")
        return 0

    url = f"{source['api_url']}?recursive=1"
    print("  skills: fetching repo tree...")

    if dry_run:
        print(f"  skills: [dry-run] would fetch {url}")
        return 0

    resp = api_request(url)
    if resp is None:
        print("  skills: API error, skipping")
        return 0

    tree = resp.get("tree", [])
    skill_files = [
        item for item in tree
        if item.get("path", "").endswith("SKILL.md") and item.get("type") == "blob"
    ]

    cache = load_cache("skills-catalog.json")
    existing = {s["path"]: s for s in cache.get("skills", [])}
    added = 0

    for skill_file in skill_files:
        path = skill_file["path"]
        sha = skill_file.get("sha", "")

        # Skip if unchanged
        if path in existing and existing[path].get("sha") == sha:
            continue

        # Fetch file content for new/changed skills
        content_url = f"https://api.github.com/repos/anthropics/skills/contents/{path}"
        content_resp = api_request(content_url)
        if content_resp is None:
            continue

        # Decode base64 content
        raw_content = ""
        if content_resp.get("encoding") == "base64":
            raw_content = base64.b64decode(content_resp.get("content", "")).decode("utf-8", errors="replace")

        # Parse frontmatter
        frontmatter = {}
        fm_match = re.match(r"^---\n(.*?)\n---", raw_content, re.DOTALL)
        if fm_match:
            for line in fm_match.group(1).split("\n"):
                if ":" in line:
                    key, val = line.split(":", 1)
                    frontmatter[key.strip()] = val.strip()

        entry = {
            "path": path,
            "sha": sha,
            "name": frontmatter.get("name", os.path.basename(os.path.dirname(path))),
            "description": frontmatter.get("description", ""),
            "frontmatter_keys": list(frontmatter.keys()),
            "size_bytes": content_resp.get("size", 0),
        }

        existing[path] = entry
        added += 1
        time.sleep(0.5)

    if not dry_run:
        cache["skills"] = list(existing.values())
        cache["last_modified"] = datetime.now(timezone.utc).isoformat()
        cache["total_skills"] = len(existing)
        save_cache("skills-catalog.json", cache)

    print(f"  skills: +{added} new/updated skills")
    return added


# ---------------------------------------------------------------------------
# Tier 3: SDK + MCP Releases
# ---------------------------------------------------------------------------
def sync_releases_generic(config, source_key, cache_file, dry_run=False):
    """Generic release syncer for SDK and MCP repos."""
    source = config["sync_sources"].get(source_key)
    if not source or not source.get("enabled"):
        print(f"  {source_key}: disabled, skipping")
        return 0

    repo = source.get("repo", source_key)
    url = f"{source['api_url']}?per_page=30"
    print(f"  {repo}: fetching releases...")

    if dry_run:
        print(f"  {repo}: [dry-run] would fetch {url}")
        return 0

    resp = api_request(url)
    if resp is None or not isinstance(resp, list):
        print(f"  {repo}: API error, skipping")
        return 0

    cache = load_cache(cache_file)
    all_releases = cache.get("releases", {})
    if not isinstance(all_releases, dict):
        all_releases = {}
    added = 0

    for release in resp:
        tag = release.get("tag_name", "")
        if not tag:
            continue

        key = f"{repo}@{tag}"
        if key not in all_releases:
            all_releases[key] = {
                "repo": repo,
                "tag": tag,
                "date": (release.get("published_at") or "")[:10],
                "name": release.get("name", ""),
                "url": release.get("html_url", ""),
                "prerelease": release.get("prerelease", False),
            }
            added += 1

    if not dry_run:
        cache["releases"] = all_releases
        cache["last_modified"] = datetime.now(timezone.utc).isoformat()
        save_cache(cache_file, cache)

    print(f"  {repo}: +{added} new releases")
    return added


# ---------------------------------------------------------------------------
# Tier 4: Cookbooks/Courses Commits
# ---------------------------------------------------------------------------
def sync_commits_generic(config, source_key, cache_file, start_date, dry_run=False):
    """Generic commit syncer for cookbooks and courses."""
    source = config["sync_sources"].get(source_key)
    if not source or not source.get("enabled"):
        print(f"  {source_key}: disabled, skipping")
        return 0

    repo = source.get("repo", source_key)
    since = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    url = f"{source['api_url']}?since={since}&per_page=100"
    print(f"  {repo}: fetching commits since {since[:10]}...")

    if dry_run:
        print(f"  {repo}: [dry-run] would fetch {url}")
        return 0

    resp = api_request(url)
    if resp is None or not isinstance(resp, list):
        print(f"  {repo}: API error, skipping")
        return 0

    cache = load_cache(cache_file)
    existing_shas = set(c.get("sha", "") for c in cache.get("commits", []))
    new_commits = []

    for commit in resp:
        sha = commit.get("sha", "")
        if sha in existing_shas:
            continue
        commit_data = commit.get("commit", {})
        new_commits.append({
            "sha": sha[:8],
            "date": (commit_data.get("committer", {}).get("date") or "")[:10],
            "message": (commit_data.get("message") or "")[:200],
            "url": commit.get("html_url", ""),
        })

    if not dry_run and new_commits:
        cache.setdefault("commits", [])
        cache["commits"] = new_commits + cache["commits"]
        cache["commits"] = cache["commits"][:500]  # keep last 500
        cache["last_modified"] = datetime.now(timezone.utc).isoformat()
        save_cache(cache_file, cache)

    print(f"  {repo}: +{len(new_commits)} new commits")
    return len(new_commits)


# ---------------------------------------------------------------------------
# Markdown Source Generator
# ---------------------------------------------------------------------------
def generate_changelog_source(dry_run=False):
    """Generate a markdown source file from cached claude-code releases for RAG indexing."""
    cache = load_cache("claude-code-releases.json")
    releases = cache.get("releases", [])
    if not releases:
        print("  No releases cached, skipping source generation")
        return

    if dry_run:
        print(f"  [dry-run] Would generate changelog source from {len(releases)} releases")
        return

    lines = ["# Claude Code Changelog — Feature Intelligence\n"]
    lines.append("Auto-generated from GitHub releases for RAG indexing.\n")

    for release in releases[:100]:  # cap at 100 releases
        version = release.get("version", "")
        date = release.get("date", "")
        features = release.get("features", [])
        deprecations = release.get("deprecations", [])
        breaking = release.get("breaking_changes", [])

        if not features and not deprecations and not breaking:
            continue

        lines.append(f"\n## v{version} ({date})\n")

        if features:
            lines.append("\n### Features\n")
            for f in features:
                lines.append(f"- {f}")

        if deprecations:
            lines.append("\n### Deprecations\n")
            for d in deprecations:
                lines.append(f"- {d}")

        if breaking:
            lines.append("\n### Breaking Changes\n")
            for b in breaking:
                lines.append(f"- {b}")

    source_path = os.path.join(EVOLVE_SOURCES_DIR, "claude-code-changelog.md")
    os.makedirs(os.path.dirname(source_path), exist_ok=True)
    with open(source_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"  Generated changelog source: {len(releases)} releases -> {source_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Sentinel Evolve — Anthropic Ecosystem Sync")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--days", type=int, default=None, help="Days to look back (default: 90 first run)")
    parser.add_argument("--tier", type=int, default=None, help="Sync only a specific tier (1-4)")
    args = parser.parse_args()

    print("=" * 60)
    print("Sentinel Evolve — Anthropic Ecosystem Sync")
    print("=" * 60)

    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        print("Using GITHUB_TOKEN (5000 req/h)")
    else:
        print("No GITHUB_TOKEN — limited to 60 req/h. Set GITHUB_TOKEN for better coverage.")

    config = load_config()

    # Determine start date
    last_sync = config.get("last_sync")
    if args.days:
        start_date = datetime.now(timezone.utc) - timedelta(days=args.days)
        print(f"Looking back {args.days} days (--days override)")
    elif last_sync:
        start_date = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
        print(f"Syncing since last run: {last_sync[:10]}")
    else:
        start_date = datetime.now(timezone.utc) - timedelta(days=90)
        print("First run — fetching last 90 days")

    if args.dry_run:
        print("[DRY RUN — no files will be written]\n")
    print()

    totals = {}
    tier_filter = args.tier

    # Tier 1: Claude Code
    if tier_filter is None or tier_filter == 1:
        print("[Tier 1] Claude Code Releases")
        totals["claude_code"] = sync_claude_code(config, start_date, args.dry_run)

    # Tier 2: Skills Repo
    if tier_filter is None or tier_filter == 2:
        print("[Tier 2] Official Skills Catalog")
        totals["skills"] = sync_skills_repo(config, start_date, args.dry_run)

    # Tier 3: SDKs + MCP
    if tier_filter is None or tier_filter == 3:
        print("[Tier 3] SDKs & MCP Releases")
        for source_key in ["sdk_python", "sdk_typescript", "mcp_python", "mcp_typescript"]:
            totals[source_key] = sync_releases_generic(
                config, source_key, "sdk-mcp-releases.json", args.dry_run
            )

    # Tier 4: Cookbooks/Courses (weekly only unless forced by --tier)
    if tier_filter == 4 or (tier_filter is None and datetime.now().weekday() == 0):
        print("[Tier 4] Cookbooks & Courses")
        totals["cookbooks"] = sync_commits_generic(
            config, "cookbooks", "cookbooks-commits.json", start_date, args.dry_run
        )
        totals["courses"] = sync_commits_generic(
            config, "courses", "courses-commits.json", start_date, args.dry_run
        )
    elif tier_filter is None:
        print("[Tier 4] Cookbooks & Courses — skipped (weekly only, run on Mondays or use --tier 4)")

    # Generate markdown source for RAG
    print("\n[Post] Generating RAG sources")
    generate_changelog_source(args.dry_run)

    # Update sync metadata
    if not args.dry_run:
        config["last_sync"] = datetime.now(timezone.utc).isoformat()
        config["last_sync_status"] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": totals,
            "success": True,
        }
        save_config(config)

    # Summary
    print()
    print("=" * 60)
    print("Summary:")
    for source, count in totals.items():
        print(f"  {source}: {count} entries processed")
    total = sum(totals.values())
    print(f"  Total: {total}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
