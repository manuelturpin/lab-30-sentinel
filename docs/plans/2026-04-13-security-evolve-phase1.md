# Security Evolve — Phase 1 (Sync++) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend sentinel-security with a `evolve` mode that autonomously syncs threat intelligence from CISA KEV, auto-syncs OWASP/CWE standards, and produces a Threat Intelligence Report (TIR).

**Architecture:** Linear pipeline added as a new mode inside `/sentinel-security`. Step 1 (sync) extends the existing `cve-sync.py` with 2 new sources (CISA KEV, OWASP GitHub releases). A new `coverage-scorer.py` measures rule coverage vs standards. A TIR template renders the results. The SKILL.md gains a `## Mode: evolve` section that orchestrates the pipeline.

**Tech Stack:** Python 3 (stdlib only — urllib, json, argparse), Markdown templates, JSON data files.

**Spec:** `docs/specs/2026-04-13-security-evolve-design.md`

---

## File Structure

### New files
- `scripts/coverage-scorer.py` — Measures KB rule coverage vs security standards
- `reports/templates/threat-intel-report.md` — TIR Markdown template

### Modified files
- `scripts/cve-sync.py` — Add CISA KEV sync + OWASP standards auto-sync
- `knowledge-base/cve-feed/sync-config.json` — Add `kev` and `owasp` source configs
- `skills/security/SKILL.md` — Add `## Mode: evolve` section

### New data files (generated at runtime, not committed)
- `knowledge-base/cve-feed/kev-catalog.json` — CISA KEV cache
- `knowledge-base/standards/*.json` — Auto-refreshed from GitHub

---

## Task 1: Add CISA KEV sync to cve-sync.py

**Files:**
- Modify: `scripts/cve-sync.py`
- Modify: `knowledge-base/cve-feed/sync-config.json`
- Test: manual run with `--dry-run`

- [ ] **Step 1: Add KEV source config to sync-config.json**

Add a `kev` entry to `sync_sources` in `knowledge-base/cve-feed/sync-config.json`:

```json
"kev": {
  "api_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "enabled": true,
  "note": "CISA Known Exploited Vulnerabilities catalog — no auth, no rate limit"
}
```

- [ ] **Step 2: Implement sync_kev() function in cve-sync.py**

Add after the `sync_epss()` function (around line 518). The function:
1. Fetches the full KEV JSON catalog (single GET, ~2MB)
2. Extracts: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, `requiredAction`
3. Saves to `kev-catalog.json` as `{"vulnerabilities": [...], "last_modified": "ISO"}`
4. Also enriches existing NVD cache entries: if a CVE exists in both NVD and KEV, add `"kev": true` and `"kev_due_date"` to the NVD entry

```python
def sync_kev(config, dry_run=False):
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    source = config["sync_sources"].get("kev", {})
    if not source.get("enabled"):
        print("  KEV: disabled, skipping")
        return 0

    api_url = source["api_url"]
    print("  KEV: fetching catalog...")

    if dry_run:
        print("  KEV: [dry-run] would fetch catalog")
        return 0

    resp = api_request(api_url, timeout=60)
    if resp is None:
        print("  KEV: failed to fetch catalog")
        return 0

    catalog = resp.get("vulnerabilities", [])
    entries = []
    kev_cve_ids = set()

    for vuln in catalog:
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue
        kev_cve_ids.add(cve_id)
        entries.append({
            "cve_id": cve_id,
            "vendor": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "name": vuln.get("vulnerabilityName", ""),
            "date_added": vuln.get("dateAdded", ""),
            "due_date": vuln.get("shortDescription", ""),
            "ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            "required_action": vuln.get("requiredAction", ""),
            "source": "kev",
        })

    save_cache("kev-catalog.json", {
        "vulnerabilities": entries,
        "total": len(entries),
        "last_modified": datetime.now(timezone.utc).isoformat(),
    })

    # Enrich NVD cache with KEV flag
    nvd_cache = load_cache("nvd-cache.json")
    enriched = 0
    for v in nvd_cache.get("vulnerabilities", []):
        cve_id = v.get("cve_id", "")
        if cve_id in kev_cve_ids:
            v["kev"] = True
            enriched += 1
        elif "kev" not in v:
            v["kev"] = False
    save_cache("nvd-cache.json", nvd_cache)

    print(f"  KEV: {len(entries)} known exploited vulns, enriched {enriched} NVD entries")
    return len(entries)
```

- [ ] **Step 3: Wire sync_kev() into main()**

In `main()`, change step numbering from `[1/4]...[4/4]` to `[1/5]...[5/5]` and add KEV as step 5 after EPSS:

```python
# 5. KEV
print("[5/5] CISA KEV Catalog")
totals["kev"] = sync_kev(config, args.dry_run)
```

- [ ] **Step 4: Create empty kev-catalog.json cache file**

Create `knowledge-base/cve-feed/kev-catalog.json`:
```json
{"vulnerabilities": [], "total": 0, "last_modified": null}
```

- [ ] **Step 5: Test with --dry-run**

Run: `python3 scripts/cve-sync.py --dry-run`
Expected: Output shows `[5/5] CISA KEV Catalog` with `[dry-run] would fetch catalog`

- [ ] **Step 6: Test real sync (KEV only)**

Run: `python3 scripts/cve-sync.py --days 1`
Expected: KEV shows ~1100+ known exploited vulns, NVD entries enriched with `kev: true`

Verify: `python3 -c "import json; d=json.load(open('knowledge-base/cve-feed/kev-catalog.json')); print(f'KEV: {d[\"total\"]} vulns')"` → shows ~1100+

- [ ] **Step 7: Commit**

```bash
git add scripts/cve-sync.py knowledge-base/cve-feed/sync-config.json knowledge-base/cve-feed/kev-catalog.json
git commit -m "feat(evolve): add CISA KEV sync to cve-sync.py — enriches NVD with kev flag"
```

---

## Task 2: Add OWASP/CWE standards auto-sync to cve-sync.py

**Files:**
- Modify: `scripts/cve-sync.py`
- Modify: `knowledge-base/cve-feed/sync-config.json`
- Affects: `knowledge-base/standards/*.json` (auto-refreshed)

- [ ] **Step 1: Add owasp source config to sync-config.json**

Add to `sync_sources`:

```json
"owasp": {
  "enabled": true,
  "repos": {
    "owasp-web": {
      "repo": "OWASP/Top10",
      "current_version": "2025",
      "standards_file": "owasp-web-2025.json"
    },
    "owasp-api": {
      "repo": "OWASP/API-Security",
      "current_version": "2023",
      "standards_file": "owasp-api-2023.json"
    },
    "owasp-llm": {
      "repo": "OWASP/www-project-top-10-for-large-language-model-applications",
      "current_version": "2025",
      "standards_file": "owasp-llm-2025.json"
    },
    "owasp-mobile": {
      "repo": "OWASP/owasp-mastg",
      "current_version": "2024",
      "standards_file": "owasp-mobile-2024.json"
    }
  },
  "note": "Checks GitHub releases for version changes — does not overwrite content, only flags updates"
}
```

- [ ] **Step 2: Implement sync_standards() function**

Add after `sync_kev()`. This function checks GitHub releases for each OWASP repo and flags when a new version is detected — it does NOT auto-rewrite the standards JSON content (that would require manual curation), but it writes a `standards_update_available` flag.

```python
STANDARDS_DIR = os.path.join(PROJECT_ROOT, "knowledge-base", "standards")


def sync_standards(config, dry_run=False):
    """Check OWASP GitHub repos for new releases and flag updates."""
    source = config["sync_sources"].get("owasp", {})
    if not source.get("enabled"):
        print("  Standards: disabled, skipping")
        return 0

    repos = source.get("repos", {})
    headers = {"Accept": "application/vnd.github+json"}
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    updates = []

    for key, repo_config in repos.items():
        repo = repo_config["repo"]
        current = repo_config.get("current_version", "")
        print(f"  Standards: checking {repo}...")

        if dry_run:
            print(f"  Standards: [dry-run] would check {repo}")
            continue

        url = f"https://api.github.com/repos/{repo}/releases/latest"
        resp = api_request(url, headers=headers)

        if resp is None:
            # Fallback: try tags
            url = f"https://api.github.com/repos/{repo}/tags?per_page=1"
            resp = api_request(url, headers=headers)
            if resp and isinstance(resp, list) and resp:
                latest = resp[0].get("name", "").lstrip("v")
            else:
                print(f"  Standards: could not determine latest version for {repo}")
                continue
        else:
            latest = resp.get("tag_name", "").lstrip("v")

        if latest and latest != current:
            updates.append({
                "key": key,
                "repo": repo,
                "current": current,
                "latest": latest,
                "standards_file": repo_config.get("standards_file", ""),
            })
            print(f"  Standards: {key} update available: {current} → {latest}")
        else:
            print(f"  Standards: {key} is current ({current})")

        time.sleep(1)

    # Write update flags to a sidecar file
    if updates and not dry_run:
        update_path = os.path.join(STANDARDS_DIR, "pending-updates.json")
        save_json = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "updates": updates,
        }
        with open(update_path, "w") as f:
            json.dump(save_json, f, indent=2)
            f.write("\n")

    print(f"  Standards: {len(updates)} updates available")
    return len(updates)
```

- [ ] **Step 3: Wire sync_standards() into main()**

Change `[1/5]...[5/5]` to `[1/6]...[6/6]` and add standards as step 6:

```python
# 6. Standards
print("[6/6] OWASP/CWE Standards")
totals["standards"] = sync_standards(config, args.dry_run)
```

- [ ] **Step 4: Test with --dry-run**

Run: `python3 scripts/cve-sync.py --dry-run`
Expected: Output shows `[6/6] OWASP/CWE Standards` with `[dry-run] would check {repo}` for each OWASP repo

- [ ] **Step 5: Test real sync**

Run: `python3 scripts/cve-sync.py --days 1`
Expected: Standards check shows `is current` or `update available` for each repo. If updates found, `knowledge-base/standards/pending-updates.json` is created.

- [ ] **Step 6: Commit**

```bash
git add scripts/cve-sync.py knowledge-base/cve-feed/sync-config.json
git commit -m "feat(evolve): add OWASP/CWE standards auto-sync — checks GitHub releases for updates"
```

---

## Task 3: Create coverage-scorer.py

**Files:**
- Create: `scripts/coverage-scorer.py`
- Test: manual run

- [ ] **Step 1: Create the coverage scorer script**

Create `scripts/coverage-scorer.py`:

```python
#!/usr/bin/env python3
"""
Sentinel Coverage Scorer — Measures KB rule coverage vs security standards.

Usage:
    python3 scripts/coverage-scorer.py              # Full coverage report
    python3 scripts/coverage-scorer.py --json       # JSON output only
"""

import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
STANDARDS_DIR = os.path.join(PROJECT_ROOT, "knowledge-base", "standards")
DOMAINS_DIR = os.path.join(PROJECT_ROOT, "knowledge-base", "domains")


def load_all_rules():
    """Load all rules (manual + CVE) from all domains."""
    rules = []
    for domain in os.listdir(DOMAINS_DIR):
        domain_dir = os.path.join(DOMAINS_DIR, domain)
        if not os.path.isdir(domain_dir):
            continue
        for filename in ["rules.json", "cve-rules.json"]:
            filepath = os.path.join(domain_dir, filename)
            if not os.path.exists(filepath):
                continue
            with open(filepath) as f:
                data = json.load(f)
            rule_list = data if isinstance(data, list) else data.get("rules", [])
            for rule in rule_list:
                rule["_domain"] = domain
                rule["_source"] = filename
                rules.append(rule)
    return rules


def load_standard(filename):
    """Load a standards JSON file."""
    filepath = os.path.join(STANDARDS_DIR, filename)
    if not os.path.exists(filepath):
        return None
    with open(filepath) as f:
        return json.load(f)


def check_coverage(rules, standard_data, match_field, standard_name):
    """Check how many standard items are covered by rules.

    match_field: the field in rules to match against (e.g., 'owasp', 'cwe')
    """
    categories = standard_data.get("categories", standard_data.get("techniques", []))
    if not categories:
        return None

    # Collect all values for the match_field across rules
    rule_values = set()
    for rule in rules:
        val = rule.get(match_field, "")
        if isinstance(val, str) and val:
            rule_values.add(val)
        elif isinstance(val, list):
            rule_values.update(val)
        # Also check standards array
        for std in rule.get("standards", []):
            if isinstance(std, str):
                rule_values.add(std)
            elif isinstance(std, dict):
                for v in std.values():
                    if isinstance(v, str):
                        rule_values.add(v)

    covered = []
    gaps = []

    for cat in categories:
        cat_id = cat.get("id", cat.get("technique_id", ""))
        cat_name = cat.get("name", cat.get("technique_name", ""))

        # Check if any rule references this category
        matched = any(cat_id in rv or cat_id.split(":")[0] in rv for rv in rule_values)

        if matched:
            covered.append({"id": cat_id, "name": cat_name})
        else:
            gaps.append({"id": cat_id, "name": cat_name})

    total = len(categories)
    pct = round(len(covered) / total * 100) if total > 0 else 0

    return {
        "standard": standard_name,
        "total": total,
        "covered": len(covered),
        "pct": pct,
        "gaps": gaps,
    }


def count_rule_quality(rules):
    """Count rules by quality: active patterns vs empty patterns."""
    active = 0  # Has non-empty detect.patterns
    template = 0  # Has empty detect.patterns
    manual = 0  # From rules.json (always active)

    for rule in rules:
        if rule.get("_source") == "rules.json":
            manual += 1
            continue
        patterns = rule.get("detect", {}).get("patterns", [])
        if patterns:
            active += 1
        else:
            template += 1

    return {"manual": manual, "auto_active": active, "auto_template": template}


def main():
    parser = argparse.ArgumentParser(description="Sentinel Coverage Scorer")
    parser.add_argument("--json", action="store_true", help="JSON output only")
    args = parser.parse_args()

    rules = load_all_rules()

    # Standards to check
    standards_checks = [
        ("owasp-web-2025.json", "owasp", "OWASP Web 2025"),
        ("owasp-api-2023.json", "owasp", "OWASP API 2023"),
        ("owasp-llm-2025.json", "owasp", "OWASP LLM 2025"),
        ("owasp-mobile-2024.json", "owasp", "OWASP Mobile 2024"),
        ("cwe-top25.json", "cwe", "CWE Top 25"),
        ("mitre-atlas.json", "mitre_atlas", "MITRE ATLAS"),
    ]

    results = []
    for filename, match_field, name in standards_checks:
        standard = load_standard(filename)
        if standard is None:
            continue
        coverage = check_coverage(rules, standard, match_field, name)
        if coverage:
            results.append(coverage)

    quality = count_rule_quality(rules)

    report = {
        "total_rules": len(rules),
        "quality": quality,
        "coverage": results,
        "overall_pct": round(
            sum(r["pct"] for r in results) / len(results)
        ) if results else 0,
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    # Human-readable output
    print("=" * 60)
    print("Sentinel Coverage Report")
    print("=" * 60)
    print()
    print(f"Total rules: {len(rules)}")
    print(f"  Manual (curated):     {quality['manual']}")
    print(f"  Auto (with patterns): {quality['auto_active']}")
    print(f"  Auto (template only): {quality['auto_template']}")
    print()

    for r in results:
        status = "OK" if r["pct"] >= 90 else "WARN" if r["pct"] >= 70 else "GAP"
        print(f"[{status}] {r['standard']}: {r['covered']}/{r['total']} ({r['pct']}%)")
        if r["gaps"]:
            for gap in r["gaps"][:5]:
                print(f"      Missing: {gap['id']} — {gap['name']}")
            if len(r["gaps"]) > 5:
                print(f"      ... and {len(r['gaps']) - 5} more")
    print()
    print(f"Overall coverage: {report['overall_pct']}%")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Test coverage scorer**

Run: `python3 scripts/coverage-scorer.py`
Expected: Output shows coverage % for each standard with gaps listed. No errors.

Run: `python3 scripts/coverage-scorer.py --json`
Expected: Valid JSON output with `total_rules`, `quality`, `coverage` fields.

- [ ] **Step 3: Commit**

```bash
git add scripts/coverage-scorer.py
git commit -m "feat(evolve): add coverage-scorer.py — measures KB rule coverage vs standards"
```

---

## Task 4: Create TIR report template

**Files:**
- Create: `reports/templates/threat-intel-report.md`

- [ ] **Step 1: Create the TIR template**

Create `reports/templates/threat-intel-report.md`:

```markdown
# Threat Intelligence Report (TIR)

**Date**: {date}
**Sources Synced**: {sources_synced}
**Pipeline**: sentinel-security evolve

---

## Sync Summary

| Source | Status | New Entries |
|--------|--------|-------------|
| NVD | {nvd_status} | {nvd_new} |
| OSV | {osv_status} | {osv_new} |
| GitHub | {github_status} | {github_new} |
| EPSS | {epss_status} | {epss_enriched} |
| CISA KEV | {kev_status} | {kev_total} |
| Standards | {standards_status} | {standards_updates} updates |

---

## Rule Quality

| Category | Count |
|----------|-------|
| Manual (curated) | {rules_manual} |
| Auto (active patterns) | {rules_auto_active} |
| Auto (template only) | {rules_auto_template} |
| **Total** | **{rules_total}** |

---

## Standards Coverage

{coverage_table}

### Gaps

{gaps_list}

---

## KEV Highlights

Active exploits in the wild that affect common stacks:

{kev_highlights}

---

## Recommendations

{recommendations}

---

## Methodology

Generated by `/sentinel-security evolve` pipeline.
Sources: NVD API v2, OSV API, GitHub Advisories, EPSS, CISA KEV, OWASP GitHub.
Standards: OWASP Web/API/LLM/Mobile, CWE Top 25, MITRE ATLAS.

Next sync: {next_sync}
```

- [ ] **Step 2: Commit**

```bash
git add reports/templates/threat-intel-report.md
git commit -m "feat(evolve): add TIR report template for threat intelligence reports"
```

---

## Task 5: Add Mode: evolve to security SKILL.md

**Files:**
- Modify: `skills/security/SKILL.md`

- [ ] **Step 1: Add evolve mode section**

Add a new `## Mode: evolve` section after the `## Multi-Skill Orchestration (Agent Teams)` section at the end of `skills/security/SKILL.md`. This section documents the evolve pipeline and how to invoke each sub-mode.

The section should contain:
1. Invocation syntax (`/sentinel-security evolve [sync|gen|test|score|report]`)
2. Pipeline overview (6 steps with descriptions)
3. Step-by-step instructions for `sync` sub-mode (calls `cve-sync.py`)
4. Step-by-step instructions for `score` sub-mode (calls `coverage-scorer.py`)
5. Step-by-step instructions for `report` sub-mode (renders TIR template)
6. Placeholder notes for `gen`, `test`, `feedback` (Phase 2-4)
7. Cron schedule recommendation

- [ ] **Step 2: Test skill invocation**

Verify the SKILL.md is valid by checking frontmatter is intact and the new section doesn't break the existing skill.

Run: `head -20 skills/security/SKILL.md` — confirm frontmatter is unchanged
Run: `grep -c "## Mode: evolve" skills/security/SKILL.md` — returns 1

- [ ] **Step 3: Commit**

```bash
git add skills/security/SKILL.md
git commit -m "feat(evolve): add Mode: evolve to security SKILL.md — threat intel pipeline"
```

---

## Task 6: Deploy and validate

**Files:**
- Run: `scripts/deploy.sh`

- [ ] **Step 1: Run deploy**

```bash
bash scripts/deploy.sh
```

Expected: All green, new scripts copied to `~/.sentinel/scripts/`

- [ ] **Step 2: Run full sync with new sources**

```bash
python3 ~/.sentinel/scripts/cve-sync.py --days 1
```

Expected: 6 sources synced (NVD, OSV, GitHub, EPSS, KEV, Standards). KEV shows ~1100+ vulns.

- [ ] **Step 3: Run coverage scorer**

```bash
python3 ~/.sentinel/scripts/coverage-scorer.py
```

Expected: Coverage percentages for all 6 standards. Gaps identified.

- [ ] **Step 4: Verify TIR template deployed**

```bash
ls ~/.sentinel/reports/templates/threat-intel-report.md
```

Expected: File exists.

- [ ] **Step 5: Commit deploy verification**

No files to commit — deploy copies to runtime, not repo. Push existing commits:

```bash
git push
```

---

## Summary

| Task | What | New/Modified | Effort |
|------|------|-------------|--------|
| 1 | CISA KEV sync | cve-sync.py, sync-config.json, kev-catalog.json | ~20 min |
| 2 | OWASP auto-sync | cve-sync.py, sync-config.json | ~15 min |
| 3 | Coverage scorer | coverage-scorer.py (new) | ~15 min |
| 4 | TIR template | threat-intel-report.md (new) | ~5 min |
| 5 | SKILL.md evolve mode | security/SKILL.md | ~15 min |
| 6 | Deploy & validate | deploy.sh run + tests | ~10 min |

**Total estimated effort: ~80 min**

After Phase 1, sentinel-security can:
- Sync 6 threat intel sources (up from 4)
- Flag actively exploited CVEs (CISA KEV)
- Detect when OWASP standards have new versions
- Measure rule coverage vs 6 security standards
- Produce a TIR report

Phase 2 (pattern generation by LLM) builds on this foundation.
