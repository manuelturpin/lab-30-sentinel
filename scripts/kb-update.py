#!/usr/bin/env python3
"""
Sentinel KB Update — Generates KB rules from CVE caches and re-indexes ChromaDB.

Usage:
    python3 scripts/kb-update.py              # Full update + re-index
    python3 scripts/kb-update.py --dry-run     # Preview without writing
    python3 scripts/kb-update.py --skip-reindex # Generate rules only, skip ChromaDB
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
CVE_FEED_DIR = os.path.join(PROJECT_ROOT, "knowledge-base", "cve-feed")
KB_DOMAINS_DIR = os.path.join(PROJECT_ROOT, "knowledge-base", "domains")
RAG_DIR = os.path.join(PROJECT_ROOT, "rag")

# Mapping: keywords in CVE description/package → KB domain
DOMAIN_KEYWORDS = {
    "web-app": [
        "express", "django", "rails", "flask", "spring", "laravel", "nextjs",
        "next.js", "react", "angular", "vue", "xss", "csrf", "injection",
        "cross-site", "web server", "http", "apache", "nginx",
    ],
    "api": [
        "api", "graphql", "rest", "oauth", "jwt", "token", "authentication",
        "authorization", "endpoint",
    ],
    "database": [
        "postgres", "mysql", "mongodb", "sqlite", "redis", "sql injection",
        "database", "mariadb", "oracle db",
    ],
    "infrastructure": [
        "docker", "kubernetes", "k8s", "terraform", "aws", "azure", "gcp",
        "container", "vm", "ssh", "server",
    ],
    "ssl-tls": [
        "ssl", "tls", "certificate", "openssl", "x509",
    ],
    "cors": [
        "cors", "cross-origin",
    ],
    "mobile": [
        "android", "ios", "mobile", "swift", "kotlin",
    ],
    "data-privacy": [
        "privacy", "gdpr", "pii", "personal data", "data leak",
    ],
    "llm-ai": [
        "llm", "prompt injection", "ai model", "machine learning", "langchain",
        "openai",
    ],
}

# Ecosystem → default domain
ECOSYSTEM_DOMAIN_MAP = {
    "npm": "supply-chain",
    "pypi": "supply-chain",
    "pip": "supply-chain",
    "go": "supply-chain",
    "cargo": "supply-chain",
    "crates.io": "supply-chain",
    "maven": "supply-chain",
    "rubygems": "supply-chain",
    "PyPI": "supply-chain",
    "Go": "supply-chain",
    "Maven": "supply-chain",
    "RubyGems": "supply-chain",
    "rust": "supply-chain",
}


def classify_domain(description, ecosystem=None):
    """Determine KB domain from CVE description and ecosystem."""
    text = (description or "").lower()

    # Check keyword-based domains first
    for domain, keywords in DOMAIN_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                return domain

    # Fall back to ecosystem mapping
    if ecosystem:
        return ECOSYSTEM_DOMAIN_MAP.get(ecosystem, "supply-chain")

    return "supply-chain"


def cvss_to_severity(score):
    """Convert CVSS score to severity string."""
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def build_rule_from_nvd(vuln):
    """Generate a KB rule from an NVD CVE entry."""
    cve_id = vuln.get("cve_id", "")
    score = vuln.get("cvss_score")

    # Only generate rules for CVSS >= 7.0
    if score is None or score < 7.0:
        return None

    description = vuln.get("description", "")
    domain = classify_domain(description)
    cwes = vuln.get("cwes", [])
    epss = vuln.get("epss", {})

    return {
        "id": cve_id,
        "severity": cvss_to_severity(score),
        "cvss_v4": score,
        "category": domain,
        "subcategory": "cve-automated",
        "title": f"{cve_id}: {description[:100]}",
        "description": description[:500],
        "detect": {
            "patterns": [],
            "file_types": [],
            "exclude": [],
        },
        "remediation": {
            "description": f"Update affected components to patched versions. See NVD entry for {cve_id}.",
            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        },
        "standards": cwes,
        "epss_score": epss.get("score"),
        "epss_percentile": epss.get("percentile"),
        "source": "nvd",
        "auto_generated": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_rule_from_osv(vuln):
    """Generate a KB rule from an OSV vulnerability."""
    vuln_id = vuln.get("id", "")
    summary = vuln.get("summary", "")
    details = vuln.get("details", "")

    # Get CVSS from severity field (OSV stores CVSS vector string, not score)
    score = None
    severity_str = vuln.get("severity")
    if isinstance(severity_str, str):
        # Try to extract numeric score if present (some OSV entries include it)
        score_match = re.search(r"(\d+\.\d+)", severity_str)
        if score_match:
            score = float(score_match.group(1))
        elif severity_str.startswith("CVSS:"):
            # CVSS vector without inline score — cannot determine severity
            # Skip rather than assume a score
            score = None

    # Only generate rules for CVSS >= 7.0 (same threshold as NVD/GitHub)
    if score is None or score < 7.0:
        return None

    # Determine ecosystem from affected packages
    ecosystem = None
    package_patterns = []
    for pkg in vuln.get("affected_packages", []):
        eco = pkg.get("ecosystem", "")
        if eco:
            ecosystem = eco
        name = pkg.get("name", "")
        if name:
            package_patterns.append(re.escape(name))

    domain = classify_domain(f"{summary} {details}", ecosystem)

    # Get CVE alias if present
    cve_alias = None
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_alias = alias
            break

    return {
        "id": vuln_id,
        "severity": cvss_to_severity(score),
        "cvss_v4": score,
        "category": domain,
        "subcategory": "cve-automated",
        "title": f"{vuln_id}: {summary[:100]}",
        "description": (summary or details)[:500],
        "detect": {
            "patterns": package_patterns[:5],
            "file_types": ["package.json", "requirements.txt", "go.mod", "Cargo.toml", "pom.xml", "Gemfile"],
            "exclude": ["node_modules"],
        },
        "remediation": {
            "description": f"Update affected packages. See {vuln_id} advisory.",
            "references": [f"https://osv.dev/vulnerability/{vuln_id}"],
        },
        "standards": [cve_alias] if cve_alias else [],
        "source": "osv",
        "auto_generated": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_rule_from_github(advisory):
    """Generate a KB rule from a GitHub advisory."""
    ghsa_id = advisory.get("ghsa_id", "")
    score = advisory.get("cvss_score")

    # Only generate rules for high+ severity
    if score is not None and score < 7.0:
        return None
    severity = advisory.get("severity", "").upper()
    if score is None and severity not in ("CRITICAL", "HIGH"):
        return None

    summary = advisory.get("summary", "")
    ecosystem = advisory.get("ecosystem", "")
    domain = classify_domain(summary, ecosystem)
    cwes = advisory.get("cwes", [])
    cve_id = advisory.get("cve_id")
    epss = advisory.get("epss", {})

    return {
        "id": ghsa_id,
        "severity": cvss_to_severity(score) if score else severity,
        "cvss_v4": score,
        "category": domain,
        "subcategory": "cve-automated",
        "title": f"{ghsa_id}: {summary[:100]}",
        "description": summary[:500],
        "detect": {
            "patterns": [],
            "file_types": [],
            "exclude": [],
        },
        "remediation": {
            "description": f"Update affected packages. See GitHub advisory {ghsa_id}.",
            "references": [f"https://github.com/advisories/{ghsa_id}"],
        },
        "standards": cwes + ([cve_id] if cve_id else []),
        "epss_score": epss.get("score"),
        "epss_percentile": epss.get("percentile"),
        "source": "github",
        "auto_generated": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_rules():
    """Generate KB rules from all CVE caches."""
    rules_by_domain = {}
    seen_ids = set()

    # Process NVD cache
    nvd_cache = load_cache("nvd-cache.json")
    for vuln in nvd_cache.get("vulnerabilities", []):
        rule = build_rule_from_nvd(vuln)
        if rule and rule["id"] not in seen_ids:
            seen_ids.add(rule["id"])
            domain = rule["category"]
            rules_by_domain.setdefault(domain, []).append(rule)

    # Process OSV cache
    osv_cache = load_cache("osv-cache.json")
    for vuln in osv_cache.get("vulnerabilities", []):
        rule = build_rule_from_osv(vuln)
        if rule and rule["id"] not in seen_ids:
            seen_ids.add(rule["id"])
            domain = rule["category"]
            rules_by_domain.setdefault(domain, []).append(rule)

    # Process GitHub cache
    gh_cache = load_cache("github-advisories.json")
    for advisory in gh_cache.get("advisories", []):
        rule = build_rule_from_github(advisory)
        if rule and rule["id"] not in seen_ids:
            seen_ids.add(rule["id"])
            domain = rule["category"]
            rules_by_domain.setdefault(domain, []).append(rule)

    return rules_by_domain


def load_cache(filename):
    path = os.path.join(CVE_FEED_DIR, filename)
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_domain_rules(rules_by_domain, dry_run=False):
    """Save generated rules to cve-rules.json per domain."""
    total = 0
    domains_updated = []

    # First pass: redirect rules from non-existent domains to supply-chain
    redirected = {}
    for domain, rules in list(rules_by_domain.items()):
        domain_dir = os.path.join(KB_DOMAINS_DIR, domain)
        if not os.path.isdir(domain_dir):
            print(f"  Warning: domain dir '{domain}' does not exist, redirecting to supply-chain")
            redirected.setdefault("supply-chain", []).extend(rules)
            del rules_by_domain[domain]

    for domain, rules in redirected.items():
        rules_by_domain.setdefault(domain, []).extend(rules)

    # Second pass: save all rules
    for domain, rules in rules_by_domain.items():
        domain_dir = os.path.join(KB_DOMAINS_DIR, domain)
        output_path = os.path.join(domain_dir, "cve-rules.json")
        print(f"  {domain}: {len(rules)} rules → cve-rules.json")

        if not dry_run:
            with open(output_path, "w") as f:
                json.dump(rules, f, indent=2)
                f.write("\n")

        total += len(rules)
        domains_updated.append(domain)

    return total, domains_updated


def reindex_chromadb():
    """Re-index ChromaDB by calling the existing indexer."""
    indexer_path = os.path.join(RAG_DIR, "indexer.py")
    print(f"\n  Running: python3 {indexer_path}")

    result = subprocess.run(
        [sys.executable, indexer_path],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"  Re-indexing failed:\n{result.stderr}", file=sys.stderr)
        return False

    for line in result.stdout.strip().split("\n"):
        print(f"    {line}")
    return True


def validate_rag():
    """Validate RAG with a test query."""
    query_path = os.path.join(RAG_DIR, "query.py")
    result = subprocess.run(
        [sys.executable, query_path, "--query", "latest CVE vulnerability", "--limit", "3"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"  Validation query failed:\n{result.stderr}", file=sys.stderr)
        return False

    print("  RAG validation query OK:")
    for line in result.stdout.strip().split("\n")[:5]:
        print(f"    {line}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Sentinel KB Update")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--skip-reindex", action="store_true", help="Skip ChromaDB re-indexing")
    args = parser.parse_args()

    print("=" * 60)
    print("Sentinel KB Update")
    print("=" * 60)

    if args.dry_run:
        print("[DRY RUN — no files will be written]\n")

    # Check caches are populated
    nvd = load_cache("nvd-cache.json")
    osv = load_cache("osv-cache.json")
    gh = load_cache("github-advisories.json")
    total_cached = (
        len(nvd.get("vulnerabilities", []))
        + len(osv.get("vulnerabilities", []))
        + len(gh.get("advisories", []))
    )

    if total_cached == 0:
        print("Error: CVE caches are empty. Run cve-sync.py first.")
        return 1

    print(f"CVE caches: {total_cached} entries total")
    print(f"  NVD: {len(nvd.get('vulnerabilities', []))}")
    print(f"  OSV: {len(osv.get('vulnerabilities', []))}")
    print(f"  GitHub: {len(gh.get('advisories', []))}")

    # Generate rules
    print("\nGenerating KB rules (CVSS >= 7.0)...")
    rules_by_domain = generate_rules()

    total_rules = sum(len(r) for r in rules_by_domain.values())
    print(f"Generated {total_rules} rules across {len(rules_by_domain)} domains")

    # Save rules
    print("\nSaving rules...")
    saved, domains = save_domain_rules(rules_by_domain, args.dry_run)

    # Re-index ChromaDB
    if not args.dry_run and not args.skip_reindex:
        print("\nRe-indexing ChromaDB...")
        if reindex_chromadb():
            print("\nValidating RAG...")
            validate_rag()
        else:
            print("Warning: ChromaDB re-indexing failed. Rules were saved but not indexed.")
    elif args.skip_reindex:
        print("\nSkipping ChromaDB re-index (--skip-reindex)")

    # Summary
    print()
    print("=" * 60)
    print("Summary:")
    print(f"  Rules generated: {total_rules}")
    print(f"  Domains updated: {', '.join(domains) if domains else 'none'}")
    print(f"  Re-indexed: {'skipped' if args.skip_reindex or args.dry_run else 'yes'}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
