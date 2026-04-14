#!/usr/bin/env python3
"""
Sentinel Pattern Generator — LLM-powered detection pattern generation for CVE rules.

Uses `claude -p` (pipe mode) to generate regex detection patterns for CVE rules
that have empty detect.patterns[]. Runs through the user's Claude Max subscription
— no API key needed.

Usage:
    python3 scripts/pattern-gen.py                  # Top 50 rules
    python3 scripts/pattern-gen.py --limit 10        # Top 10 rules
    python3 scripts/pattern-gen.py --dry-run         # Preview rules without calling Claude
    python3 scripts/pattern-gen.py --domain web-app  # Only generate for one domain
    python3 scripts/pattern-gen.py --workers 3       # Parallel workers (default: 1)
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
KB_DIR = os.path.join(PROJECT_ROOT, "knowledge-base")
DOMAINS_DIR = os.path.join(KB_DIR, "domains")
KEV_PATH = os.path.join(KB_DIR, "cve-feed", "kev-catalog.json")


# ---------------------------------------------------------------------------
# Reference examples — loaded from domain rules.json for few-shot prompting
# ---------------------------------------------------------------------------

def load_reference_rules(domain=None):
    """Load curated domain rules with populated patterns as few-shot examples."""
    examples = []
    pattern = os.path.join(DOMAINS_DIR, domain or "*", "rules.json")
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            rules = json.load(f)
        for r in rules:
            detect = r.get("detect", {})
            if detect.get("patterns"):
                examples.append({
                    "id": r["id"],
                    "category": r.get("category", ""),
                    "title": r.get("title", ""),
                    "description": r.get("description", "")[:200],
                    "cwe": [s for s in r.get("standards", []) if s.startswith("CWE-")],
                    "detect": {
                        "patterns": detect["patterns"][:3],
                        "negative_patterns": detect.get("negative_patterns", [])[:3],
                        "file_types": detect.get("file_types", []),
                    },
                })
    return examples


def pick_reference_examples(rule, all_examples, count=3):
    """Pick the most relevant reference examples for a given CVE rule."""
    domain = rule.get("category", "")
    cwe_ids = set(s for s in rule.get("standards", []) if s.startswith("CWE-"))

    scored = []
    for ex in all_examples:
        score = 0
        if ex["category"] == domain:
            score += 2
        if cwe_ids & set(ex.get("cwe", [])):
            score += 3
        scored.append((score, ex))

    scored.sort(key=lambda x: -x[0])
    return [ex for _, ex in scored[:count]]


# ---------------------------------------------------------------------------
# CVE rule loading and prioritization
# ---------------------------------------------------------------------------

def load_kev_cve_ids():
    """Load set of CVE IDs from the CISA KEV catalog."""
    if not os.path.exists(KEV_PATH):
        return set()
    with open(KEV_PATH) as f:
        data = json.load(f)
    return {v["cve_id"] for v in data.get("vulnerabilities", [])}


def load_empty_rules(domain_filter=None):
    """Load all CVE rules with empty detect.patterns across all domains."""
    rules = []
    pattern = os.path.join(DOMAINS_DIR, domain_filter or "*", "cve-rules.json")
    for path in sorted(glob.glob(pattern)):
        domain = os.path.basename(os.path.dirname(path))
        with open(path) as f:
            domain_rules = json.load(f)
        for r in domain_rules:
            if not r.get("detect", {}).get("patterns"):
                # Skip rules that were already LLM-generated
                if r.get("generated_by") == "llm":
                    continue
                r["_source_path"] = path
                r["_domain"] = domain
                rules.append(r)
    return rules


def prioritize_rules(rules, kev_ids):
    """Sort rules by priority: KEV > CVSS>=9 > CVSS>=7+EPSS>=0.5 > rest."""
    def priority_key(r):
        is_kev = r["id"] in kev_ids
        cvss = r.get("cvss_v4") or 0
        epss = r.get("epss_score") or 0
        if is_kev:
            return (0, -cvss)
        if cvss >= 9.0:
            return (1, -cvss)
        if cvss >= 7.0 and epss >= 0.5:
            return (2, -epss)
        return (3, -cvss)

    rules.sort(key=priority_key)
    return rules


def priority_label(rule, kev_ids):
    """Human-readable priority label for a rule."""
    if rule["id"] in kev_ids:
        return "KEV"
    cvss = rule.get("cvss_v4") or 0
    epss = rule.get("epss_score") or 0
    if cvss >= 9.0:
        return f"CVSS {cvss}"
    if cvss >= 7.0 and epss >= 0.5:
        return f"CVSS {cvss} + EPSS {epss:.2f}"
    return f"CVSS {cvss}"


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a security static analysis rule generator. Given a CVE description, you generate \
regex detection patterns that identify vulnerable code patterns in source files.

Rules:
- Patterns are Python-compatible regex strings used with re.search() on source code lines
- Patterns should be specific enough to detect the vulnerability class, not just the CVE product
- Focus on the CWE (weakness class) to write general patterns, not product-specific strings
- negative_patterns are strings/regexes that indicate the vulnerability is mitigated (e.g., sanitization functions)
- file_types are glob patterns for files to scan (e.g., "*.js", "*.py", "*.go")
- exclude lists directory names to skip during scanning
- confidence: 1.0 = exact CVE pattern, 0.7 = CWE-class pattern, 0.4 = broad heuristic
- If the CVE is too product-specific or infrastructure-only (no detectable code pattern), \
set patterns to an empty array and confidence to 0.0

Output ONLY valid JSON, no markdown fences, no explanation."""


def build_user_prompt(rule, examples):
    """Build the user prompt for a single CVE rule."""
    cwe_list = ", ".join(s for s in rule.get("standards", []) if s.startswith("CWE-"))
    epss_info = ""
    if rule.get("epss_score"):
        epss_info = f"\nEPSS Score: {rule['epss_score']:.4f} (exploit probability)"

    examples_text = ""
    if examples:
        ex_items = []
        for ex in examples:
            ex_items.append(json.dumps({
                "id": ex["id"],
                "title": ex["title"],
                "cwe": ex["cwe"],
                "detect": ex["detect"],
            }, indent=2))
        examples_text = "\n\nReference patterns from the same domain (learn the style):\n" + \
            "\n---\n".join(ex_items)

    return f"""\
Generate detection patterns for this CVE:

CVE ID: {rule['id']}
Severity: {rule.get('severity', 'UNKNOWN')} (CVSS {rule.get('cvss_v4', 'N/A')})
Domain: {rule.get('category', 'unknown')}
CWE: {cwe_list or 'Not specified'}
Description: {rule.get('description', 'No description available')}{epss_info}
{examples_text}

Output JSON with this exact schema:
{{
  "patterns": ["regex1", "regex2"],
  "file_types": ["*.ext"],
  "negative_patterns": ["mitigationPattern1"],
  "exclude": ["dir_to_skip"],
  "confidence": 0.7
}}"""


# ---------------------------------------------------------------------------
# Claude CLI — pipe mode execution
# ---------------------------------------------------------------------------

def call_claude(prompt, system_prompt, model="sonnet"):
    """Call claude CLI in pipe mode and return the raw text output."""
    cmd = ["claude", "-p", "--output-format", "text", "--model", model]
    if system_prompt:
        cmd.extend(["--system-prompt", system_prompt])

    full_prompt = prompt
    try:
        result = subprocess.run(
            cmd,
            input=full_prompt,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                print(f"  claude stderr: {stderr[:200]}", file=sys.stderr)
            return None
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print("  claude: timeout (120s)", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("  ERROR: 'claude' CLI not found in PATH", file=sys.stderr)
        sys.exit(1)


def generate_one(rule, examples_db, model):
    """Generate patterns for a single rule via claude -p."""
    examples = pick_reference_examples(rule, examples_db)
    user_prompt = build_user_prompt(rule, examples)
    text = call_claude(user_prompt, SYSTEM_PROMPT, model=model)
    if text:
        parsed = parse_llm_output(text)
        if parsed:
            return (rule["id"], parsed)
    return (rule["id"], None)


def generate_patterns(rules, examples_db, model, workers=1):
    """Generate patterns for all selected rules."""
    results = {}

    if workers <= 1:
        # Sequential
        for i, rule in enumerate(rules):
            rid = rule["id"]
            print(f"  [{i+1}/{len(rules)}] {rid} ({rule.get('category')})...",
                  end="", flush=True)
            _, parsed = generate_one(rule, examples_db, model)
            if parsed:
                results[rid] = parsed
                n = len(parsed.get("patterns", []))
                print(f" {n} patterns, conf={parsed.get('confidence', 0)}")
            else:
                print(" no result")
    else:
        # Parallel
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(generate_one, rule, examples_db, model): rule
                for rule in rules
            }
            done = 0
            for future in as_completed(futures):
                done += 1
                rule = futures[future]
                rid, parsed = future.result()
                if parsed:
                    results[rid] = parsed
                    n = len(parsed.get("patterns", []))
                    print(f"  [{done}/{len(rules)}] {rid}: "
                          f"{n} patterns, conf={parsed.get('confidence', 0)}")
                else:
                    print(f"  [{done}/{len(rules)}] {rid}: no result")

    return results


# ---------------------------------------------------------------------------
# Output parsing and validation
# ---------------------------------------------------------------------------

def parse_llm_output(text):
    """Parse LLM output into a validated pattern dict."""
    text = text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        text = re.sub(r'^```(?:json)?\s*\n?', '', text)
        text = re.sub(r'\n?```\s*$', '', text)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to extract JSON from surrounding text
        match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
            except json.JSONDecodeError:
                return None
        else:
            return None

    # Validate and normalize
    patterns = data.get("patterns", [])
    if not isinstance(patterns, list):
        return None

    # Validate regexes
    valid_patterns = []
    for p in patterns:
        if not isinstance(p, str) or not p.strip():
            continue
        try:
            re.compile(p)
            valid_patterns.append(p)
        except re.error:
            pass  # Skip invalid regex

    file_types = data.get("file_types", [])
    if not isinstance(file_types, list):
        file_types = []
    file_types = [ft for ft in file_types if isinstance(ft, str) and ft.strip()]

    negative_patterns = data.get("negative_patterns", [])
    if not isinstance(negative_patterns, list):
        negative_patterns = []
    negative_patterns = [np for np in negative_patterns if isinstance(np, str) and np.strip()]

    exclude = data.get("exclude", [])
    if not isinstance(exclude, list):
        exclude = []
    exclude = [e for e in exclude if isinstance(e, str) and e.strip()]

    confidence = data.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)):
        confidence = 0.5
    confidence = max(0.0, min(1.0, float(confidence)))

    return {
        "patterns": valid_patterns,
        "file_types": file_types,
        "negative_patterns": negative_patterns,
        "exclude": exclude,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Write results back to cve-rules.json files
# ---------------------------------------------------------------------------

def apply_results(rules, results):
    """Write generated patterns back to their source cve-rules.json files."""
    now = datetime.now(timezone.utc).isoformat()
    files_to_update = {}

    # Index selected rules by ID for quick lookup
    rules_by_id = {r["id"]: r for r in rules}

    updated = 0
    skipped = 0

    for rule_id, generated in results.items():
        if rule_id not in rules_by_id:
            continue
        rule = rules_by_id[rule_id]
        source_path = rule["_source_path"]

        # Skip if LLM returned no patterns (product-specific CVE)
        if not generated["patterns"]:
            skipped += 1
            continue

        # Mark for update
        rule["detect"]["patterns"] = generated["patterns"]
        rule["detect"]["file_types"] = generated["file_types"]
        if generated["negative_patterns"]:
            rule["detect"]["negative_patterns"] = generated["negative_patterns"]
        if generated["exclude"]:
            rule["detect"]["exclude"] = generated["exclude"]
        rule["confidence"] = generated["confidence"]
        rule["generated_by"] = "llm"
        rule["generated_at"] = now
        rule["status"] = "untested"

        files_to_update[source_path] = True
        updated += 1

    # Write back to each modified file
    for path in files_to_update:
        with open(path) as f:
            all_rules = json.load(f)

        # Apply updates by matching rule ID
        for i, r in enumerate(all_rules):
            if r["id"] in results and r["id"] in rules_by_id:
                rule = rules_by_id[r["id"]]
                for key in ("detect", "confidence", "generated_by", "generated_at", "status"):
                    if key in rule:
                        all_rules[i][key] = rule[key]

        with open(path, "w") as f:
            json.dump(all_rules, f, indent=2)
            f.write("\n")

        domain = os.path.basename(os.path.dirname(path))
        count = sum(1 for rid in results if rules_by_id.get(rid, {}).get("_source_path") == path
                    and results[rid].get("patterns"))
        print(f"  Updated {path.split('domains/')[-1]}: {count} rules")

    return updated, skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate detection patterns for CVE rules using Claude CLI (Max subscription)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max rules to process per run (default: 50)")
    parser.add_argument("--domain", type=str, default=None,
                        help="Only process rules from this domain")
    parser.add_argument("--model", type=str, default="sonnet",
                        help="Claude model to use: sonnet, opus, haiku (default: sonnet)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel claude processes (default: 1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview selected rules without calling Claude")
    args = parser.parse_args()

    print("=" * 60)
    print("Sentinel Pattern Generator (claude -p, Max subscription)")
    print("=" * 60)

    # Load KEV catalog for prioritization
    kev_ids = load_kev_cve_ids()
    print(f"\nKEV catalog: {len(kev_ids)} actively exploited CVEs")

    # Load reference rules for few-shot prompting
    ref_examples = load_reference_rules(args.domain)
    print(f"Reference rules loaded: {len(ref_examples)} examples")

    # Load and prioritize empty CVE rules
    empty_rules = load_empty_rules(args.domain)
    print(f"Empty CVE rules found: {len(empty_rules)}")

    if not empty_rules:
        print("\nNo empty CVE rules to process. Done.")
        return

    prioritized = prioritize_rules(empty_rules, kev_ids)
    selected = prioritized[:args.limit]

    # Count by priority tier
    kev_count = sum(1 for r in selected if r["id"] in kev_ids)
    crit_count = sum(1 for r in selected if r["id"] not in kev_ids
                     and (r.get("cvss_v4") or 0) >= 9.0)
    high_epss = sum(1 for r in selected if r["id"] not in kev_ids
                    and (r.get("cvss_v4") or 0) >= 7.0 and (r.get("cvss_v4") or 0) < 9.0
                    and (r.get("epss_score") or 0) >= 0.5)
    rest = len(selected) - kev_count - crit_count - high_epss

    print(f"\nSelected {len(selected)} rules (limit={args.limit}):")
    print(f"  KEV (actively exploited): {kev_count}")
    print(f"  CVSS >= 9.0 (critical):   {crit_count}")
    print(f"  CVSS >= 7.0 + EPSS >= 0.5: {high_epss}")
    print(f"  Other:                     {rest}")

    # Domain breakdown
    domain_counts = {}
    for r in selected:
        d = r.get("_domain", "unknown")
        domain_counts[d] = domain_counts.get(d, 0) + 1
    print(f"\n  By domain: {', '.join(f'{d}={c}' for d, c in sorted(domain_counts.items()))}")

    if args.dry_run:
        print(f"\n--- DRY RUN: Top {min(10, len(selected))} rules ---")
        for r in selected[:10]:
            label = priority_label(r, kev_ids)
            cwe = ", ".join(s for s in r.get("standards", []) if s.startswith("CWE-"))
            print(f"  {r['id']:20s} | {r.get('severity', '?'):8s} | {label:20s} | {cwe:15s} | {r.get('_domain', '?')}")
        if len(selected) > 10:
            print(f"  ... and {len(selected) - 10} more")

        # Show sample prompt
        sample = selected[0]
        sample_examples = pick_reference_examples(sample, ref_examples)
        print(f"\n--- Sample prompt for {sample['id']} ---")
        print(f"System: {SYSTEM_PROMPT[:200]}...")
        print(f"\nUser:\n{build_user_prompt(sample, sample_examples)[:600]}...")
        print(f"\n--- End dry run ---")
        return

    # Generate patterns
    print(f"\nModel: {args.model} | Workers: {args.workers}")
    print(f"Running via: claude -p (Max subscription)\n")

    results = generate_patterns(selected, ref_examples, args.model, args.workers)

    if not results:
        print("\nNo results generated. Check 'claude -p' works in your terminal.")
        sys.exit(1)

    # Apply results
    print(f"\n--- Applying {len(results)} results ---")
    updated, skipped = apply_results(selected, results)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Summary:")
    print(f"  Rules processed:  {len(selected)}")
    print(f"  Patterns generated: {len(results)}")
    print(f"  Rules updated:    {updated}")
    print(f"  Skipped (no code pattern): {skipped}")
    print(f"  Errors:           {len(selected) - len(results)}")
    remaining = len(empty_rules) - updated
    print(f"  Remaining empty:  {remaining}")
    print(f"{'=' * 60}")

    if updated > 0:
        print(f"\nNext: run 'python3 scripts/rule-tester.py' to validate generated patterns")
        print(f"Then: run 'python3 rag/indexer.py' to re-index the KB")


if __name__ == "__main__":
    main()
