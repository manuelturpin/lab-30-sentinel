#!/usr/bin/env python3
"""
Sentinel Rule Tester — validates LLM-generated detection patterns.

Tests untested CVE rules against a corpus of known-vulnerable and known-safe
code fixtures. Rules passing the precision gate (>=70%) are promoted to "active".

Usage:
    python3 scripts/rule-tester.py                  # Test all untested rules
    python3 scripts/rule-tester.py --domain api     # Test one domain
    python3 scripts/rule-tester.py --dry-run        # Preview without status changes
    python3 scripts/rule-tester.py --verbose         # Show match details
    python3 scripts/rule-tester.py --precision 0.8   # Custom precision gate
"""

import argparse
import glob
import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
KB_DIR = os.path.join(PROJECT_ROOT, "knowledge-base")
DOMAINS_DIR = os.path.join(KB_DIR, "domains")
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "tests", "fixtures")
VULN_APP_DIR = os.path.join(PROJECT_ROOT, "tests", "vulnerable-app", "src")

DEFAULT_PRECISION_GATE = 0.70
BACKTRACK_TIMEOUT_S = 2.0  # Max seconds for a single regex test


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------

def load_files_from_dir(directory):
    """Load all source files from a directory tree."""
    files = []
    if not os.path.isdir(directory):
        return files
    for root, _, filenames in os.walk(directory):
        for fname in filenames:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                files.append({
                    "path": fpath,
                    "filename": fname,
                    "content": content,
                    "lines": content.splitlines(),
                })
            except IOError:
                pass
    return files


def load_corpus():
    """Load the full test corpus: vulnerable + safe files."""
    vulnerable = load_files_from_dir(os.path.join(FIXTURES_DIR, "vulnerable"))
    vulnerable += load_files_from_dir(VULN_APP_DIR)
    safe = load_files_from_dir(os.path.join(FIXTURES_DIR, "safe"))
    return {"vulnerable": vulnerable, "safe": safe}


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def load_untested_rules(domain_filter=None):
    """Load all CVE rules with status='untested'."""
    rules = []
    pattern = os.path.join(DOMAINS_DIR, domain_filter or "*", "cve-rules.json")
    for path in sorted(glob.glob(pattern)):
        domain = os.path.basename(os.path.dirname(path))
        with open(path) as f:
            domain_rules = json.load(f)
        for r in domain_rules:
            if r.get("status") == "untested":
                r["_source_path"] = path
                r["_domain"] = domain
                rules.append(r)
    return rules


# ---------------------------------------------------------------------------
# Pattern validation
# ---------------------------------------------------------------------------

def validate_pattern(pattern_str):
    """Validate a regex pattern: compilation and backtracking safety."""
    # Compile check
    try:
        compiled = re.compile(pattern_str)
    except re.error as e:
        return {"valid": False, "error": f"compile: {e}"}

    # Backtracking check with adversarial inputs
    adversarial_inputs = [
        "a" * 200,
        "a" * 100 + "!" * 100,
        " " * 200,
        "x" * 50 + "\n" * 50 + "y" * 50,
        "aaaa@aaaa.aaaa.aaaa.aaaa.aaaa.aaaa",
    ]

    for test_input in adversarial_inputs:
        start = time.time()
        try:
            compiled.search(test_input)
        except Exception:
            pass
        elapsed = time.time() - start
        if elapsed > BACKTRACK_TIMEOUT_S:
            return {"valid": False, "error": f"backtracking ({elapsed:.1f}s)"}

    return {"valid": True, "compiled": compiled}


# ---------------------------------------------------------------------------
# File type matching
# ---------------------------------------------------------------------------

def file_matches_types(filename, file_types):
    """Check if filename matches any of the rule's file_types globs."""
    if not file_types:
        return True  # No filter = match all source files

    for ft in file_types:
        if ft.startswith("*."):
            ext = ft[1:]  # .js, .py, etc.
            if filename.endswith(ext):
                return True
        elif ft == filename:
            return True
    return False


# ---------------------------------------------------------------------------
# Pattern matching engine
# ---------------------------------------------------------------------------

def scan_file(file_info, patterns, negative_patterns, file_types):
    """Scan a single file with a rule's patterns. Returns list of matches."""
    if not file_matches_types(file_info["filename"], file_types):
        return []

    matches = []
    for line_num, line in enumerate(file_info["lines"], 1):
        for pattern in patterns:
            try:
                if re.search(pattern, line):
                    # Check negative patterns (mitigations)
                    mitigated = False
                    for neg in negative_patterns:
                        try:
                            if re.search(neg, line):
                                mitigated = True
                                break
                        except re.error:
                            pass

                    if not mitigated:
                        matches.append({
                            "file": file_info["filename"],
                            "line": line_num,
                            "pattern": pattern,
                            "text": line.strip()[:120],
                        })
            except re.error:
                pass

    return matches


def run_rule_against_corpus(rule, corpus_files):
    """Run a rule's patterns against a list of files."""
    patterns = rule.get("detect", {}).get("patterns", [])
    negative_patterns = rule.get("detect", {}).get("negative_patterns", [])
    file_types = rule.get("detect", {}).get("file_types", [])

    all_matches = []
    for file_info in corpus_files:
        matches = scan_file(file_info, patterns, negative_patterns, file_types)
        all_matches.extend(matches)

    return all_matches


# ---------------------------------------------------------------------------
# Rule testing
# ---------------------------------------------------------------------------

def test_rule(rule, corpus, precision_gate=DEFAULT_PRECISION_GATE, verbose=False):
    """Test a single rule. Returns a result dict with scores."""
    rule_id = rule["id"]
    patterns = rule.get("detect", {}).get("patterns", [])

    result = {
        "id": rule_id,
        "domain": rule.get("_domain"),
        "title": rule.get("title", "")[:60],
        "confidence": rule.get("confidence", 0),
        "pattern_count": len(patterns),
        "patterns_valid": 0,
        "patterns_invalid": [],
        "tp_count": 0,
        "fp_count": 0,
        "tp_matches": [],
        "fp_matches": [],
        "precision": None,
        "verdict": "inconclusive",
    }

    # Step 1: Validate patterns
    valid_patterns = []
    for p in patterns:
        check = validate_pattern(p)
        if check["valid"]:
            result["patterns_valid"] += 1
            valid_patterns.append(p)
        else:
            result["patterns_invalid"].append({"pattern": p, "error": check["error"]})

    if result["patterns_valid"] == 0:
        result["verdict"] = "invalid"
        return result

    # Step 2: True positives — matches in vulnerable corpus
    tp_matches = run_rule_against_corpus(rule, corpus["vulnerable"])
    result["tp_matches"] = tp_matches
    result["tp_count"] = len(tp_matches)

    # Step 3: False positives — matches in safe corpus
    fp_matches = run_rule_against_corpus(rule, corpus["safe"])
    result["fp_matches"] = fp_matches
    result["fp_count"] = len(fp_matches)

    # Step 4: Calculate precision
    tp = result["tp_count"]
    fp = result["fp_count"]

    if tp + fp == 0:
        result["verdict"] = "no-matches"
        result["precision"] = None
    elif tp == 0 and fp > 0:
        result["precision"] = 0.0
        result["verdict"] = "fp-only"
    else:
        result["precision"] = tp / (tp + fp)
        result["verdict"] = "pass" if result["precision"] >= precision_gate else "fail"

    if verbose:
        if tp_matches:
            print(f"    TP ({tp}):")
            for m in tp_matches[:5]:
                print(f"      {m['file']}:{m['line']} [{m['pattern'][:40]}] → {m['text'][:60]}")
            if tp > 5:
                print(f"      ... and {tp - 5} more")
        if fp_matches:
            print(f"    FP ({fp}):")
            for m in fp_matches[:5]:
                print(f"      {m['file']}:{m['line']} [{m['pattern'][:40]}] → {m['text'][:60]}")
            if fp > 5:
                print(f"      ... and {fp - 5} more")

    return result


# ---------------------------------------------------------------------------
# Apply results to cve-rules.json
# ---------------------------------------------------------------------------

def apply_results(rules, test_results, precision_gate, dry_run=False):
    """Update rule statuses in cve-rules.json files."""
    now = datetime.now(timezone.utc).isoformat()
    results_by_id = {r["id"]: r for r in test_results}
    rules_by_id = {r["id"]: r for r in rules}
    files_modified = set()

    counts = {"active": 0, "needs-review": 0, "no-matches": 0, "invalid": 0}

    for result in test_results:
        verdict = result["verdict"]

        if verdict == "pass":
            new_status = "active"
            counts["active"] += 1
        elif verdict in ("fail", "fp-only"):
            new_status = "needs-review"
            counts["needs-review"] += 1
        elif verdict == "no-matches":
            new_status = "no-matches"
            counts["no-matches"] += 1
        elif verdict == "invalid":
            new_status = "invalid"
            counts["invalid"] += 1
        else:
            continue

        rule = rules_by_id.get(result["id"])
        if rule:
            files_modified.add(rule["_source_path"])

    if dry_run:
        return counts

    # Write changes
    for path in files_modified:
        with open(path) as f:
            all_rules = json.load(f)

        changed = False
        for i, r in enumerate(all_rules):
            if r["id"] not in results_by_id:
                continue
            result = results_by_id[r["id"]]
            verdict = result["verdict"]

            if verdict == "pass":
                all_rules[i]["status"] = "active"
            elif verdict in ("fail", "fp-only"):
                all_rules[i]["status"] = "needs-review"
            elif verdict == "no-matches":
                all_rules[i]["status"] = "no-matches"
            elif verdict == "invalid":
                all_rules[i]["status"] = "invalid"
            else:
                continue

            if result["precision"] is not None:
                all_rules[i]["test_precision"] = round(result["precision"], 3)
            all_rules[i]["tested_at"] = now
            changed = True

        if changed:
            with open(path, "w") as f:
                json.dump(all_rules, f, indent=2)
                f.write("\n")
            domain = os.path.basename(os.path.dirname(path))
            n = sum(1 for r in test_results
                    if rules_by_id.get(r["id"], {}).get("_source_path") == path)
            print(f"  Updated {domain}/cve-rules.json: {n} rules")

    return counts


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_results_table(test_results):
    """Print a summary table of test results."""
    print(f"\n{'ID':24s} {'Domain':14s} {'Pats':>4s} {'TP':>4s} {'FP':>4s} {'Prec':>6s} {'Verdict':12s}")
    print("-" * 76)

    for r in sorted(test_results, key=lambda x: (
        {"pass": 0, "fail": 1, "fp-only": 2, "no-matches": 3, "invalid": 4}.get(x["verdict"], 5),
        -(x["precision"] or 0),
    )):
        prec_str = f"{r['precision']:.1%}" if r["precision"] is not None else "—"
        verdict_icon = {
            "pass": "PASS",
            "fail": "FAIL",
            "fp-only": "FP-ONLY",
            "no-matches": "NO-MATCH",
            "invalid": "INVALID",
        }.get(r["verdict"], r["verdict"])

        print(f"{r['id']:24s} {r['domain']:14s} {r['pattern_count']:4d} "
              f"{r['tp_count']:4d} {r['fp_count']:4d} {prec_str:>6s} {verdict_icon:12s}")

    # Invalid patterns detail
    invalids = [r for r in test_results if r["patterns_invalid"]]
    if invalids:
        print(f"\n--- Invalid patterns ---")
        for r in invalids:
            for inv in r["patterns_invalid"]:
                print(f"  {r['id']}: {inv['error']} — {inv['pattern'][:60]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate LLM-generated CVE detection patterns against test corpus")
    parser.add_argument("--domain", type=str, default=None,
                        help="Only test rules from this domain")
    parser.add_argument("--precision", type=float, default=DEFAULT_PRECISION_GATE,
                        help=f"Precision gate for promotion (default: {DEFAULT_PRECISION_GATE})")
    parser.add_argument("--verbose", action="store_true",
                        help="Show individual match details")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview results without updating rule statuses")
    args = parser.parse_args()

    precision_gate = args.precision

    print("=" * 60)
    print("Sentinel Rule Tester")
    print("=" * 60)

    # Load corpus
    corpus = load_corpus()
    print(f"\nCorpus loaded:")
    print(f"  Vulnerable files: {len(corpus['vulnerable'])} "
          f"({sum(len(f['lines']) for f in corpus['vulnerable'])} lines)")
    print(f"  Safe files:       {len(corpus['safe'])} "
          f"({sum(len(f['lines']) for f in corpus['safe'])} lines)")

    # Load rules
    rules = load_untested_rules(args.domain)
    print(f"\nUntested rules: {len(rules)}")

    if not rules:
        print("No untested rules to validate. Done.")
        return

    # Domain breakdown
    domain_counts = {}
    for r in rules:
        d = r.get("_domain", "unknown")
        domain_counts[d] = domain_counts.get(d, 0) + 1
    print(f"  By domain: {', '.join(f'{d}={c}' for d, c in sorted(domain_counts.items()))}")

    # Test each rule
    print(f"\nPrecision gate: {precision_gate:.0%}")
    print(f"Testing...\n")

    test_results = []
    for i, rule in enumerate(rules):
        label = f"[{i+1}/{len(rules)}]"
        print(f"  {label} {rule['id']} ({rule.get('_domain')})...", end="", flush=True)
        result = test_rule(rule, corpus, precision_gate=precision_gate, verbose=args.verbose)
        test_results.append(result)

        prec = f"{result['precision']:.0%}" if result['precision'] is not None else "—"
        print(f" TP={result['tp_count']} FP={result['fp_count']} "
              f"prec={prec} → {result['verdict']}")

    # Results table
    print_results_table(test_results)

    # Summary
    verdicts = {}
    for r in test_results:
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1

    print(f"\n{'=' * 60}")
    print(f"Summary ({len(test_results)} rules tested):")
    print(f"  PASS (→ active):      {verdicts.get('pass', 0)}")
    print(f"  FAIL (→ needs-review): {verdicts.get('fail', 0)}")
    print(f"  FP-ONLY (→ needs-review): {verdicts.get('fp-only', 0)}")
    print(f"  NO-MATCH (→ no-matches): {verdicts.get('no-matches', 0)}")
    print(f"  INVALID:              {verdicts.get('invalid', 0)}")

    # Apply
    if args.dry_run:
        print(f"\n--- DRY RUN: no statuses updated ---")
    else:
        print(f"\n--- Applying results ---")
        counts = apply_results(rules, test_results, precision_gate)
        print(f"\nApplied: {counts['active']} active, "
              f"{counts['needs-review']} needs-review, "
              f"{counts['no-matches']} no-matches, "
              f"{counts['invalid']} invalid")

    # Next steps
    promoted = verdicts.get("pass", 0)
    if promoted > 0:
        print(f"\nNext: run 'python3 rag/indexer.py' to re-index promoted rules")

    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
