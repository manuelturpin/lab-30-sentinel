#!/usr/bin/env python3
"""
Sentinel Feedback Loop — FP/TP ingestion, confidence scoring, cross-domain propagation.

Processes scan feedback to improve rule quality over time.

Subcommands:
    ingest     Record TP/FP verdicts from scan results
    seed       Auto-seed feedback from rule-tester.py results (Phase 3 data)
    score      Recalculate confidence scores from accumulated feedback
    propagate  Share validated patterns across domains with same CWE
    report     Show feedback stats and confidence changes

Usage:
    python3 scripts/feedback-loop.py ingest --rule CVE-XXX --verdict tp --file src/app.js --line 42
    python3 scripts/feedback-loop.py seed                    # Seed from Phase 3 test results
    python3 scripts/feedback-loop.py score                   # Recalculate confidence
    python3 scripts/feedback-loop.py score --dry-run         # Preview changes
    python3 scripts/feedback-loop.py propagate               # Cross-domain propagation
    python3 scripts/feedback-loop.py propagate --apply       # Apply propagation
    python3 scripts/feedback-loop.py report                  # Show stats
"""
from __future__ import annotations


import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
KB_DIR = os.path.join(PROJECT_ROOT, "knowledge-base")
DOMAINS_DIR = os.path.join(KB_DIR, "domains")
FEEDBACK_PATH = os.path.join(KB_DIR, "feedback", "feedback.json")
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "tests", "fixtures")
VULN_APP_DIR = os.path.join(PROJECT_ROOT, "tests", "vulnerable-app", "src")

# Confidence thresholds
MIN_FEEDBACK_FOR_UPDATE = 3     # Minimum feedback entries before adjusting confidence
DEMOTE_THRESHOLD = 0.3          # Demote to "needs-review" if confidence drops below this
PROMOTE_THRESHOLD = 0.7         # Promote to "active" if confidence rises above this
PROPAGATE_MIN_CONFIDENCE = 0.7  # Only propagate patterns from rules above this confidence


# ===========================================================================
# Feedback storage
# ===========================================================================

def load_feedback():
    """Load feedback entries from disk."""
    if not os.path.exists(FEEDBACK_PATH):
        return {"version": 1, "entries": []}
    with open(FEEDBACK_PATH) as f:
        return json.load(f)


def save_feedback(data):
    """Save feedback entries to disk."""
    os.makedirs(os.path.dirname(FEEDBACK_PATH), exist_ok=True)
    with open(FEEDBACK_PATH, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


# ===========================================================================
# Rule loading
# ===========================================================================

def load_all_cve_rules():
    """Load all CVE rules across all domains."""
    rules = {}
    for path in sorted(glob.glob(os.path.join(DOMAINS_DIR, "*", "cve-rules.json"))):
        domain = os.path.basename(os.path.dirname(path))
        with open(path) as f:
            domain_rules = json.load(f)
        for r in domain_rules:
            r["_source_path"] = path
            r["_domain"] = domain
            rules[r["id"]] = r
    return rules


def load_domain_rules():
    """Load curated domain rules (rules.json, not cve-rules.json)."""
    rules = {}
    for path in sorted(glob.glob(os.path.join(DOMAINS_DIR, "*", "rules.json"))):
        domain = os.path.basename(os.path.dirname(path))
        with open(path) as f:
            domain_rules = json.load(f)
        for r in domain_rules:
            r["_source_path"] = path
            r["_domain"] = domain
            rules[r["id"]] = r
    return rules


def save_rules_to_file(path, rules_list):
    """Save rules list back to a cve-rules.json file."""
    # Strip internal fields
    clean = []
    for r in rules_list:
        clean.append({k: v for k, v in r.items() if not k.startswith("_")})
    with open(path, "w") as f:
        json.dump(clean, f, indent=2)
        f.write("\n")


# ===========================================================================
# Subcommand: ingest
# ===========================================================================

def cmd_ingest(args):
    """Record a single TP/FP feedback entry."""
    feedback = load_feedback()

    entry = {
        "rule_id": args.rule,
        "verdict": args.verdict,
        "file": args.file or "",
        "line": args.line or 0,
        "pattern": args.pattern or "",
        "context": args.context or "",
        "project": args.project or "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    feedback["entries"].append(entry)
    save_feedback(feedback)

    total = len(feedback["entries"])
    print(f"Recorded {args.verdict.upper()} for {args.rule} ({total} total entries)")


# ===========================================================================
# Subcommand: seed
# ===========================================================================

def cmd_seed(args):
    """Auto-seed feedback from rule-tester.py Phase 3 test results.

    Re-runs the pattern matching against the test corpus and records
    each match as TP (vulnerable corpus) or FP (safe corpus).
    """
    feedback = load_feedback()
    existing_count = len(feedback["entries"])

    rules = load_all_cve_rules()
    now = datetime.now(timezone.utc).isoformat()

    # Load corpus files
    vuln_files = _load_files(os.path.join(FIXTURES_DIR, "vulnerable"))
    vuln_files += _load_files(VULN_APP_DIR)
    safe_files = _load_files(os.path.join(FIXTURES_DIR, "safe"))

    added = 0
    # Only seed for rules that have been tested (have test_precision)
    for rule_id, rule in rules.items():
        if "test_precision" not in rule:
            continue

        patterns = rule.get("detect", {}).get("patterns", [])
        negative_patterns = rule.get("detect", {}).get("negative_patterns", [])
        file_types = rule.get("detect", {}).get("file_types", [])

        # Scan vulnerable files → TP
        for file_info in vuln_files:
            if not _file_matches(file_info["filename"], file_types):
                continue
            for line_num, line in enumerate(file_info["lines"], 1):
                for pattern in patterns:
                    try:
                        if re.search(pattern, line) and not _is_mitigated(line, negative_patterns):
                            feedback["entries"].append({
                                "rule_id": rule_id,
                                "verdict": "tp",
                                "file": file_info["filename"],
                                "line": line_num,
                                "pattern": pattern,
                                "context": line.strip()[:120],
                                "project": "sentinel-fixtures",
                                "timestamp": now,
                            })
                            added += 1
                    except re.error:
                        pass

        # Scan safe files → FP
        for file_info in safe_files:
            if not _file_matches(file_info["filename"], file_types):
                continue
            for line_num, line in enumerate(file_info["lines"], 1):
                for pattern in patterns:
                    try:
                        if re.search(pattern, line) and not _is_mitigated(line, negative_patterns):
                            feedback["entries"].append({
                                "rule_id": rule_id,
                                "verdict": "fp",
                                "file": file_info["filename"],
                                "line": line_num,
                                "pattern": pattern,
                                "context": line.strip()[:120],
                                "project": "sentinel-fixtures",
                                "timestamp": now,
                            })
                            added += 1
                    except re.error:
                        pass

    save_feedback(feedback)
    print(f"Seeded {added} feedback entries from test corpus")
    print(f"Total entries: {len(feedback['entries'])} (was {existing_count})")


def _load_files(directory):
    """Load source files from directory."""
    files = []
    if not os.path.isdir(directory):
        return files
    for root, _, filenames in os.walk(directory):
        for fname in filenames:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                files.append({"filename": fname, "lines": content.splitlines()})
            except IOError:
                pass
    return files


def _file_matches(filename, file_types):
    """Check if filename matches file_types globs."""
    if not file_types:
        return True
    for ft in file_types:
        if ft.startswith("*.") and filename.endswith(ft[1:]):
            return True
    return False


def _is_mitigated(line, negative_patterns):
    """Check if line matches any negative pattern."""
    for neg in negative_patterns:
        try:
            if re.search(neg, line):
                return True
        except re.error:
            pass
    return False


# ===========================================================================
# Subcommand: score
# ===========================================================================

def cmd_score(args):
    """Recalculate confidence scores from accumulated feedback."""
    feedback = load_feedback()
    rules = load_all_cve_rules()

    if not feedback["entries"]:
        print("No feedback entries. Run 'seed' or 'ingest' first.")
        return

    # Aggregate feedback per rule
    rule_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "patterns": defaultdict(lambda: {"tp": 0, "fp": 0})})

    for entry in feedback["entries"]:
        rid = entry["rule_id"]
        verdict = entry["verdict"]
        pattern = entry.get("pattern", "")

        if verdict == "tp":
            rule_stats[rid]["tp"] += 1
            if pattern:
                rule_stats[rid]["patterns"][pattern]["tp"] += 1
        elif verdict == "fp":
            rule_stats[rid]["fp"] += 1
            if pattern:
                rule_stats[rid]["patterns"][pattern]["fp"] += 1

    # Calculate new confidence scores
    updates = []
    for rid, stats in sorted(rule_stats.items()):
        if rid not in rules:
            continue

        rule = rules[rid]
        old_confidence = rule.get("confidence", 0.5)
        old_status = rule.get("status", "unknown")
        tp = stats["tp"]
        fp = stats["fp"]
        total = tp + fp

        if total < MIN_FEEDBACK_FOR_UPDATE:
            continue

        # Bayesian confidence: Laplace-smoothed precision weighted by base confidence
        # factor = (tp + 1) / (tp + fp + 2)  → converges to precision with more data
        bayesian_factor = (tp + 1) / (tp + fp + 2)

        # Blend: 30% base confidence + 70% empirical
        new_confidence = round(0.3 * old_confidence + 0.7 * bayesian_factor, 3)

        # Determine status change
        new_status = old_status
        if new_confidence < DEMOTE_THRESHOLD and old_status == "active":
            new_status = "needs-review"
        elif new_confidence >= PROMOTE_THRESHOLD and old_status in ("needs-review", "no-matches"):
            new_status = "active"

        # Identify worst patterns (FP-heavy)
        worst_patterns = []
        for pat, pat_stats in stats["patterns"].items():
            if pat_stats["fp"] > 0:
                pat_prec = pat_stats["tp"] / (pat_stats["tp"] + pat_stats["fp"])
                if pat_prec < 0.5:
                    worst_patterns.append({
                        "pattern": pat[:60],
                        "tp": pat_stats["tp"],
                        "fp": pat_stats["fp"],
                        "precision": round(pat_prec, 2),
                    })

        updates.append({
            "rule_id": rid,
            "domain": rule.get("_domain"),
            "old_confidence": old_confidence,
            "new_confidence": new_confidence,
            "old_status": old_status,
            "new_status": new_status,
            "tp": tp,
            "fp": fp,
            "precision": round(tp / total, 3),
            "worst_patterns": worst_patterns,
            "source_path": rule["_source_path"],
        })

    # Print results
    print(f"\n{'Rule ID':24s} {'Domain':14s} {'TP':>4s} {'FP':>4s} {'Prec':>6s} "
          f"{'Old Conf':>8s} {'New Conf':>8s} {'Status Change':20s}")
    print("-" * 100)

    for u in updates:
        status_change = ""
        if u["old_status"] != u["new_status"]:
            status_change = f"{u['old_status']} → {u['new_status']}"

        print(f"{u['rule_id']:24s} {u['domain']:14s} {u['tp']:4d} {u['fp']:4d} "
              f"{u['precision']:6.1%} {u['old_confidence']:8.3f} {u['new_confidence']:8.3f} "
              f"{status_change:20s}")

        if u["worst_patterns"]:
            for wp in u["worst_patterns"]:
                print(f"  {'':24s} FP-heavy: {wp['pattern']} "
                      f"(tp={wp['tp']}, fp={wp['fp']}, prec={wp['precision']:.0%})")

    # Apply
    if args.dry_run:
        print(f"\n--- DRY RUN: no changes applied ---")
        return

    files_to_update = defaultdict(list)
    for u in updates:
        files_to_update[u["source_path"]].append(u)

    for path, path_updates in files_to_update.items():
        with open(path) as f:
            all_rules = json.load(f)

        updates_by_id = {u["rule_id"]: u for u in path_updates}
        for i, r in enumerate(all_rules):
            if r["id"] in updates_by_id:
                u = updates_by_id[r["id"]]
                all_rules[i]["confidence"] = u["new_confidence"]
                if u["old_status"] != u["new_status"]:
                    all_rules[i]["status"] = u["new_status"]
                all_rules[i]["feedback_tp"] = u["tp"]
                all_rules[i]["feedback_fp"] = u["fp"]
                all_rules[i]["feedback_precision"] = u["precision"]
                all_rules[i]["confidence_updated_at"] = datetime.now(timezone.utc).isoformat()

        with open(path, "w") as f:
            json.dump(all_rules, f, indent=2)
            f.write("\n")

        domain = os.path.basename(os.path.dirname(path))
        print(f"  Updated {domain}/cve-rules.json: {len(path_updates)} rules")

    changed_status = sum(1 for u in updates if u["old_status"] != u["new_status"])
    print(f"\nApplied: {len(updates)} confidence updates, {changed_status} status changes")


# ===========================================================================
# Subcommand: propagate
# ===========================================================================

def cmd_propagate(args):
    """Find validated patterns and propagate across domains sharing the same CWE."""
    cve_rules = load_all_cve_rules()
    domain_rules = load_domain_rules()
    all_rules = {**domain_rules, **cve_rules}

    # Step 1: Collect active rules grouped by CWE
    cwe_patterns = defaultdict(list)  # CWE -> list of (rule_id, domain, patterns, confidence)

    for rid, rule in all_rules.items():
        if rule.get("status") not in ("active", None):
            # Domain rules (rules.json) don't have status; CVE rules need "active"
            if "_source_path" in rule and "cve-rules" in rule["_source_path"]:
                continue

        confidence = rule.get("confidence", 0.7)
        if confidence < PROPAGATE_MIN_CONFIDENCE:
            continue

        patterns = rule.get("detect", {}).get("patterns", [])
        if not patterns:
            continue

        cwes = [s for s in rule.get("standards", []) if s.startswith("CWE-")]
        domain = rule.get("_domain", "unknown")

        for cwe in cwes:
            cwe_patterns[cwe].append({
                "rule_id": rid,
                "domain": domain,
                "patterns": patterns,
                "negative_patterns": rule.get("detect", {}).get("negative_patterns", []),
                "file_types": rule.get("detect", {}).get("file_types", []),
                "confidence": confidence,
            })

    # Step 2: Find propagation opportunities
    # A CWE with rules in multiple domains where some domains have more patterns
    suggestions = []

    for cwe, sources in sorted(cwe_patterns.items()):
        if len(sources) < 2:
            continue

        # Group by domain
        by_domain = defaultdict(list)
        for s in sources:
            by_domain[s["domain"]].append(s)

        if len(by_domain) < 2:
            continue

        # Find the richest source (most patterns, highest confidence)
        domain_scores = {}
        for domain, domain_sources in by_domain.items():
            total_patterns = sum(len(s["patterns"]) for s in domain_sources)
            max_confidence = max(s["confidence"] for s in domain_sources)
            domain_scores[domain] = (total_patterns, max_confidence)

        best_domain = max(domain_scores, key=lambda d: domain_scores[d])
        best_sources = by_domain[best_domain]

        # Collect all unique patterns from the best domain
        best_patterns = set()
        for s in best_sources:
            best_patterns.update(s["patterns"])

        # Check other domains for missing patterns
        for target_domain, target_sources in by_domain.items():
            if target_domain == best_domain:
                continue

            target_patterns = set()
            for s in target_sources:
                target_patterns.update(s["patterns"])

            new_patterns = best_patterns - target_patterns
            if new_patterns:
                suggestions.append({
                    "cwe": cwe,
                    "source_domain": best_domain,
                    "target_domain": target_domain,
                    "target_rules": [s["rule_id"] for s in target_sources],
                    "new_patterns": sorted(new_patterns),
                    "source_confidence": domain_scores[best_domain][1],
                })

    # Print suggestions
    if not suggestions:
        print("No cross-domain propagation opportunities found.")
        return

    print(f"\n{'CWE':12s} {'From':14s} {'To':14s} {'New Patterns':>12s} {'Conf':>6s}")
    print("-" * 64)

    for s in suggestions:
        print(f"{s['cwe']:12s} {s['source_domain']:14s} {s['target_domain']:14s} "
              f"{len(s['new_patterns']):12d} {s['source_confidence']:6.2f}")
        for p in s["new_patterns"][:5]:
            print(f"  {'':12s} + {p[:70]}")
        if len(s["new_patterns"]) > 5:
            print(f"  {'':12s} ... and {len(s['new_patterns']) - 5} more")
        print(f"  {'':12s} Target rules: {', '.join(s['target_rules'][:3])}")

    print(f"\nTotal: {len(suggestions)} propagation opportunities, "
          f"{sum(len(s['new_patterns']) for s in suggestions)} new patterns")

    if not args.apply:
        print("\n--- Preview only. Use --apply to propagate patterns ---")
        return

    # Apply propagation
    applied = 0
    files_modified = set()

    for s in suggestions:
        for target_rid in s["target_rules"]:
            if target_rid not in all_rules:
                continue
            rule = all_rules[target_rid]
            current_patterns = rule.get("detect", {}).get("patterns", [])
            added = [p for p in s["new_patterns"] if p not in current_patterns]
            if not added:
                continue

            rule["detect"]["patterns"].extend(added)
            rule["propagated_from"] = s["source_domain"]
            rule["propagated_at"] = datetime.now(timezone.utc).isoformat()
            rule["propagated_patterns"] = added
            files_modified.add(rule["_source_path"])
            applied += len(added)

    # Save modified files
    for path in files_modified:
        with open(path) as f:
            all_file_rules = json.load(f)

        for i, r in enumerate(all_file_rules):
            if r["id"] in all_rules:
                updated = all_rules[r["id"]]
                if "propagated_from" in updated:
                    all_file_rules[i]["detect"] = {k: v for k, v in updated["detect"].items()
                                                    if not k.startswith("_")}
                    all_file_rules[i]["propagated_from"] = updated["propagated_from"]
                    all_file_rules[i]["propagated_at"] = updated["propagated_at"]
                    all_file_rules[i]["propagated_patterns"] = updated["propagated_patterns"]

        with open(path, "w") as f:
            json.dump(all_file_rules, f, indent=2)
            f.write("\n")

        domain = os.path.basename(os.path.dirname(path))
        print(f"  Updated {domain}/cve-rules.json")

    print(f"\nApplied {applied} propagated patterns across {len(files_modified)} files")


# ===========================================================================
# Subcommand: report
# ===========================================================================

def cmd_report(args):
    """Show feedback statistics and rule health."""
    feedback = load_feedback()
    rules = load_all_cve_rules()

    entries = feedback.get("entries", [])
    if not entries:
        print("No feedback entries yet. Run 'seed' or 'ingest' first.")
        return

    # Overall stats
    verdicts = Counter(e["verdict"] for e in entries)
    projects = Counter(e.get("project", "unknown") for e in entries)
    rules_with_feedback = Counter(e["rule_id"] for e in entries)

    print("=" * 60)
    print("Sentinel Feedback Report")
    print("=" * 60)

    print(f"\nTotal entries: {len(entries)}")
    print(f"  True positives:  {verdicts.get('tp', 0)}")
    print(f"  False positives: {verdicts.get('fp', 0)}")
    overall_prec = verdicts["tp"] / (verdicts["tp"] + verdicts["fp"]) if verdicts["tp"] + verdicts["fp"] > 0 else 0
    print(f"  Overall precision: {overall_prec:.1%}")

    print(f"\nRules with feedback: {len(rules_with_feedback)}")
    print(f"Projects: {', '.join(f'{p}={c}' for p, c in projects.most_common(5))}")

    # Per-rule breakdown
    print(f"\n{'Rule ID':24s} {'Domain':14s} {'TP':>4s} {'FP':>4s} {'Prec':>6s} {'Conf':>6s} {'Status':12s}")
    print("-" * 80)

    rule_stats = defaultdict(lambda: {"tp": 0, "fp": 0})
    for e in entries:
        rule_stats[e["rule_id"]][e["verdict"]] += 1

    for rid, stats in sorted(rule_stats.items(), key=lambda x: -(x[1]["tp"] + x[1]["fp"])):
        rule = rules.get(rid, {})
        tp = stats.get("tp", 0)
        fp = stats.get("fp", 0)
        total = tp + fp
        prec = tp / total if total > 0 else 0
        conf = rule.get("confidence", 0)
        domain = rule.get("_domain", "?")
        status = rule.get("status", "?")

        print(f"{rid:24s} {domain:14s} {tp:4d} {fp:4d} {prec:6.1%} {conf:6.2f} {status:12s}")

    # Pattern-level stats (top FP patterns)
    pattern_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "rules": set()})
    for e in entries:
        if e.get("pattern"):
            pat = e["pattern"][:80]
            pattern_stats[pat][e["verdict"]] += 1
            pattern_stats[pat]["rules"].add(e["rule_id"])

    fp_heavy = [(pat, s) for pat, s in pattern_stats.items()
                if s["fp"] > 0 and s["tp"] / (s["tp"] + s["fp"]) < 0.5]

    if fp_heavy:
        print(f"\n--- FP-Heavy Patterns (precision < 50%) ---")
        for pat, s in sorted(fp_heavy, key=lambda x: x[1]["fp"], reverse=True)[:10]:
            prec = s["tp"] / (s["tp"] + s["fp"])
            print(f"  {pat[:60]:60s} tp={s['tp']} fp={s['fp']} prec={prec:.0%}")

    print(f"\n{'=' * 60}")


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Feedback Loop — FP/TP ingestion, confidence scoring, cross-domain propagation")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # ingest
    p_ingest = subparsers.add_parser("ingest", help="Record a TP/FP feedback entry")
    p_ingest.add_argument("--rule", required=True, help="Rule ID (e.g., CVE-2021-22054)")
    p_ingest.add_argument("--verdict", required=True, choices=["tp", "fp"], help="True positive or false positive")
    p_ingest.add_argument("--file", help="Source file where match occurred")
    p_ingest.add_argument("--line", type=int, help="Line number")
    p_ingest.add_argument("--pattern", help="The specific regex pattern that matched")
    p_ingest.add_argument("--context", help="Matched line content")
    p_ingest.add_argument("--project", help="Project name")

    # seed
    p_seed = subparsers.add_parser("seed", help="Auto-seed feedback from rule-tester.py results")

    # score
    p_score = subparsers.add_parser("score", help="Recalculate confidence from feedback")
    p_score.add_argument("--dry-run", action="store_true", help="Preview without applying")

    # propagate
    p_propagate = subparsers.add_parser("propagate", help="Cross-domain pattern propagation")
    p_propagate.add_argument("--apply", action="store_true", help="Apply propagation (default: preview)")

    # report
    p_report = subparsers.add_parser("report", help="Show feedback statistics")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    commands = {
        "ingest": cmd_ingest,
        "seed": cmd_seed,
        "score": cmd_score,
        "propagate": cmd_propagate,
        "report": cmd_report,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
