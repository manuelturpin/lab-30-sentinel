#!/usr/bin/env python3
"""
Coverage Scorer — Measure security rule coverage against standards.

Loads all rules from knowledge-base/domains/{domain}/{rules,cve-rules}.json
and checks coverage against standards in knowledge-base/standards/*.json.

Usage:
    python3 scripts/coverage-scorer.py              # Human-readable report
    python3 scripts/coverage-scorer.py --json       # JSON output only
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Set, Any, Optional


def load_json_safe(filepath: str) -> Any:
    """Load JSON file, handle both array and object with 'rules' key."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            # If it's a dict with 'rules' key, extract the rules array
            if isinstance(data, dict) and 'rules' in data:
                return data['rules']
            return data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Warning: Could not load {filepath}: {e}", file=sys.stderr)
        return []


def load_all_rules(kb_path: str) -> tuple[List[Dict], int, int, int]:
    """
    Load all rules from domains/*/rules.json and domains/*/cve-rules.json.
    Returns (all_rules, manual_count, auto_active_count, auto_template_count).
    """
    all_rules = []
    manual_count = 0
    auto_active_count = 0
    auto_template_count = 0

    domains_dir = os.path.join(kb_path, 'domains')
    if not os.path.isdir(domains_dir):
        print(f"Warning: {domains_dir} not found", file=sys.stderr)
        return all_rules, 0, 0, 0

    for domain in sorted(os.listdir(domains_dir)):
        domain_path = os.path.join(domains_dir, domain)
        if not os.path.isdir(domain_path):
            continue

        # Load manual rules
        rules_file = os.path.join(domain_path, 'rules.json')
        if os.path.exists(rules_file):
            rules = load_json_safe(rules_file)
            if isinstance(rules, list):
                all_rules.extend(rules)
                manual_count += len(rules)

        # Load CVE rules (auto-generated)
        cve_file = os.path.join(domain_path, 'cve-rules.json')
        if os.path.exists(cve_file):
            cve_rules = load_json_safe(cve_file)
            if isinstance(cve_rules, list):
                all_rules.extend(cve_rules)
                for rule in cve_rules:
                    # Check if rule has patterns (active) or is template-only
                    patterns = rule.get('detect', {}).get('patterns', [])
                    if patterns:
                        auto_active_count += 1
                    else:
                        auto_template_count += 1

    return all_rules, manual_count, auto_active_count, auto_template_count


def load_standards(kb_path: str) -> Dict[str, Dict[str, Any]]:
    """Load all standards files."""
    standards = {}
    standards_dir = os.path.join(kb_path, 'standards')

    if not os.path.isdir(standards_dir):
        print(f"Warning: {standards_dir} not found", file=sys.stderr)
        return standards

    for filename in sorted(os.listdir(standards_dir)):
        if not filename.endswith('.json'):
            continue

        filepath = os.path.join(standards_dir, filename)
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            # Extract standard name and items
            standard_name = data.get('standard', filename.replace('.json', ''))
            items = []

            # Handle different structures
            if 'categories' in data:
                items = data['categories']
            elif 'weaknesses' in data:
                items = data['weaknesses']
            elif 'tactics' in data:
                items = data['tactics']
            elif 'techniques' in data:
                items = data['techniques']

            # Normalize item IDs
            normalized_items = {}
            for item in items:
                item_id = item.get('id', '')
                if item_id:
                    normalized_items[item_id.upper()] = item

            standards[filename] = {
                'name': standard_name,
                'items': normalized_items,
                'item_list': list(normalized_items.keys())
            }
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Warning: Could not load standard {filename}: {e}", file=sys.stderr)

    return standards


def extract_standard_refs(rule: Dict) -> Set[str]:
    """
    Extract all standard references from a rule.
    Returns a set of normalized standard IDs.
    Handles formats like: "CWE-79", "OWASP-A01:2025", "A01:2025", "AML.TA0000", etc.
    """
    refs = set()

    # OWASP field (direct)
    if 'owasp' in rule:
        val = rule['owasp']
        if isinstance(val, str) and val:
            refs.add(val.upper())
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    refs.add(v.upper())

    # CWE field (direct)
    if 'cwe' in rule:
        val = rule['cwe']
        if isinstance(val, str) and val:
            refs.add(val.upper())
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    refs.add(v.upper())

    # MITRE ATLAS field (direct)
    if 'mitre_atlas' in rule:
        val = rule['mitre_atlas']
        if isinstance(val, str) and val:
            refs.add(val.upper())
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    refs.add(v.upper())

    # Generic standards field — can contain mixed references
    if 'standards' in rule:
        val = rule['standards']
        if isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    refs.add(v.upper())
                elif isinstance(v, dict) and 'id' in v:
                    refs.add(v['id'].upper())

    return refs


def normalize_standard_id(std_id: str) -> str:
    """
    Normalize a standard ID for matching.
    Strips prefixes like 'OWASP-', 'GDPR-', etc.
    E.g., "OWASP-A01:2025" -> "A01:2025", "CWE-79" -> "CWE-79", "AML.TA0000" -> "AML.TA0000"
    """
    std_id = std_id.upper().strip()
    # Remove prefixes
    if std_id.startswith('OWASP-'):
        return std_id[6:]  # Remove 'OWASP-'
    if std_id.startswith('GDPR-'):
        return std_id[5:]  # Keep 'GDPR-' in place, just uppercase
    return std_id


def calculate_coverage(rules: List[Dict], standards: Dict) -> Dict[str, Any]:
    """
    Calculate coverage for each standard.
    Returns dict mapping standard filename to coverage info.
    """
    coverage = {}

    # Build inverted index: normalized_standard_id -> list of rules covering it
    coverage_map = {}

    for rule in rules:
        refs = extract_standard_refs(rule)

        for ref in refs:
            normalized = normalize_standard_id(ref)
            if normalized not in coverage_map:
                coverage_map[normalized] = []
            coverage_map[normalized].append(rule.get('id', 'unknown'))

    # Calculate coverage per standard file
    for filename, std_data in standards.items():
        items = std_data['item_list']
        covered = []
        gaps = []

        for item_id in items:
            # Check if item is covered by any rule
            # Use normalized matching
            item_id_normalized = normalize_standard_id(item_id)
            if item_id_normalized in coverage_map:
                covered.append(item_id)
            else:
                gaps.append({'id': item_id, 'name': std_data['items'].get(item_id.upper(), {}).get('name', '')})

        total = len(items)
        covered_count = len(covered)
        pct = int((covered_count / total * 100) if total > 0 else 0)

        coverage[filename] = {
            'standard': std_data['name'],
            'total': total,
            'covered': covered_count,
            'pct': pct,
            'gaps': gaps
        }

    return coverage


def format_human_output(total_rules: int, manual: int, auto_active: int, auto_template: int,
                        coverage: Dict[str, Any]) -> str:
    """Format human-readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append("Sentinel Coverage Report")
    lines.append("=" * 60)
    lines.append("")

    lines.append(f"Total rules: {total_rules}")
    lines.append(f"  Manual (curated):     {manual}")
    lines.append(f"  Auto (with patterns): {auto_active}")
    lines.append(f"  Auto (template only): {auto_template}")
    lines.append("")

    # Sort by coverage percentage (descending)
    sorted_coverage = sorted(coverage.items(), key=lambda x: (x[1]['pct'], x[0]), reverse=True)

    overall_total = 0
    overall_covered = 0

    for filename, data in sorted_coverage:
        overall_total += data['total']
        overall_covered += data['covered']

        pct = data['pct']
        total = data['total']
        covered = data['covered']
        standard_name = data['standard']
        gaps = data['gaps']

        # Status indicator
        if pct == 100:
            status = "[OK]"
        elif pct >= 80:
            status = "[GOOD]"
        elif pct >= 60:
            status = "[WARN]"
        else:
            status = "[GAP]"

        lines.append(f"{status} {standard_name}: {covered}/{total} ({pct}%)")

        # Show gaps
        if gaps:
            gaps_to_show = gaps[:5]
            for gap in gaps_to_show:
                gap_name = gap.get('name', '')
                if gap_name:
                    lines.append(f"      Missing: {gap['id']} — {gap_name}")
                else:
                    lines.append(f"      Missing: {gap['id']}")

            if len(gaps) > 5:
                remaining = len(gaps) - 5
                lines.append(f"      ...and {remaining} more")

    lines.append("")

    overall_pct = int((overall_covered / overall_total * 100) if overall_total > 0 else 0)
    lines.append(f"Overall coverage: {overall_pct}%")
    lines.append("=" * 60)

    return "\n".join(lines)


def format_json_output(total_rules: int, manual: int, auto_active: int, auto_template: int,
                       coverage: Dict[str, Any]) -> str:
    """Format JSON output."""
    overall_total = sum(c['total'] for c in coverage.values())
    overall_covered = sum(c['covered'] for c in coverage.values())
    overall_pct = int((overall_covered / overall_total * 100) if overall_total > 0 else 0)

    output = {
        'total_rules': total_rules,
        'quality': {
            'manual': manual,
            'auto_active': auto_active,
            'auto_template': auto_template
        },
        'coverage': [
            {
                'standard': data['standard'],
                'total': data['total'],
                'covered': data['covered'],
                'pct': data['pct'],
                'gaps': [{'id': g['id'], 'name': g.get('name', '')} for g in data['gaps']]
            }
            for data in sorted(coverage.values(), key=lambda x: x['standard'])
        ],
        'overall_pct': overall_pct
    }

    return json.dumps(output, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Measure Sentinel KB rule coverage vs standards')
    parser.add_argument('--json', action='store_true', help='Output JSON format only')
    args = parser.parse_args()

    # Find knowledge base path (relative to script location)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    kb_path = os.path.join(os.path.dirname(script_dir), 'knowledge-base')

    if not os.path.isdir(kb_path):
        print(f"Error: knowledge-base directory not found at {kb_path}", file=sys.stderr)
        sys.exit(1)

    # Load data
    rules, manual, auto_active, auto_template = load_all_rules(kb_path)
    standards = load_standards(kb_path)

    if not rules:
        print("Error: No rules found", file=sys.stderr)
        sys.exit(1)

    if not standards:
        print("Error: No standards found", file=sys.stderr)
        sys.exit(1)

    # Calculate coverage
    coverage = calculate_coverage(rules, standards)

    # Output
    if args.json:
        print(format_json_output(len(rules), manual, auto_active, auto_template, coverage))
    else:
        print(format_human_output(len(rules), manual, auto_active, auto_template, coverage))


if __name__ == '__main__':
    main()
