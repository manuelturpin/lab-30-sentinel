# Design: sentinel-security evolve — Threat Intelligence Pipeline

**Date**: 2026-04-13
**Status**: Approved
**Scope**: Add `evolve` mode to `/sentinel-security` for autonomous threat intel evolution

---

## Problem

sentinel-evolve optimizes Claude Code tooling (hooks, model tiers, LSP, features) but sentinel-security has no autonomous pipeline to evolve its **detection rules and threat coverage**. Specifically:

- ~1000 auto-generated CVE rules have empty `detect.patterns[]` — they exist but detect nothing
- Standards (OWASP, CWE, MITRE) are static JSON files, never auto-synced
- No CISA KEV integration — missing actively exploited vulnerabilities
- No feedback loop: scan results (false positives, confirmed findings) never improve rules
- No cross-domain intelligence: supply-chain vulns don't propagate to web-app rules
- No measurement of detection coverage vs standards

## Decision

**Approach**: Linear pipeline inside sentinel-security (mode `evolve`), mirroring sentinel-evolve's structure but focused on threat intelligence instead of Claude Code features.

**Separation of concerns**:

| Skill | Evolves | Sources | Report |
|-------|---------|---------|--------|
| `/sentinel-evolve` | Claude Code tooling (hooks, features, model tiers) | GitHub releases, changelogs | EIR |
| `/sentinel-security evolve` | Detection rules, patterns, threat coverage | NVD, OSV, EPSS, KEV, ATT&CK, OWASP | TIR |

sentinel-evolve never touches security content. sentinel-security evolve never touches Claude Code tooling.

---

## Invocation

```
/sentinel-security evolve        # Full pipeline (sync → gen → test → score → report)
/sentinel-security evolve sync   # Fetch all threat intel sources
/sentinel-security evolve gen    # LLM-generate patterns for empty CVE rules
/sentinel-security evolve test   # Validate rules against vulnerable-app
/sentinel-security evolve score  # Measure coverage vs standards
/sentinel-security evolve report # Generate TIR (Threat Intelligence Report)
```

When invoked without sub-mode, runs all 6 steps sequentially. Each sub-mode can run independently.

---

## Pipeline Steps

### Step 1: `sync` — Fetch Threat Intel Sources

Extends existing `cve-sync.py` with new sources. Does NOT replace — adds to.

**Current sources (preserved):**

| Source | Endpoint | Auth | Rate Limit | Frequency |
|--------|----------|------|-----------|-----------|
| NVD API v2 | `nvd.nist.gov/rest/json/cves/2.0` | API key (free) | 50 req/30s | Daily |
| OSV API | `api.osv.dev/v1/query` | None | Unlimited | Real-time |
| GitHub Advisories | GitHub GraphQL | GITHUB_TOKEN | 5000/h | Daily |
| EPSS | `api.first.org/data/v1/epss` | None | Unlimited | Daily |

**New sources (added):**

| Source | Endpoint | Auth | Rate Limit | Frequency |
|--------|----------|------|-----------|-----------|
| CISA KEV | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | None | Real-time |
| MITRE ATT&CK | `github.com/mitre-att&ck/attack-stix-data` (STIX 2.1) | None | GitHub API | Quarterly |
| OWASP Top 10 | GitHub releases API per repo | GITHUB_TOKEN | 5000/h | Yearly |
| MITRE ATLAS | `atlas.mitre.org` JSON data | None | None | Bi-annual |

**Output**: JSON cache files in `knowledge-base/cve-feed/` and `knowledge-base/standards/`.

**New cache files**:
- `knowledge-base/cve-feed/kev-catalog.json` — CISA Known Exploited Vulnerabilities
- `knowledge-base/standards/mitre-attack.json` — ATT&CK techniques (simplified from STIX)

**Existing files auto-synced** (were previously static):
- `knowledge-base/standards/owasp-*.json` — fetched from GitHub releases
- `knowledge-base/standards/cwe-top25.json` — fetched from MITRE
- `knowledge-base/standards/mitre-atlas.json` — fetched from ATLAS

**Implementation**: Extend `scripts/cve-sync.py` with new source classes following the same pattern (fetch → parse → cache → report).

### Step 2: `gen` — LLM Pattern Generation

The core innovation. Transforms empty CVE rule templates into active detection rules using Claude.

**Input**: CVE rules where `detect.patterns` is empty (`knowledge-base/domains/*/cve-rules.json`)

**Process**:
1. Load all CVE rules with `detect.patterns: []`
2. Prioritize: KEV = true first, then CVSS >= 9.0, then CVSS >= 7.0
3. For each rule (max 50 per run to control cost):
   - Send to Claude: CVE description + domain + affected package + CWE
   - Claude generates: `detect.patterns[]`, `detect.file_types[]`, `detect.negative_patterns[]`, `detect.exclude[]`
   - Claude assigns `confidence: 0.0-1.0` based on pattern specificity
4. Write patterns back to `cve-rules.json`
5. Mark rule: `"generated_by": "llm", "generated_at": "ISO-date", "status": "untested"`

**Priority order**:
1. KEV = true (actively exploited) — always generate first
2. CVSS >= 9.0 (critical)
3. CVSS >= 7.0 + EPSS >= 0.5 (high exploit probability)
4. Remaining CVSS >= 7.0

**Implementation**: New script `scripts/pattern-gen.py` using Claude API (batch mode for cost efficiency).

**Cost control**: Max 50 rules per run. Each rule = ~500 input tokens + ~200 output tokens. ~50 * 700 = 35K tokens per run.

### Step 3: `test` — Rule Validation

Tests newly generated rules against known-vulnerable code.

**Input**: Rules with `status: "untested"` from step 2

**Test corpus**: `tests/vulnerable-app/` — existing directory with intentionally vulnerable code samples.

**Process**:
1. For each untested rule:
   - Run `Grep` with each `detect.patterns[]` against vulnerable-app
   - Check if matches align with known vulnerability locations (golden dataset)
   - Check `negative_patterns[]` filter out false positives
2. Calculate per-rule metrics:
   - **Precision**: true positives / (true positives + false positives)
   - **Recall**: true positives / (true positives + false negatives)
3. Assign status:
   - Precision >= 70%: `"status": "active"` — used in scans
   - Precision 50-69%: `"status": "review"` — needs manual check
   - Precision < 50%: `"status": "draft"` — not used in scans
4. Write results back to the rule

**Golden dataset**: `tests/vulnerable-app/golden.json` — maps file:line to CVE/CWE for known vulns.

**Implementation**: New script `scripts/rule-tester.py`. Requires expanding `tests/vulnerable-app/` with more diverse samples over time.

### Step 4: `score` — Coverage Measurement

Measures how well the KB covers security standards.

**Standards measured**:

| Standard | Source | Total Items | How Measured |
|----------|--------|-------------|-------------|
| CWE-Top-25 | `standards/cwe-top25.json` | 25 | Rules with matching `cwe` field |
| OWASP Web 2025 | `standards/owasp-web-2025.json` | 10 | Rules with matching `owasp` field |
| OWASP API 2023 | `standards/owasp-api-2023.json` | 10 | Rules with matching `owasp` field |
| OWASP LLM 2025 | `standards/owasp-llm-2025.json` | 10 | Rules with matching `owasp` field |
| OWASP Mobile 2024 | `standards/owasp-mobile-2024.json` | 10 | Rules with matching `owasp` field |
| MITRE ATLAS | `standards/mitre-atlas.json` | ~20 | Rules with matching `mitre_atlas` field |

**Output**: Coverage percentages per standard + list of uncovered items (gaps).

**Rule quality score**: Beyond coverage, score the KB quality:
- Active rules with confidence >= 0.7: **strong**
- Active rules with confidence < 0.7: **weak**
- Draft/untested rules: **inactive**
- Quality = strong / (strong + weak + inactive) * 100

**Implementation**: New script `scripts/coverage-scorer.py`. Reads all rules.json + cve-rules.json, cross-references with standards JSON files.

### Step 5: `report` — Threat Intelligence Report (TIR)

Generates a structured report, equivalent to sentinel-evolve's EIR.

**JSON output** (`reports/archive/TIR-{date}.json`):

```json
{
  "date": "2026-04-13",
  "sources": {
    "synced": 8,
    "new_cves": 47,
    "new_kev": 3,
    "new_attack_techniques": 0,
    "standards_updated": ["owasp-llm-2025"]
  },
  "rules": {
    "total": 1139,
    "manual": 139,
    "auto_active": 450,
    "auto_draft": 300,
    "auto_untested": 250,
    "generated_this_run": 12,
    "activated_this_run": 9
  },
  "coverage": {
    "cwe_top25": { "covered": 23, "total": 25, "pct": 92, "gaps": ["CWE-416", "CWE-476"] },
    "owasp_web": { "covered": 10, "total": 10, "pct": 100, "gaps": [] },
    "owasp_llm": { "covered": 8, "total": 10, "pct": 80, "gaps": ["LLM09", "LLM10"] }
  },
  "quality": {
    "strong": 520,
    "weak": 69,
    "inactive": 550,
    "score": 76
  },
  "feedback": {
    "false_positives_ingested": 5,
    "patterns_refined": 3,
    "cross_domain_propagated": 1
  }
}
```

**Markdown output** (`reports/archive/TIR-{date}.md`): Human-readable report using template `reports/templates/threat-intel-report.md`.

**Implementation**: Template-based rendering, same pattern as EIR.

### Step 6: `feedback` — Continuous Improvement Loop

Ingests scan results to improve rule quality over time.

**Input sources**:
- `~/.sentinel/feedback/false-positives.json` — FP marked by user during/after scans
- `~/.sentinel/feedback/confirmed.json` — TP confirmed by user
- Previous scan SARIF reports in `reports/archive/`

**Feedback actions**:

| Signal | Action |
|--------|--------|
| False positive on rule X, file pattern Y | Add Y to `negative_patterns[]` of rule X |
| Confirmed TP on rule X | Increase `confidence` score of rule X |
| Supply-chain vuln in package P | Flag web-app/api rules that import P for priority re-scan |
| Multiple FP on same rule | Downgrade to `status: "review"`, decrease confidence |
| Rule X never triggers in 90 days | Mark as `status: "stale"` for review |

**Cross-domain propagation**: When a supply-chain vulnerability is confirmed (e.g., lodash prototype pollution), the feedback step:
1. Identifies which projects use the affected package (from `scan-dependencies` results)
2. Creates/upgrades web-app rules for the specific vulnerability pattern
3. Flags these rules as `"propagated_from": "SC-CVE-2025-XXXX"`

**Storage**:
- `~/.sentinel/feedback/false-positives.json` — array of `{rule_id, file, line, date, reason}`
- `~/.sentinel/feedback/confirmed.json` — array of `{rule_id, file, line, date}`
- Both files are append-only, pruned after 6 months

**Implementation**: Integrated into the evolve pipeline. Also hookable via PostScan (future): after each `/sentinel-security` scan completes, prompt user to mark FP/TP.

---

## File Structure

### New files

```
scripts/
  pattern-gen.py              # LLM pattern generation for CVE rules
  rule-tester.py              # Test rules against vulnerable-app
  coverage-scorer.py          # Standards coverage measurement

reports/templates/
  threat-intel-report.md      # TIR template

tests/vulnerable-app/
  golden.json                 # Golden dataset: file:line → CVE/CWE mapping

~/.sentinel/feedback/
  false-positives.json        # FP marked by users
  confirmed.json              # TP confirmed by users
```

### Modified files

```
scripts/cve-sync.py           # Extended with KEV, ATT&CK, OWASP sync
skills/security/SKILL.md      # New "## Mode: evolve" section
knowledge-base/cve-feed/      # New kev-catalog.json
knowledge-base/standards/     # Auto-synced (no longer static)
```

### Unchanged

```
knowledge-base/domains/*/rules.json    # Manual rules — never auto-modified
rag/indexer.py                         # Re-indexes all rules (auto + manual)
rag/query.py                           # Unchanged, queries same ChromaDB
scripts/kb-update.py                   # Unchanged, generates templates
scripts/deploy.sh                      # Unchanged, deploys everything
```

---

## Cron Schedule

```
Daily   6:00 AM  — cve-sync.py (all sources including new ones)
Weekly  Mon 9 AM — kb-update.py (generate rule templates) → pattern-gen.py (LLM fill) → rule-tester.py → coverage-scorer.py
Weekly  Mon 9 AM — RAG re-index (indexer.py)
```

The full `evolve` pipeline (all 6 steps) runs weekly. Individual steps (especially `sync`) run daily.

---

## Success Metrics

| Metric | Current | Target (3 months) |
|--------|---------|-------------------|
| Rules with active patterns | 139 (manual only) | 600+ (manual + LLM-generated) |
| CWE-Top-25 coverage | ~60% (estimated) | 90%+ |
| OWASP LLM coverage | ~80% | 95%+ |
| CISA KEV integration | 0 | 100% |
| Average rule confidence | N/A | 0.75+ |
| Feedback loop active | No | Yes |
| Standards auto-sync | No | Yes (all 8) |

---

## Implementation Phases

### Phase 1 — Sync++ (Week 1)
- Extend `cve-sync.py` with CISA KEV + OWASP auto-sync
- Add `kev-catalog.json` cache
- Auto-sync standards JSON files
- Add `evolve sync` sub-mode to SKILL.md

### Phase 2 — Pattern Generation (Week 2)
- Create `pattern-gen.py` with Claude API
- Generate patterns for top 50 CVE rules (KEV + CVSS >= 9)
- Add `evolve gen` sub-mode to SKILL.md

### Phase 3 — Testing & Scoring (Week 3)
- Create `rule-tester.py` + expand `tests/vulnerable-app/golden.json`
- Create `coverage-scorer.py`
- Add `evolve test` and `evolve score` sub-modes

### Phase 4 — Report & Feedback (Week 4)
- Create TIR template + report generation
- Create feedback ingestion (`~/.sentinel/feedback/`)
- Cross-domain propagation logic
- Full pipeline integration

### Phase 5 — Automation (Week 5)
- Wire into cron schedule
- Add MITRE ATT&CK STIX sync
- PostScan hook for FP/TP collection

---

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| LLM-generated patterns have low precision | Step 3 (test) gates activation at 70% precision |
| Pattern generation cost | Max 50 rules/run, batch API calls, ~35K tokens/run |
| Feedback data grows unbounded | Prune after 6 months, aggregate stats before pruning |
| Standards sync breaks on format changes | Schema validation on fetch, fallback to cached version |
| vulnerable-app corpus too small | Expand incrementally, community samples |
