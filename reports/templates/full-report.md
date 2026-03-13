# Sentinel Security Report

**Project**: {{project_name}}
**Date**: {{date}}
**Stack detected**: {{stacks}}
**Agents dispatched**: {{agent_count}} ({{agent_names}})
**Scan depth**: {{depth}}
**Duration**: {{duration}}

---

## Executive Summary

{{executive_summary}}

## Risk Summary

| Severity | Count | % of Total |
|----------|-------|------------|
| CRITICAL | {{critical}} | {{critical_pct}} |
| HIGH     | {{high}}     | {{high_pct}}     |
| MEDIUM   | {{medium}}   | {{medium_pct}}   |
| LOW      | {{low}}      | {{low_pct}}      |
| INFO     | {{info}}     | {{info_pct}}     |
| **TOTAL**| **{{total}}**| **100%**         |

**Composite Risk Score**: {{composite_score}}/10
**EPSS Average**: {{epss_avg}}

---

## Critical & High Findings

{{#each critical_high_findings}}
### [{{id}}] {{title}}
- **Severity**: {{severity}} (CVSS v4: {{cvss_v4}})
- **EPSS**: {{epss}} ({{epss_percentile}} percentile)
- **Location**: `{{file}}:{{line}}`
- **Standard**: {{standard}} | {{owasp}}
- **Agent**: {{agent}}

**Description**: {{description}}

**Remediation**: {{remediation}}

{{#if code_fix}}
```diff
{{code_fix}}
```
{{/if}}

---
{{/each}}

## Medium Findings

| # | ID | Title | Location | Standard | CVSS |
|---|-----|-------|----------|----------|------|
{{#each medium_findings}}
| {{@index}} | {{id}} | {{title}} | `{{file}}:{{line}}` | {{standard}} | {{cvss_v4}} |
{{/each}}

## Low & Info Findings

| # | ID | Title | Location | Standard |
|---|-----|-------|----------|----------|
{{#each low_info_findings}}
| {{@index}} | {{id}} | {{title}} | `{{file}}:{{line}}` | {{standard}} |
{{/each}}

---

## Recommendations

{{#each recommendations}}
{{@index}}. **{{priority}}**: {{description}}
{{/each}}

## Supply Chain Summary

- **Total dependencies**: {{total_deps}}
- **Vulnerable dependencies**: {{vuln_deps}}
- **SBOM generated**: {{sbom_path}}

## Files

- **SARIF report**: `{{sarif_path}}`
- **CycloneDX SBOM**: `{{sbom_path}}`
- **This report**: `{{report_path}}`
