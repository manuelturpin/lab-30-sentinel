# Sentinel — Executive Security Summary

**Project**: {{project_name}} | **Date**: {{date}} | **Risk Score**: {{composite_score}}/10

## Key Metrics

| Metric | Value |
|--------|-------|
| Critical vulnerabilities | {{critical}} |
| High vulnerabilities | {{high}} |
| Total findings | {{total}} |
| Dependencies scanned | {{total_deps}} |
| Vulnerable dependencies | {{vuln_deps}} |

## Top 5 Risks

{{#each top_risks}}
{{@index}}. **[{{severity}}]** {{title}} — {{file}} (CVSS: {{cvss_v4}})
{{/each}}

## Immediate Actions Required

{{#each immediate_actions}}
- {{description}}
{{/each}}

## Standards Compliance

| Standard | Coverage | Status |
|----------|----------|--------|
{{#each standards_compliance}}
| {{name}} | {{coverage}} | {{status}} |
{{/each}}
