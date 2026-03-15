/**
 * Report Renderer — Renders Markdown reports from findings using the Handlebars-like template.
 *
 * Simple string replacement engine: {{variables}}, {{#each}} loops, {{#if}} conditionals.
 * No external dependencies required.
 */

import * as fs from "fs";
import * as path from "path";
import type { Finding } from "./types.js";
import { calculateCompositeRisk } from "./risk-scorer.js";

export interface ReportData {
  project_name: string;
  date: string;
  stacks: string;
  agent_count: number;
  agent_names: string;
  depth: string;
  duration: string;
  executive_summary: string;
  findings: Finding[];
  total_deps: number;
  vuln_deps: number;
  sarif_path: string;
  sbom_path: string;
  report_path: string;
}

interface TemplateContext {
  [key: string]: string | number | boolean | TemplateContext[] | undefined;
}

/**
 * Render a Markdown report from findings using the template.
 */
export function renderReport(data: ReportData): string {
  const templatePath = path.resolve(
    __dirname,
    "../../../../reports/templates/full-report.md"
  );

  let template: string;
  try {
    template = fs.readFileSync(templatePath, "utf-8");
  } catch {
    // Fallback: generate report without template
    return renderFallback(data);
  }

  // Build template context
  const severityCounts = countSeverities(data.findings);
  const total = data.findings.length;
  const compositeScores = data.findings.map(
    (f) => calculateCompositeRisk(f.cvss_v4 || 0, f.epss || 0).composite
  );
  const avgComposite =
    compositeScores.length > 0
      ? (
          compositeScores.reduce((a, b) => a + b, 0) / compositeScores.length
        ).toFixed(2)
      : "0.00";
  const avgEpss =
    data.findings.length > 0
      ? (
          data.findings.reduce((a, f) => a + (f.epss || 0), 0) /
          data.findings.length
        ).toFixed(4)
      : "0.0000";

  const criticalHigh = data.findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
  );
  const medium = data.findings.filter((f) => f.severity === "MEDIUM");
  const lowInfo = data.findings.filter(
    (f) => f.severity === "LOW" || f.severity === "INFO"
  );

  const pct = (n: number) =>
    total > 0 ? `${Math.round((n / total) * 100)}%` : "0%";

  // Build recommendations from critical/high findings
  const recommendations = criticalHigh.map((f, i) => ({
    priority: f.severity === "CRITICAL" ? "Immediate" : "High",
    description: `${f.title} — ${f.remediation}`,
    "@index": i + 1,
  }));

  const context: TemplateContext = {
    project_name: data.project_name,
    date: data.date,
    stacks: data.stacks,
    agent_count: data.agent_count,
    agent_names: data.agent_names,
    depth: data.depth,
    duration: data.duration,
    executive_summary: data.executive_summary,
    critical: severityCounts.CRITICAL,
    high: severityCounts.HIGH,
    medium: severityCounts.MEDIUM,
    low: severityCounts.LOW,
    info: severityCounts.INFO,
    total,
    critical_pct: pct(severityCounts.CRITICAL),
    high_pct: pct(severityCounts.HIGH),
    medium_pct: pct(severityCounts.MEDIUM),
    low_pct: pct(severityCounts.LOW),
    info_pct: pct(severityCounts.INFO),
    composite_score: avgComposite,
    epss_avg: avgEpss,
    total_deps: data.total_deps,
    vuln_deps: data.vuln_deps,
    sarif_path: data.sarif_path,
    sbom_path: data.sbom_path,
    report_path: data.report_path,
  };

  let result = template;

  // Process {{#each}} blocks
  result = processEachBlocks(result, {
    critical_high_findings: criticalHigh.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      cvss_v4: f.cvss_v4 || 0,
      epss: f.epss || 0,
      epss_percentile: f.epss ? `${Math.round(f.epss * 100)}th` : "N/A",
      file: f.location.file,
      line: f.location.line || 0,
      standard: f.standard || "N/A",
      owasp: f.owasp || "N/A",
      agent: (f as Finding & { agent?: string }).agent || "unknown",
      description: f.description,
      remediation: f.remediation,
      code_fix: "",
    })),
    medium_findings: medium.map((f, i) => ({
      "@index": i + 1,
      id: f.id,
      title: f.title,
      file: f.location.file,
      line: f.location.line || 0,
      standard: f.standard || "N/A",
      cvss_v4: f.cvss_v4 || 0,
    })),
    low_info_findings: lowInfo.map((f, i) => ({
      "@index": i + 1,
      id: f.id,
      title: f.title,
      file: f.location.file,
      line: f.location.line || 0,
      standard: f.standard || "N/A",
    })),
    recommendations: recommendations as unknown as TemplateContext[],
  });

  // Process {{#if}} blocks
  result = processIfBlocks(result);

  // Replace simple {{variables}}
  result = replaceVariables(result, context);

  return result;
}

function countSeverities(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  return counts;
}

function processEachBlocks(
  template: string,
  collections: Record<string, TemplateContext[]>
): string {
  // Match {{#each collectionName}}...{{/each}}
  const eachRegex = /\{\{#each\s+(\w+)\}\}\n?([\s\S]*?)\{\{\/each\}\}/g;

  return template.replace(eachRegex, (_match, collectionName, body) => {
    const items = collections[collectionName];
    if (!items || items.length === 0) {
      return "_No findings in this category._\n";
    }

    return items
      .map((item) => {
        let rendered = body;
        // Replace {{variable}} with item values
        rendered = rendered.replace(
          /\{\{(@?\w+)\}\}/g,
          (_m: string, key: string) => {
            const val = item[key];
            return val !== undefined ? String(val) : "";
          }
        );
        return rendered;
      })
      .join("");
  });
}

function processIfBlocks(template: string): string {
  // Match {{#if variable}}...{{/if}}
  const ifRegex = /\{\{#if\s+(\w+)\}\}\n?([\s\S]*?)\{\{\/if\}\}/g;

  return template.replace(ifRegex, (_match, _variable, body) => {
    // After each-block processing, variables are already replaced.
    // If the body content (between markers) is empty/whitespace-only, hide the block.
    const stripped = body.replace(/\{\{\w+\}\}/g, "").trim();
    // Check for actual content: if only whitespace/code-fence markers remain, skip
    const contentOnly = stripped.replace(/```\w*/g, "").trim();
    if (!contentOnly) {
      return "";
    }
    return body;
  });
}

function replaceVariables(
  template: string,
  context: TemplateContext
): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_match, key) => {
    const val = context[key];
    return val !== undefined ? String(val) : "";
  });
}

/**
 * Fallback renderer when template is not available.
 */
function renderFallback(data: ReportData): string {
  const counts = countSeverities(data.findings);
  const lines: string[] = [
    `# Sentinel Security Report`,
    ``,
    `**Project**: ${data.project_name}`,
    `**Date**: ${data.date}`,
    `**Stack detected**: ${data.stacks}`,
    `**Agents dispatched**: ${data.agent_count} (${data.agent_names})`,
    ``,
    `## Risk Summary`,
    ``,
    `| Severity | Count |`,
    `|----------|-------|`,
    `| CRITICAL | ${counts.CRITICAL} |`,
    `| HIGH     | ${counts.HIGH} |`,
    `| MEDIUM   | ${counts.MEDIUM} |`,
    `| LOW      | ${counts.LOW} |`,
    `| INFO     | ${counts.INFO} |`,
    `| **TOTAL**| **${data.findings.length}** |`,
    ``,
    `## Findings`,
    ``,
  ];

  for (const f of data.findings) {
    lines.push(`### [${f.id}] ${f.title}`);
    lines.push(`- **Severity**: ${f.severity} (CVSS v4: ${f.cvss_v4 || 0})`);
    lines.push(`- **Location**: \`${f.location.file}:${f.location.line || 0}\``);
    lines.push(`- **Description**: ${f.description}`);
    lines.push(`- **Remediation**: ${f.remediation}`);
    lines.push(``);
  }

  lines.push(`## Files`);
  lines.push(`- **SARIF report**: \`${data.sarif_path}\``);
  lines.push(`- **CycloneDX SBOM**: \`${data.sbom_path}\``);
  lines.push(`- **This report**: \`${data.report_path}\``);

  return lines.join("\n");
}
