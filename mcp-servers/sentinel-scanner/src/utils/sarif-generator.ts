/**
 * SARIF Generator — Converts scan findings to SARIF 2.1.0 format
 *
 * Skeleton for Session 8 implementation.
 * SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { Finding } from "./types.js";

export interface SARIFReport {
  $schema: string;
  version: string;
  runs: SARIFRun[];
}

export interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SARIFRule[];
    };
  };
  results: SARIFResult[];
}

export interface SARIFRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration: {
    level: "error" | "warning" | "note" | "none";
  };
  properties?: Record<string, unknown>;
}

export interface SARIFResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: {
        startLine: number;
        startColumn?: number;
      };
    };
  }>;
  properties?: Record<string, unknown>;
}

/**
 * Convert Sentinel findings to SARIF 2.1.0 format.
 */
export function generateSARIF(findings: Finding[]): SARIFReport {
  const rules: SARIFRule[] = [];
  const results: SARIFResult[] = [];
  const seenRules = new Set<string>();

  for (const finding of findings) {
    // Add rule if not seen
    if (!seenRules.has(finding.id)) {
      seenRules.add(finding.id);
      rules.push({
        id: finding.id,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          cvss_v4: finding.cvss_v4,
          standard: finding.standard,
          owasp: finding.owasp,
          cwe: finding.cwe,
        },
      });
    }

    // Add result
    results.push({
      ruleId: finding.id,
      level: severityToLevel(finding.severity),
      message: { text: `${finding.description}\n\nRemediation: ${finding.remediation}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.location.file },
            region: finding.location.line
              ? {
                  startLine: finding.location.line,
                  startColumn: finding.location.column,
                }
              : undefined,
          },
        },
      ],
      properties: {
        severity: finding.severity,
        cvss_v4: finding.cvss_v4,
        epss: finding.epss,
      },
    });
  }

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Sentinel",
            version: "0.1.0",
            informationUri: "https://github.com/bonsai974/sentinel",
            rules,
          },
        },
        results,
      },
    ],
  };
}

function severityToLevel(
  severity: string
): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
      return "note";
    default:
      return "none";
  }
}
