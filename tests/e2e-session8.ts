/**
 * E2E Validation — Session 8
 *
 * Tests: SBOM generation, SARIF enrichment, report rendering, risk scoring,
 * and secret redaction against the vulnerable-app fixture.
 */

import * as path from "path";
import * as fs from "fs";
import { generateSBOM } from "../mcp-servers/sentinel-scanner/src/utils/sbom-generator.js";
import { generateSARIF } from "../mcp-servers/sentinel-scanner/src/utils/sarif-generator.js";
import { renderReport } from "../mcp-servers/sentinel-scanner/src/utils/report-renderer.js";
import { calculateCompositeRisk } from "../mcp-servers/sentinel-scanner/src/utils/risk-scorer.js";
import type { Finding } from "../mcp-servers/sentinel-scanner/src/utils/types.js";

const VULN_APP_PATH = path.resolve(__dirname, "vulnerable-app");
const ARCHIVE_PATH = path.resolve(__dirname, "../reports/archive");
const PROJECT_NAME = "vulnerable-app";
const DATE = new Date().toISOString().split("T")[0];

let passed = 0;
let failed = 0;

function assert(condition: boolean, label: string): void {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}`);
    failed++;
  }
}

// --- Sample findings (simulating agent output) ---
const sampleFindings: Finding[] = [
  {
    id: "SECRETS-001",
    severity: "CRITICAL",
    title: "Hardcoded API key detected",
    description: "API key found in source code",
    location: { file: "src/server.js", line: 17 },
    standard: "CWE-798",
    owasp: "A07:2021",
    cwe: "CWE-798",
    remediation: "Move API keys to environment variables",
    cvss_v4: 9.1,
    epss: 0.85,
  },
  {
    id: "SQLI-001",
    severity: "CRITICAL",
    title: "SQL Injection via string concatenation",
    description: "User input directly concatenated into SQL query",
    location: { file: "src/server.js", line: 26 },
    standard: "CWE-89",
    owasp: "A03:2021",
    cwe: "CWE-89",
    remediation: "Use parameterized queries",
    cvss_v4: 9.8,
    epss: 0.92,
  },
  {
    id: "XSS-001",
    severity: "HIGH",
    title: "Reflected XSS via unescaped user input",
    description: "User input rendered directly in HTML response",
    location: { file: "src/server.js", line: 38 },
    standard: "CWE-79",
    owasp: "A07:2021",
    cwe: "CWE-79",
    remediation: "Sanitize and escape user input before rendering",
    cvss_v4: 7.5,
    epss: 0.45,
  },
  {
    id: "CORS-001",
    severity: "MEDIUM",
    title: "Permissive CORS configuration",
    description: "CORS allows all origins",
    location: { file: "src/server.js", line: 13 },
    standard: "CWE-942",
    owasp: "A05:2021",
    cwe: "CWE-942",
    remediation: "Restrict CORS to specific trusted origins",
    cvss_v4: 5.3,
    epss: 0.1,
  },
  {
    id: "LOG-001",
    severity: "LOW",
    title: "Sensitive data in logs",
    description: "Password logged in plaintext",
    location: { file: "src/server.js", line: 57 },
    standard: "CWE-532",
    owasp: "A09:2021",
    cwe: "CWE-532",
    remediation: "Never log sensitive data. Use structured logging with field redaction.",
    cvss_v4: 3.0,
    epss: 0.02,
  },
];

// ========== TEST: Risk Scorer ==========
console.log("\n=== Risk Scorer ===");

const risk1 = calculateCompositeRisk(9.8, 0.92);
assert(
  risk1.composite === Math.round(9.8 * (0.6 + 0.4 * 0.92) * 100) / 100,
  `Composite formula correct: ${risk1.composite} (expected ${Math.round(9.8 * (0.6 + 0.4 * 0.92) * 100) / 100})`
);

const risk2 = calculateCompositeRisk(5.0, 0);
assert(
  risk2.composite === 3.0,
  `Zero EPSS gives 60% of CVSS: ${risk2.composite} (expected 3.0)`
);

const risk3 = calculateCompositeRisk(10, 1);
assert(
  risk3.composite === 10.0,
  `Max EPSS gives full CVSS: ${risk3.composite} (expected 10.0)`
);

// ========== TEST: SBOM Generator ==========
console.log("\n=== SBOM Generator ===");

const sbom = generateSBOM(VULN_APP_PATH, undefined, undefined, sampleFindings);

assert(sbom.bomFormat === "CycloneDX", "SBOM format is CycloneDX");
assert(sbom.specVersion === "1.5", "SBOM spec version is 1.5");
assert(sbom.components.length > 0, `SBOM has ${sbom.components.length} components`);
assert(
  sbom.components.some((c) => c.name === "express"),
  "SBOM contains 'express' dependency"
);
assert(
  sbom.components.some((c) => c.name === "jsonwebtoken"),
  "SBOM contains 'jsonwebtoken' dependency"
);
assert(
  sbom.components.every((c) => c.purl && c.purl.startsWith("pkg:")),
  "All components have valid PURLs"
);
assert(
  sbom.metadata.component.name === "vulnerable-test-app",
  `Auto-detected project name: ${sbom.metadata.component.name}`
);
assert(
  sbom.vulnerabilities !== undefined && sbom.vulnerabilities.length > 0,
  `SBOM has ${sbom.vulnerabilities?.length || 0} vulnerabilities mapped`
);

// ========== TEST: SARIF Generator ==========
console.log("\n=== SARIF Generator ===");

const startTime = new Date().toISOString();
const sarif = generateSARIF(sampleFindings, {
  startTime,
  endTime: new Date().toISOString(),
  args: ["--depth", "standard"],
  scannedFiles: ["src/server.js", "package.json", ".env"],
});

assert(sarif.version === "2.1.0", "SARIF version is 2.1.0");
assert(sarif.runs.length === 1, "SARIF has 1 run");
assert(
  sarif.runs[0].invocations !== undefined && sarif.runs[0].invocations.length === 1,
  "SARIF has invocations"
);
assert(
  sarif.runs[0].invocations![0].executionSuccessful === true,
  "Invocation marked successful"
);
assert(
  sarif.runs[0].invocations![0].startTimeUtc === startTime,
  "Invocation has correct start time"
);
assert(
  sarif.runs[0].artifacts !== undefined && sarif.runs[0].artifacts.length === 3,
  `SARIF has ${sarif.runs[0].artifacts?.length || 0} artifacts`
);
assert(
  sarif.runs[0].artifacts![0].roles![0] === "analysisTarget",
  "Artifacts have analysisTarget role"
);
assert(
  sarif.runs[0].results.length === sampleFindings.length,
  `SARIF has ${sarif.runs[0].results.length} results`
);

// ========== TEST: Report Renderer ==========
console.log("\n=== Report Renderer ===");

const report = renderReport({
  project_name: PROJECT_NAME,
  date: DATE,
  stacks: "Node.js, JavaScript",
  agent_count: 4,
  agent_names: "web-audit, supply-chain-audit, data-privacy-audit, cors-audit",
  depth: "standard",
  duration: "42s",
  executive_summary:
    "5 vulnerabilities found including 2 critical issues requiring immediate attention.",
  findings: sampleFindings,
  total_deps: 4,
  vuln_deps: 2,
  sarif_path: `reports/archive/${PROJECT_NAME}_${DATE}.sarif.json`,
  sbom_path: `reports/archive/${PROJECT_NAME}_${DATE}.sbom.json`,
  report_path: `reports/archive/${PROJECT_NAME}_${DATE}.md`,
});

assert(report.includes("Sentinel Security Report"), "Report has title");
assert(report.includes(PROJECT_NAME), "Report includes project name");
assert(report.includes("CRITICAL"), "Report includes severity levels");
assert(report.includes("SQL Injection"), "Report includes finding titles");
assert(report.includes("CWE-89"), "Report includes standards");
assert(report.includes("sarif.json"), "Report references SARIF file");
assert(report.includes("sbom.json"), "Report references SBOM file");

// ========== TEST: Redaction format ==========
console.log("\n=== Redaction Format ===");

// Read scan-secrets.ts to verify redaction format
const scanSecretsPath = path.resolve(
  __dirname,
  "../mcp-servers/sentinel-scanner/src/tools/scan-secrets.ts"
);
const scanSecretsContent = fs.readFileSync(scanSecretsPath, "utf-8");
assert(
  !scanSecretsContent.includes('***REDACTED***'),
  "scan-secrets.ts does NOT use ***REDACTED***"
);
assert(
  scanSecretsContent.includes('[REDACTED]'),
  "scan-secrets.ts uses [REDACTED] format"
);

// ========== SAVE REPORTS ==========
console.log("\n=== Saving Reports ===");

fs.mkdirSync(ARCHIVE_PATH, { recursive: true });

const sarifPath = path.join(ARCHIVE_PATH, `${PROJECT_NAME}_${DATE}.sarif.json`);
fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2));
assert(fs.existsSync(sarifPath), `SARIF saved: ${sarifPath}`);

const sbomPath = path.join(ARCHIVE_PATH, `${PROJECT_NAME}_${DATE}.sbom.json`);
fs.writeFileSync(sbomPath, JSON.stringify(sbom, null, 2));
assert(fs.existsSync(sbomPath), `SBOM saved: ${sbomPath}`);

const reportPath = path.join(ARCHIVE_PATH, `${PROJECT_NAME}_${DATE}.md`);
fs.writeFileSync(reportPath, report);
assert(fs.existsSync(reportPath), `Report saved: ${reportPath}`);

// ========== SUMMARY ==========
console.log(`\n${"=".repeat(40)}`);
console.log(`E2E Session 8: ${passed} passed, ${failed} failed`);
console.log(`${"=".repeat(40)}`);

if (failed > 0) process.exit(1);
