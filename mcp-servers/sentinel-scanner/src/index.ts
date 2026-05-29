/**
 * Sentinel Scanner — MCP Server
 *
 * Exposes security scanning tools to Claude Code via the
 * Model Context Protocol. This is the main entry point.
 *
 * Session 12 (2026-03-15) / T2 (2026-04-21): 4 local scanning tools
 * (scan-project, scan-secrets, query-cve, query-kb) were removed in
 * favor of native Read/Grep/Bash — see docs/adr/2026-04-21-mcp-tools-removal.md.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanDependencies } from "./tools/scan-dependencies.js";
import { scanHeaders } from "./tools/scan-headers.js";
import { generateSBOM } from "./utils/sbom-generator.js";

const server = new McpServer({
  name: "sentinel-scanner",
  version: "0.1.0",
});

// --- Tool: scan-dependencies ---
server.tool(
  "scan-dependencies",
  "Analyze project dependencies for known vulnerabilities using OSV and NVD databases.",
  {
    projectPath: z.string().describe("Absolute path to the project"),
    ecosystem: z
      .enum(["npm", "pypi", "gem", "go", "cargo", "maven", "auto"])
      .default("auto")
      .describe("Package ecosystem to scan"),
  },
  async ({ projectPath, ecosystem }) => {
    const result = await scanDependencies(projectPath, ecosystem);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
      _meta: {
        "anthropic/maxResultSizeChars": 500000,
      },
    };
  }
);

// --- Tool: scan-headers ---
server.tool(
  "scan-headers",
  "Check security headers (CSP, HSTS, X-Frame-Options, etc.) for a web application.",
  {
    url: z.string().describe("URL to check headers for"),
  },
  async ({ url }) => {
    const result = await scanHeaders(url);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
      _meta: {
        "anthropic/maxResultSizeChars": 500000,
      },
    };
  }
);

// --- Tool: generate-sbom ---
server.tool(
  "generate-sbom",
  "Generate a CycloneDX Software Bill of Materials (SBOM) for a project.",
  {
    projectPath: z.string().describe("Absolute path to the project"),
    projectName: z.string().optional().describe("Project name (auto-detected from package.json if omitted)"),
    projectVersion: z.string().optional().describe("Project version (auto-detected if omitted)"),
  },
  async ({ projectPath, projectName, projectVersion }) => {
    const sbom = generateSBOM(projectPath, projectName, projectVersion);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(sbom, null, 2),
        },
      ],
    };
  }
);

// --- Start server ---
async function main() {
  // Session correlation context. Claude Code injects these into stdio MCP
  // subprocess environments: CLAUDE_CODE_SESSION_ID + CLAUDECODE=1 (v2.1.154),
  // CLAUDE_PROJECT_DIR (v2.1.139). Logged to stderr so MCP scans can be
  // correlated with the dispatching Claude Code session in the audit trail.
  const sessionId = process.env.CLAUDE_CODE_SESSION_ID ?? "unknown";
  const projectDir = process.env.CLAUDE_PROJECT_DIR ?? process.cwd();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    `Sentinel Scanner MCP Server running on stdio ` +
      `(session=${sessionId}, project=${projectDir})`
  );
}

main().catch(console.error);
