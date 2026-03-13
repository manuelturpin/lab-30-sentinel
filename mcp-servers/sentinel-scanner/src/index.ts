/**
 * Sentinel Scanner — MCP Server
 *
 * Exposes security scanning tools to Claude Code via the
 * Model Context Protocol. This is the main entry point.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
  name: "sentinel-scanner",
  version: "0.1.0",
});

// --- Tool: scan-project ---
server.tool(
  "scan-project",
  "Run a full security scan on a project. Detects the stack and dispatches relevant checks.",
  {
    projectPath: z.string().describe("Absolute path to the project to scan"),
    depth: z
      .enum(["quick", "standard", "deep"])
      .default("standard")
      .describe("Scan depth: quick (5min), standard (15min), deep (30min+)"),
  },
  async ({ projectPath, depth }) => {
    // Skeleton — will be implemented in Session 5
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              status: "not_implemented",
              message: `scan-project for ${projectPath} at depth ${depth} — implementation pending (Session 5)`,
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

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
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            status: "not_implemented",
            message: `scan-dependencies for ${projectPath} (${ecosystem}) — implementation pending (Session 5)`,
          }),
        },
      ],
    };
  }
);

// --- Tool: scan-secrets ---
server.tool(
  "scan-secrets",
  "Detect hardcoded secrets, API keys, tokens, and credentials in the project.",
  {
    projectPath: z.string().describe("Absolute path to the project"),
    includeGitHistory: z
      .boolean()
      .default(false)
      .describe("Also scan git history for leaked secrets"),
  },
  async ({ projectPath, includeGitHistory }) => {
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            status: "not_implemented",
            message: `scan-secrets for ${projectPath} (git history: ${includeGitHistory}) — implementation pending (Session 5)`,
          }),
        },
      ],
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
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            status: "not_implemented",
            message: `scan-headers for ${url} — implementation pending (Session 5)`,
          }),
        },
      ],
    };
  }
);

// --- Tool: query-cve ---
server.tool(
  "query-cve",
  "Query CVE database for vulnerabilities affecting a specific component or package.",
  {
    component: z.string().describe("Package or component name"),
    version: z.string().optional().describe("Specific version to check"),
    ecosystem: z
      .enum(["npm", "pypi", "gem", "go", "cargo", "maven"])
      .optional()
      .describe("Package ecosystem"),
  },
  async ({ component, version, ecosystem }) => {
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            status: "not_implemented",
            message: `query-cve for ${component}@${version || "latest"} (${ecosystem || "auto"}) — implementation pending (Session 5)`,
          }),
        },
      ],
    };
  }
);

// --- Tool: query-kb ---
server.tool(
  "query-kb",
  "Query the Sentinel Knowledge Base using semantic search (RAG) for security rules and patterns.",
  {
    query: z
      .string()
      .describe("Natural language security query"),
    domain: z
      .enum([
        "web-app",
        "api",
        "llm-ai",
        "mobile",
        "infrastructure",
        "supply-chain",
        "database",
        "data-privacy",
        "all",
      ])
      .default("all")
      .describe("Domain to search within"),
    limit: z
      .number()
      .default(10)
      .describe("Maximum number of results to return"),
  },
  async ({ query, domain, limit }) => {
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            status: "not_implemented",
            message: `query-kb for "${query}" in domain ${domain} (limit: ${limit}) — implementation pending (Session 6)`,
          }),
        },
      ],
    };
  }
);

// --- Start server ---
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Sentinel Scanner MCP Server running on stdio");
}

main().catch(console.error);
