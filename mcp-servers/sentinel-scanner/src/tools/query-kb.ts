/**
 * query-kb tool — Knowledge Base semantic query (RAG)
 *
 * Bridges to Python ChromaDB via subprocess.
 */

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

export interface KBQueryResult {
  query: string;
  domain: string;
  totalResults: number;
  results: KBEntry[];
  error?: string;
}

export interface KBEntry {
  id: string;
  score: number; // Relevance score 0-1
  domain: string;
  title: string;
  severity: string;
  description: string;
  detect?: {
    patterns: string[];
    file_types: string[];
  };
  remediation?: string;
  standards: string[];
  source: string; // File path in KB
}

function findQueryScript(): string {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  // Walk up from current file to find sentinel-scanner root (contains package.json),
  // then navigate to rag/query.py. Works from both src/ and dist/.
  let dir = thisDir;
  for (let i = 0; i < 5; i++) {
    dir = path.dirname(dir);
    if (existsSync(path.join(dir, "package.json"))) {
      // dir is sentinel-scanner root, go up to mcp-servers/, then lab-30-sentinel/
      const script = path.resolve(dir, "..", "..", "rag", "query.py");
      if (existsSync(script)) return script;
    }
  }
  throw new Error("Cannot find rag/query.py — ensure the project structure is intact");
}

export async function queryKB(
  query: string,
  domain: string,
  limit: number
): Promise<KBQueryResult> {
  let queryScript: string;
  try {
    queryScript = findQueryScript();
  } catch (e) {
    return {
      query, domain, totalResults: 0, results: [],
      error: (e as Error).message,
    };
  }

  // Cap query length to prevent memory issues in embedding model
  const sanitizedQuery = query.slice(0, 1000);

  return new Promise((resolve) => {
    execFile(
      "python3",
      [queryScript, "--query", sanitizedQuery, "--domain", domain, "--limit", String(limit)],
      { timeout: 30000, maxBuffer: 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          resolve({
            query,
            domain,
            totalResults: 0,
            results: [],
            error: `Python query failed: ${error.message}${stderr ? ` — ${stderr}` : ""}`,
          });
          return;
        }

        try {
          const result = JSON.parse(stdout.trim()) as KBQueryResult;
          resolve(result);
        } catch {
          resolve({
            query,
            domain,
            totalResults: 0,
            results: [],
            error: `Failed to parse query output: ${stdout.substring(0, 200)}`,
          });
        }
      }
    );
  });
}
