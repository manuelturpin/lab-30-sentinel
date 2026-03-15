/**
 * scan-project tool — Full project security scan
 *
 * Detects stack, loads KB rules for matched domains,
 * walks project files, applies regex patterns, scores findings.
 */

import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { detectStack, type StackDetectionResult } from "../utils/stack-detector.js";
import { calculateCompositeRisk } from "../utils/risk-scorer.js";
import type { Finding, ScanSummary } from "../utils/types.js";

export type { Finding, ScanSummary };

export interface ScanResult {
  projectPath: string;
  timestamp: string;
  stack: StackDetectionResult;
  findings: Finding[];
  summary: ScanSummary;
}

interface KBRuleRaw {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss_v4: number;
  category: string;
  subcategory?: string;
  title: string;
  description: string;
  detect: {
    patterns: string[];
    negative_patterns?: string[];
    file_types: string[];
    exclude: string[];
  };
  remediation: {
    description: string;
    code_example?: string;
    references?: string[];
  };
  standards: string[];
  ai_specific?: boolean;
  frameworks?: string[];
}

interface CompiledRule extends KBRuleRaw {
  compiledPatterns: RegExp[];
  compiledNegativePatterns: RegExp[];
}

const STACK_TO_DOMAIN: Record<string, string[]> = {
  nodejs: ["web-app", "supply-chain"],
  typescript: ["web-app"],
  nextjs: ["web-app", "static-sites"],
  nuxt: ["web-app", "static-sites"],
  sveltekit: ["web-app"],
  astro: ["web-app", "static-sites"],
  angular: ["web-app"],
  vite: ["web-app"],
  react: ["web-app"],
  python: ["supply-chain"],
  django: ["web-app", "database"],
  flask: ["web-app", "api"],
  fastapi: ["api"],
  ruby: ["supply-chain"],
  rails: ["web-app", "database"],
  go: ["supply-chain"],
  rust: ["supply-chain"],
  java: ["supply-chain"],
  express: ["api", "web-app"],
  fastify: ["api"],
  hono: ["api"],
  koa: ["api"],
  docker: ["infrastructure"],
  kubernetes: ["infrastructure"],
  terraform: ["infrastructure"],
  ansible: ["infrastructure"],
  prisma: ["database"],
  "sql-database": ["database"],
  mongodb: ["database"],
  ios: ["mobile"],
  android: ["mobile"],
  flutter: ["mobile"],
  "react-native": ["mobile"],
  "claude-skills": ["llm-ai"],
  "claude-code": ["llm-ai"],
  "ai-agents": ["llm-ai"],
  cursor: ["llm-ai"],
  copilot: ["llm-ai"],
  "llm-sdk": ["llm-ai"],
  dotenv: ["data-privacy"],
  websocket: ["web-app"],
  vercel: ["static-sites"],
  netlify: ["static-sites"],
};

const DEPTH_LIMITS: Record<string, { severities: string[]; maxFiles: number }> = {
  quick: { severities: ["CRITICAL", "HIGH"], maxFiles: 100 },
  standard: { severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], maxFiles: 1000 },
  deep: { severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], maxFiles: Infinity },
};

function resolveKBPath(): string {
  const thisFile = fileURLToPath(import.meta.url);
  // src/tools/scan-project.ts -> go up to sentinel-scanner, then knowledge-base
  return path.resolve(path.dirname(thisFile), "..", "..", "..", "..", "knowledge-base", "domains");
}

function mapStacksToDomains(stacks: { name: string }[]): string[] {
  const domains = new Set<string>();
  for (const stack of stacks) {
    const mapped = STACK_TO_DOMAIN[stack.name];
    if (mapped) {
      for (const d of mapped) domains.add(d);
    }
  }
  // Always include web-app and supply-chain as baseline
  if (domains.size === 0) {
    domains.add("web-app");
    domains.add("supply-chain");
  }
  return Array.from(domains);
}

function compileRegex(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

function loadRulesForDomains(domains: string[], depth: "quick" | "standard" | "deep"): CompiledRule[] {
  const kbPath = resolveKBPath();
  const rules: CompiledRule[] = [];
  const depthConfig = DEPTH_LIMITS[depth];

  for (const domain of domains) {
    const rulesFile = path.join(kbPath, domain, "rules.json");
    try {
      const content = fs.readFileSync(rulesFile, "utf-8");
      const domainRules: KBRuleRaw[] = JSON.parse(content);
      for (const rule of domainRules) {
        if (depthConfig.severities.includes(rule.severity)) {
          const compiledPatterns = rule.detect.patterns
            .map(compileRegex)
            .filter((r): r is RegExp => r !== null);
          const compiledNegativePatterns = (rule.detect.negative_patterns || [])
            .map(p => compileRegex(p))
            .filter((r): r is RegExp => r !== null);
          // Only add rule if it has at least one valid pattern
          if (compiledPatterns.length > 0) {
            rules.push({ ...rule, compiledPatterns, compiledNegativePatterns });
          }
        }
      }
    } catch {
      // Domain rules file not found or invalid, skip
    }
  }
  return rules;
}

function matchesGlob(filename: string, pattern: string): boolean {
  // Simple glob: *.js, *.ts, *.jsx, etc.
  if (pattern.startsWith("*.")) {
    const ext = pattern.slice(1); // .js, .ts, etc.
    return filename.endsWith(ext);
  }
  return filename === pattern;
}

function shouldExclude(filePath: string, excludeDirs: string[]): boolean {
  const parts = filePath.split(path.sep);
  for (const part of parts) {
    for (const exc of excludeDirs) {
      // Handle glob-like excludes (*.test.*)
      if (exc.includes("*")) {
        if (matchesGlob(part, exc)) return true;
      } else if (part === exc) {
        return true;
      }
    }
  }
  return false;
}

function walkFiles(dir: string, excludeDirs: string[], fileTypes: string[], maxFiles: number): string[] {
  const results: string[] = [];

  function walk(currentDir: string): void {
    if (results.length >= maxFiles) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) return;

      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(dir, fullPath);

      if (entry.isDirectory()) {
        if (!shouldExclude(relativePath, excludeDirs)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        if (!shouldExclude(relativePath, excludeDirs) &&
            fileTypes.some(ft => matchesGlob(entry.name, ft))) {
          results.push(fullPath);
        }
      }
    }
  }

  walk(dir);
  return results;
}

export async function scanProject(
  projectPath: string,
  depth: "quick" | "standard" | "deep"
): Promise<ScanResult> {
  const startTime = Date.now();

  // Step 1: Detect stack
  const stack = await detectStack(projectPath);

  // Step 2: Map stacks to KB domains
  const domains = mapStacksToDomains(stack.stacks);

  // Step 3: Load rules
  const rules = loadRulesForDomains(domains, depth);

  // Step 4-5: Walk files and apply patterns
  const findings: Finding[] = [];
  const depthConfig = DEPTH_LIMITS[depth];

  // Collect all unique exclude dirs and file types across rules
  const globalExclude = new Set<string>(["node_modules", "dist", "build", ".git"]);
  const globalFileTypes = new Set<string>();

  for (const rule of rules) {
    if (rule.detect.exclude) {
      for (const e of rule.detect.exclude) globalExclude.add(e);
    }
    if (rule.detect.file_types) {
      for (const ft of rule.detect.file_types) globalFileTypes.add(ft);
    }
  }

  const files = walkFiles(
    projectPath,
    Array.from(globalExclude),
    Array.from(globalFileTypes),
    depthConfig.maxFiles
  );

  // Cache file contents
  const fileContents = new Map<string, string>();

  for (const file of files) {
    let content: string;
    try {
      if (fileContents.has(file)) {
        content = fileContents.get(file)!;
      } else {
        content = fs.readFileSync(file, "utf-8");
        fileContents.set(file, content);
      }
    } catch {
      continue;
    }

    const lines = content.split("\n");
    const relativePath = path.relative(projectPath, file);
    const fileName = path.basename(file);

    for (const rule of rules) {
      // Check file type match
      if (!rule.detect.file_types.some(ft => matchesGlob(fileName, ft))) {
        continue;
      }

      // Check exclude
      if (rule.detect.exclude && shouldExclude(relativePath, rule.detect.exclude)) {
        continue;
      }

      // Test pre-compiled patterns against each line
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        let matched = false;

        for (const regex of rule.compiledPatterns) {
          if (regex.test(line)) {
            matched = true;
            break;
          }
        }

        if (!matched) continue;

        // Check negative patterns against full file content
        let negativeMatch = false;
        for (const negRegex of rule.compiledNegativePatterns) {
          if (negRegex.test(content)) {
            negativeMatch = true;
            break;
          }
        }

        if (negativeMatch) continue;

        // Create finding
        const risk = calculateCompositeRisk(rule.cvss_v4);
        const owasp = rule.standards.find(s => s.startsWith("OWASP"));
        const cwe = rule.standards.find(s => s.startsWith("CWE"));

        findings.push({
          id: rule.id,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          location: {
            file: relativePath,
            line: lineIdx + 1,
          },
          owasp,
          cwe,
          remediation: rule.remediation.description,
          cvss_v4: rule.cvss_v4,
          epss: risk.epss,
        });

        // Only report first match per rule per file
        break;
      }
    }
  }

  // Step 6: Build summary
  const summary: ScanSummary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === "CRITICAL").length,
    high: findings.filter(f => f.severity === "HIGH").length,
    medium: findings.filter(f => f.severity === "MEDIUM").length,
    low: findings.filter(f => f.severity === "LOW").length,
    info: findings.filter(f => f.severity === "INFO").length,
    agentsDispatched: stack.agents,
    duration_ms: Date.now() - startTime,
  };

  return {
    projectPath,
    timestamp: new Date().toISOString(),
    stack,
    findings,
    summary,
  };
}
