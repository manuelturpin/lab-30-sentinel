/**
 * Stack Detector — Detects the technology stack of a project
 * by analyzing indicator files and directory structures.
 */

import * as fs from "fs";
import * as path from "path";

export interface StackDetectionResult {
  stacks: DetectedStack[];
  agents: string[];
  indicators: IndicatorMatch[];
}

export interface DetectedStack {
  name: string;
  category: StackCategory;
  confidence: number; // 0-1
  version?: string;
}

export type StackCategory =
  | "language"
  | "framework"
  | "runtime"
  | "database"
  | "infrastructure"
  | "ai-agent"
  | "mobile"
  | "static-hosting";

export interface IndicatorMatch {
  file: string;
  stack: string;
  exists: boolean;
}

interface IndicatorRule {
  patterns: string[];
  stack: string;
  category: StackCategory;
  agents: string[];
  versionExtractor?: (content: string) => string | undefined;
}

const INDICATOR_RULES: IndicatorRule[] = [
  // JavaScript / TypeScript
  {
    patterns: ["package.json"],
    stack: "nodejs",
    category: "runtime",
    agents: ["web-audit", "supply-chain-audit"],
    versionExtractor: (content: string) => {
      try {
        const pkg = JSON.parse(content);
        return pkg.engines?.node;
      } catch {
        return undefined;
      }
    },
  },
  {
    patterns: ["tsconfig.json"],
    stack: "typescript",
    category: "language",
    agents: ["web-audit"],
  },

  // Web Frameworks
  {
    patterns: ["next.config.js", "next.config.ts", "next.config.mjs"],
    stack: "nextjs",
    category: "framework",
    agents: ["web-audit", "static-site-audit"],
  },
  {
    patterns: ["nuxt.config.js", "nuxt.config.ts"],
    stack: "nuxt",
    category: "framework",
    agents: ["web-audit", "static-site-audit"],
  },
  {
    patterns: ["svelte.config.js"],
    stack: "sveltekit",
    category: "framework",
    agents: ["web-audit"],
  },
  {
    patterns: ["astro.config.mjs", "astro.config.ts"],
    stack: "astro",
    category: "framework",
    agents: ["web-audit", "static-site-audit"],
  },
  {
    patterns: ["angular.json"],
    stack: "angular",
    category: "framework",
    agents: ["web-audit"],
  },
  {
    patterns: ["vite.config.js", "vite.config.ts"],
    stack: "vite",
    category: "framework",
    agents: ["web-audit"],
  },

  // Python
  {
    patterns: ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock", "uv.lock"],
    stack: "python",
    category: "language",
    agents: ["supply-chain-audit"],
  },
  {
    patterns: ["manage.py", "django/"],
    stack: "django",
    category: "framework",
    agents: ["web-audit", "database-audit"],
  },
  {
    patterns: ["flask/"],
    stack: "flask",
    category: "framework",
    agents: ["web-audit", "api-audit"],
  },
  {
    patterns: ["fastapi/"],
    stack: "fastapi",
    category: "framework",
    agents: ["api-audit"],
  },

  // Ruby
  {
    patterns: ["Gemfile"],
    stack: "ruby",
    category: "language",
    agents: ["supply-chain-audit"],
  },
  {
    patterns: ["config/routes.rb", "Rakefile"],
    stack: "rails",
    category: "framework",
    agents: ["web-audit", "database-audit"],
  },

  // Go
  {
    patterns: ["go.mod"],
    stack: "go",
    category: "language",
    agents: ["supply-chain-audit"],
  },

  // Rust
  {
    patterns: ["Cargo.toml"],
    stack: "rust",
    category: "language",
    agents: ["supply-chain-audit"],
  },

  // Java / Kotlin
  {
    patterns: ["pom.xml", "build.gradle", "build.gradle.kts"],
    stack: "java",
    category: "language",
    agents: ["supply-chain-audit"],
  },

  // Mobile
  {
    patterns: ["Podfile", "ios/"],
    stack: "ios",
    category: "mobile",
    agents: ["mobile-audit"],
  },
  {
    patterns: ["android/build.gradle", "android/app/"],
    stack: "android",
    category: "mobile",
    agents: ["mobile-audit"],
  },
  {
    patterns: ["pubspec.yaml"],
    stack: "flutter",
    category: "mobile",
    agents: ["mobile-audit", "supply-chain-audit"],
  },
  {
    patterns: ["app.json", "expo.json"],
    stack: "react-native",
    category: "mobile",
    agents: ["mobile-audit", "supply-chain-audit"],
  },

  // Infrastructure
  {
    patterns: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    stack: "docker",
    category: "infrastructure",
    agents: ["infrastructure-audit"],
  },
  {
    patterns: ["k8s/", "kubernetes/", "helm/"],
    stack: "kubernetes",
    category: "infrastructure",
    agents: ["infrastructure-audit"],
  },
  {
    patterns: ["terraform/", "terraform.tf"],
    stack: "terraform",
    category: "infrastructure",
    agents: ["infrastructure-audit"],
  },
  {
    patterns: ["ansible/", "playbook.yml"],
    stack: "ansible",
    category: "infrastructure",
    agents: ["infrastructure-audit"],
  },

  // Database
  {
    patterns: ["prisma/", "schema.prisma"],
    stack: "prisma",
    category: "database",
    agents: ["database-audit"],
  },
  {
    patterns: ["migrations/"],
    stack: "sql-database",
    category: "database",
    agents: ["database-audit"],
  },
  {
    patterns: ["mongod.conf", "mongodb.conf"],
    stack: "mongodb",
    category: "database",
    agents: ["database-audit"],
  },

  // AI/LLM Agents
  {
    patterns: ["SKILL.md", "skills/"],
    stack: "claude-skills",
    category: "ai-agent",
    agents: ["llm-ai-audit"],
  },
  {
    patterns: ["CLAUDE.md"],
    stack: "claude-code",
    category: "ai-agent",
    agents: ["llm-ai-audit"],
  },
  {
    patterns: ["AGENTS.md"],
    stack: "ai-agents",
    category: "ai-agent",
    agents: ["llm-ai-audit"],
  },
  {
    patterns: [".cursorrules"],
    stack: "cursor",
    category: "ai-agent",
    agents: ["llm-ai-audit"],
  },
  {
    patterns: ["COPILOT.md", ".github/copilot-instructions.md"],
    stack: "copilot",
    category: "ai-agent",
    agents: ["llm-ai-audit"],
  },

  // Web Server / Hosting
  {
    patterns: ["nginx.conf", "nginx/"],
    stack: "nginx",
    category: "infrastructure",
    agents: ["ssl-tls-audit", "cors-audit"],
  },
  {
    patterns: ["vercel.json"],
    stack: "vercel",
    category: "static-hosting",
    agents: ["static-site-audit"],
  },
  {
    patterns: ["netlify.toml"],
    stack: "netlify",
    category: "static-hosting",
    agents: ["static-site-audit"],
  },

  // API Spec files
  {
    patterns: ["openapi.yaml", "openapi.json", "swagger.json", "swagger.yaml"],
    stack: "openapi",
    category: "framework",
    agents: ["api-audit", "cors-audit"],
  },

  // Secrets / Config
  {
    patterns: [".env", ".env.local", ".env.production"],
    stack: "dotenv",
    category: "runtime",
    agents: ["data-privacy-audit"],
  },
];

// Agents always included regardless of detection
const ALWAYS_INCLUDE_AGENTS = ["supply-chain-audit", "data-privacy-audit"];

/**
 * Detect the technology stack of a project at the given path.
 */
export async function detectStack(
  projectPath: string
): Promise<StackDetectionResult> {
  const stacks: DetectedStack[] = [];
  const agentSet = new Set<string>(ALWAYS_INCLUDE_AGENTS);
  const indicators: IndicatorMatch[] = [];

  for (const rule of INDICATOR_RULES) {
    for (const pattern of rule.patterns) {
      const fullPath = path.join(projectPath, pattern);
      const exists = await fileOrDirExists(fullPath);

      indicators.push({
        file: pattern,
        stack: rule.stack,
        exists,
      });

      if (exists) {
        // Check if this stack was already detected
        if (!stacks.find((s) => s.name === rule.stack)) {
          let version: string | undefined;

          // Try to extract version if extractor exists
          if (rule.versionExtractor) {
            try {
              const content = await fs.promises.readFile(fullPath, "utf-8");
              version = rule.versionExtractor(content);
            } catch {
              // File might be a directory, skip version extraction
            }
          }

          stacks.push({
            name: rule.stack,
            category: rule.category,
            confidence: 1.0,
            version,
          });
        }

        // Add agents for this rule
        for (const agent of rule.agents) {
          agentSet.add(agent);
        }
      }
    }
  }

  // Extension-based detection for stacks that need glob matching
  const extensionChecks: Array<{
    ext: string;
    stack: string;
    category: StackCategory;
    agents: string[];
  }> = [
    { ext: ".tf", stack: "terraform", category: "infrastructure", agents: ["infrastructure-audit"] },
    { ext: ".xcodeproj", stack: "ios", category: "mobile", agents: ["mobile-audit"] },
    { ext: ".sql", stack: "sql-database", category: "database", agents: ["database-audit"] },
    { ext: ".prisma", stack: "prisma", category: "database", agents: ["database-audit"] },
  ];

  for (const check of extensionChecks) {
    if (!stacks.find((s) => s.name === check.stack)) {
      if (await hasFileWithExtension(projectPath, check.ext)) {
        stacks.push({
          name: check.stack,
          category: check.category,
          confidence: 0.8,
        });
        for (const agent of check.agents) {
          agentSet.add(agent);
        }
      }
    }
  }

  // Additional heuristic: check package.json for framework-specific deps
  const pkgPath = path.join(projectPath, "package.json");
  if (await fileOrDirExists(pkgPath)) {
    try {
      const content = await fs.promises.readFile(pkgPath, "utf-8");
      const pkg = JSON.parse(content);
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      // Check for WebSocket libraries
      if (allDeps["socket.io"] || allDeps["ws"] || allDeps["socket.io-client"]) {
        agentSet.add("websocket-audit");
        if (!stacks.find((s) => s.name === "websocket")) {
          stacks.push({
            name: "websocket",
            category: "framework",
            confidence: 0.9,
          });
        }
      }

      // Check for API frameworks
      if (allDeps["express"] || allDeps["fastify"] || allDeps["hono"] || allDeps["koa"]) {
        agentSet.add("api-audit");
        agentSet.add("cors-audit");
      }

      // Check for AI/LLM libraries
      if (
        allDeps["openai"] ||
        allDeps["@anthropic-ai/sdk"] ||
        allDeps["langchain"] ||
        allDeps["llamaindex"]
      ) {
        agentSet.add("llm-ai-audit");
        if (!stacks.find((s) => s.name === "llm-sdk")) {
          stacks.push({
            name: "llm-sdk",
            category: "ai-agent",
            confidence: 0.9,
          });
        }
      }

      // Check for database ORMs
      if (
        allDeps["prisma"] ||
        allDeps["@prisma/client"] ||
        allDeps["typeorm"] ||
        allDeps["sequelize"] ||
        allDeps["mongoose"] ||
        allDeps["drizzle-orm"]
      ) {
        agentSet.add("database-audit");
      }
    } catch {
      // Invalid package.json, skip
    }
  }

  // Shallow recursion: check 1 level of subdirectories for indicator files
  // This catches cases like mcp-servers/sentinel-scanner/package.json
  try {
    const entries = await fs.promises.readdir(projectPath, { withFileTypes: true });
    const subdirs = entries
      .filter((e) => e.isDirectory() && !e.name.startsWith(".") && e.name !== "node_modules" && e.name !== "dist")
      .map((e) => e.name);

    for (const subdir of subdirs) {
      const subPath = path.join(projectPath, subdir);
      // Recurse one more level into immediate children
      let subEntries: fs.Dirent[];
      try {
        subEntries = await fs.promises.readdir(subPath, { withFileTypes: true });
      } catch {
        continue;
      }
      const nestedDirs = subEntries
        .filter((e) => e.isDirectory() && !e.name.startsWith(".") && e.name !== "node_modules")
        .map((e) => e.name);

      const dirsToCheck = [subPath, ...nestedDirs.map((d) => path.join(subPath, d))];

      for (const checkDir of dirsToCheck) {
        for (const rule of INDICATOR_RULES) {
          if (stacks.find((s) => s.name === rule.stack)) continue;
          for (const pattern of rule.patterns) {
            if (pattern.includes("/")) continue; // Skip path-based patterns for shallow scan
            const fullPath = path.join(checkDir, pattern);
            if (await fileOrDirExists(fullPath)) {
              stacks.push({
                name: rule.stack,
                category: rule.category,
                confidence: 0.7, // Lower confidence for subdirectory matches
              });
              for (const agent of rule.agents) {
                agentSet.add(agent);
              }
              indicators.push({ file: path.relative(projectPath, fullPath), stack: rule.stack, exists: true });
              break;
            }
          }
        }
      }
    }
  } catch {
    // If we can't read subdirectories, skip shallow recursion silently
  }

  return {
    stacks,
    agents: Array.from(agentSet).sort(),
    indicators: indicators.filter((i) => i.exists),
  };
}

async function fileOrDirExists(p: string): Promise<boolean> {
  try {
    await fs.promises.access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if any file matching a glob extension exists in a directory.
 * Used for patterns like "*.tf", "*.sql", "*.xcodeproj".
 */
async function hasFileWithExtension(
  dir: string,
  extension: string
): Promise<boolean> {
  try {
    const entries = await fs.promises.readdir(dir);
    return entries.some((entry) => entry.endsWith(extension));
  } catch {
    return false;
  }
}

/**
 * Format detection results as a human-readable summary.
 */
export function formatDetectionSummary(result: StackDetectionResult): string {
  const lines: string[] = [];
  lines.push("## Stack Detection Results\n");

  if (result.stacks.length === 0) {
    lines.push("No specific technology stack detected.\n");
  } else {
    lines.push("| Stack | Category | Confidence | Version |");
    lines.push("|-------|----------|------------|---------|");
    for (const s of result.stacks) {
      lines.push(
        `| ${s.name} | ${s.category} | ${Math.round(s.confidence * 100)}% | ${s.version || "-"} |`
      );
    }
    lines.push("");
  }

  lines.push(`**Agents to dispatch** (${result.agents.length}):`);
  for (const agent of result.agents) {
    lines.push(`- ${agent}`);
  }

  return lines.join("\n");
}
