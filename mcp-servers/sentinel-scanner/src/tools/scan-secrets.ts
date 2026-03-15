/**
 * scan-secrets tool — Secret and credential detection
 *
 * Scans files for hardcoded secrets using regex patterns.
 * Redacts actual values in output.
 */

import * as fs from "fs";
import * as path from "path";
import { execFile } from "child_process";

export interface SecretScanResult {
  totalFilesScanned: number;
  secretsFound: number;
  secrets: DetectedSecret[];
}

export interface DetectedSecret {
  type: SecretType;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  file: string;
  line: number;
  snippet: string; // Redacted snippet showing context
  description: string;
  remediation: string;
}

export type SecretType =
  | "api_key"
  | "password"
  | "token"
  | "private_key"
  | "connection_string"
  | "oauth_secret"
  | "webhook_url"
  | "encryption_key"
  | "high_entropy_string";

// Common secret patterns (redacted in output)
export const SECRET_PATTERNS: Record<SecretType, RegExp[]> = {
  api_key: [
    /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{16,}['"]/i,
    /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/,
    /sk-[a-zA-Z0-9]{20,}/,
  ],
  password: [
    /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]/i,
  ],
  token: [
    /(?:token|bearer)\s*[:=]\s*['"][^'"]{20,}['"]/i,
    /ghp_[a-zA-Z0-9]{36}/,
    /gho_[a-zA-Z0-9]{36}/,
    /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,
  ],
  private_key: [
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  ],
  connection_string: [
    /(?:mongodb|postgres|mysql|redis):\/\/[^:\s]+:[^@\s]+@/,
  ],
  oauth_secret: [
    /(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['"][^'"]{10,}['"]/i,
  ],
  webhook_url: [
    /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/,
    /https:\/\/discord\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/,
  ],
  encryption_key: [
    /(?:encrypt|cipher|aes)[_-]?key\s*[:=]\s*['"][^'"]{16,}['"]/i,
  ],
  high_entropy_string: [],
};

const SECRET_SEVERITY: Record<SecretType, "CRITICAL" | "HIGH" | "MEDIUM"> = {
  private_key: "CRITICAL",
  api_key: "CRITICAL",
  connection_string: "CRITICAL",
  password: "HIGH",
  token: "HIGH",
  oauth_secret: "HIGH",
  encryption_key: "HIGH",
  webhook_url: "MEDIUM",
  high_entropy_string: "MEDIUM",
};

const SECRET_REMEDIATION: Record<SecretType, string> = {
  api_key: "Move API keys to environment variables or a secrets manager. Rotate the exposed key immediately.",
  password: "Remove hardcoded passwords. Use environment variables or a vault service. Rotate the password.",
  token: "Move tokens to environment variables. Revoke and regenerate the exposed token.",
  private_key: "Remove private keys from source code. Store in a secure key management system. Generate a new key pair.",
  connection_string: "Move connection strings to environment variables. Rotate database credentials.",
  oauth_secret: "Move OAuth secrets to environment variables. Regenerate the client secret.",
  webhook_url: "Move webhook URLs to environment variables. Consider regenerating the webhook.",
  encryption_key: "Move encryption keys to a key management service. Rotate the key and re-encrypt data.",
  high_entropy_string: "Review this string — it may be a secret. If so, move to environment variables.",
};

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".pdf", ".zip", ".tar", ".gz", ".bz2",
  ".exe", ".dll", ".so", ".dylib",
  ".mp3", ".mp4", ".wav", ".avi", ".mov",
  ".sqlite", ".db", ".lock",
]);

const EXCLUDE_DIRS = new Set([
  "node_modules", "dist", "build", ".git", ".next",
  "__pycache__", ".venv", "venv", "vendor", "target",
  ".angular", ".nuxt", "coverage",
]);

function isBinaryExtension(file: string): boolean {
  return BINARY_EXTENSIONS.has(path.extname(file).toLowerCase());
}

function redactSecret(line: string, match: RegExpMatchArray): string {
  const matchedText = match[0];
  // Replace the entire matched secret with a redacted version
  // Show first 4 chars for context, redact the rest
  let redactedMatch: string;
  if (matchedText.length <= 8) {
    redactedMatch = "[REDACTED]";
  } else {
    redactedMatch = matchedText.slice(0, 4) + "[REDACTED]";
  }
  return line.replace(matchedText, redactedMatch);
}

const MAX_SECRET_SCAN_FILES = 10000;

function walkProjectFiles(dir: string): string[] {
  const results: string[] = [];

  function walk(currentDir: string): void {
    if (results.length >= MAX_SECRET_SCAN_FILES) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= MAX_SECRET_SCAN_FILES) return;
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        if (!isBinaryExtension(entry.name)) {
          results.push(fullPath);
        }
      }
    }
  }

  walk(dir);
  return results;
}

function scanGitHistory(projectPath: string): Promise<DetectedSecret[]> {
  return new Promise((resolve) => {
    execFile(
      "git",
      ["log", "-p", "--all", "--diff-filter=A", "-n", "100", "--"],
      { cwd: projectPath, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout) => {
        if (error || !stdout) {
          resolve([]);
          return;
        }

        const secrets: DetectedSecret[] = [];
        const lines = stdout.split("\n");
        let currentFile = "";

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];

          // Track current file in diff
          const diffMatch = line.match(/^\+\+\+ b\/(.+)$/);
          if (diffMatch) {
            currentFile = diffMatch[1];
            continue;
          }

          // Only scan added lines
          if (!line.startsWith("+") || line.startsWith("+++")) continue;

          const addedLine = line.slice(1);

          for (const [secretType, patterns] of Object.entries(SECRET_PATTERNS)) {
            for (const pattern of patterns) {
              const match = addedLine.match(pattern);
              if (match) {
                secrets.push({
                  type: secretType as SecretType,
                  severity: SECRET_SEVERITY[secretType as SecretType],
                  file: `[git history] ${currentFile}`,
                  line: 0,
                  snippet: redactSecret(addedLine.trim(), match),
                  description: `${secretType.replace(/_/g, " ")} found in git history`,
                  remediation: SECRET_REMEDIATION[secretType as SecretType],
                });
                break;
              }
            }
          }
        }

        resolve(secrets);
      }
    );
  });
}

export async function scanSecrets(
  projectPath: string,
  includeGitHistory: boolean
): Promise<SecretScanResult> {
  const files = walkProjectFiles(projectPath);
  const secrets: DetectedSecret[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const lines = content.split("\n");
    const relativePath = path.relative(projectPath, file);

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      let lineMatched = false;

      for (const [secretType, patterns] of Object.entries(SECRET_PATTERNS)) {
        if (lineMatched) break;
        for (const pattern of patterns) {
          const match = line.match(pattern);
          if (match) {
            secrets.push({
              type: secretType as SecretType,
              severity: SECRET_SEVERITY[secretType as SecretType],
              file: relativePath,
              line: lineIdx + 1,
              snippet: redactSecret(line.trim(), match),
              description: `Potential ${secretType.replace(/_/g, " ")} detected`,
              remediation: SECRET_REMEDIATION[secretType as SecretType],
            });
            lineMatched = true;
            break;
          }
        }
      }
    }
  }

  // Optional git history scan
  if (includeGitHistory) {
    const gitSecrets = await scanGitHistory(projectPath);
    secrets.push(...gitSecrets);
  }

  return {
    totalFilesScanned: files.length,
    secretsFound: secrets.length,
    secrets,
  };
}
