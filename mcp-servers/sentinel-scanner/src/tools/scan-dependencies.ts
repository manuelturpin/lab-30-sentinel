/**
 * scan-dependencies tool — Dependency vulnerability analysis
 *
 * Parses lockfiles, queries OSV API for known vulnerabilities.
 */

import * as fs from "fs";
import * as path from "path";
import * as https from "https";

export interface DependencyScanResult {
  ecosystem: string;
  totalDependencies: number;
  vulnerableDependencies: number;
  vulnerabilities: DependencyVulnerability[];
}

export interface DependencyVulnerability {
  package: string;
  installedVersion: string;
  fixedVersion?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cveId?: string;
  osvId?: string;
  ghsaId?: string;
  title: string;
  description: string;
  cvss_v4?: number;
  epss?: number;
  references: string[];
}

interface PackageInfo {
  name: string;
  version: string;
}

type Ecosystem = "npm" | "pypi" | "go" | "cargo" | "gem" | "maven";

function detectEcosystem(projectPath: string): Ecosystem | null {
  const checks: Array<{ file: string; ecosystem: Ecosystem }> = [
    { file: "package-lock.json", ecosystem: "npm" },
    { file: "yarn.lock", ecosystem: "npm" },
    { file: "requirements.txt", ecosystem: "pypi" },
    { file: "Pipfile.lock", ecosystem: "pypi" },
    { file: "go.sum", ecosystem: "go" },
    { file: "Cargo.lock", ecosystem: "cargo" },
    { file: "Gemfile.lock", ecosystem: "gem" },
    { file: "pom.xml", ecosystem: "maven" },
  ];

  for (const check of checks) {
    if (fs.existsSync(path.join(projectPath, check.file))) {
      return check.ecosystem;
    }
  }
  return null;
}

function parseNpmLockfile(projectPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];

  // Try package-lock.json first
  const lockPath = path.join(projectPath, "package-lock.json");
  if (fs.existsSync(lockPath)) {
    try {
      const content = JSON.parse(fs.readFileSync(lockPath, "utf-8"));

      // v3 lockfile format (packages)
      if (content.packages) {
        for (const [pkgPath, info] of Object.entries(content.packages)) {
          if (pkgPath === "") continue; // root package
          const name = pkgPath.replace(/^node_modules\//, "");
          const version = (info as { version?: string }).version;
          if (name && version) {
            packages.push({ name, version });
          }
        }
      }
      // v1 lockfile format (dependencies)
      else if (content.dependencies) {
        for (const [name, info] of Object.entries(content.dependencies)) {
          const version = (info as { version?: string }).version;
          if (version) {
            packages.push({ name, version });
          }
        }
      }
    } catch {
      // Invalid JSON
    }
    return packages;
  }

  // Try yarn.lock (simpler parsing)
  const yarnPath = path.join(projectPath, "yarn.lock");
  if (fs.existsSync(yarnPath)) {
    try {
      const content = fs.readFileSync(yarnPath, "utf-8");
      const lines = content.split("\n");
      let currentPkg = "";

      for (const line of lines) {
        // Package header line: "package@version:"
        const headerMatch = line.match(/^"?([^@\s]+)@[^"]*"?:$/);
        if (headerMatch) {
          currentPkg = headerMatch[1];
          continue;
        }
        // Version line
        const versionMatch = line.match(/^\s+version\s+"([^"]+)"/);
        if (versionMatch && currentPkg) {
          packages.push({ name: currentPkg, version: versionMatch[1] });
          currentPkg = "";
        }
      }
    } catch {
      // Invalid file
    }
  }

  return packages;
}

function parsePypiDeps(projectPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];

  const reqPath = path.join(projectPath, "requirements.txt");
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, "utf-8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
        const match = trimmed.match(/^([a-zA-Z0-9_.-]+)==([a-zA-Z0-9_.]+)/);
        if (match) {
          packages.push({ name: match[1], version: match[2] });
        }
      }
    } catch { /* skip */ }
    return packages;
  }

  const pipfilePath = path.join(projectPath, "Pipfile.lock");
  if (fs.existsSync(pipfilePath)) {
    try {
      const content = JSON.parse(fs.readFileSync(pipfilePath, "utf-8"));
      const defaultDeps = content.default || {};
      for (const [name, info] of Object.entries(defaultDeps)) {
        const version = (info as { version?: string }).version?.replace("==", "");
        if (version) {
          packages.push({ name, version });
        }
      }
    } catch { /* skip */ }
  }

  return packages;
}

function parseGoSum(projectPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const sumPath = path.join(projectPath, "go.sum");

  if (!fs.existsSync(sumPath)) return packages;

  try {
    const content = fs.readFileSync(sumPath, "utf-8");
    const seen = new Set<string>();

    for (const line of content.split("\n")) {
      const match = line.match(/^(\S+)\s+v([^\s/]+)/);
      if (match) {
        const key = `${match[1]}@${match[2]}`;
        if (!seen.has(key)) {
          seen.add(key);
          packages.push({ name: match[1], version: match[2] });
        }
      }
    }
  } catch { /* skip */ }

  return packages;
}

function parseCargoLock(projectPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const lockPath = path.join(projectPath, "Cargo.lock");

  if (!fs.existsSync(lockPath)) return packages;

  try {
    const content = fs.readFileSync(lockPath, "utf-8");
    const blocks = content.split("[[package]]");

    for (const block of blocks.slice(1)) {
      const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
      const versionMatch = block.match(/version\s*=\s*"([^"]+)"/);
      if (nameMatch && versionMatch) {
        packages.push({ name: nameMatch[1], version: versionMatch[1] });
      }
    }
  } catch { /* skip */ }

  return packages;
}

function parseGemfileLock(projectPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const lockPath = path.join(projectPath, "Gemfile.lock");

  if (!fs.existsSync(lockPath)) return packages;

  try {
    const content = fs.readFileSync(lockPath, "utf-8");
    let inSpecs = false;

    for (const line of content.split("\n")) {
      if (line.trim() === "specs:") {
        inSpecs = true;
        continue;
      }
      if (inSpecs && line.match(/^\S/)) {
        inSpecs = false;
        continue;
      }
      if (inSpecs) {
        const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (match) {
          packages.push({ name: match[1], version: match[2] });
        }
      }
    }
  } catch { /* skip */ }

  return packages;
}

function parseDependencies(projectPath: string, ecosystem: Ecosystem): PackageInfo[] {
  switch (ecosystem) {
    case "npm": return parseNpmLockfile(projectPath);
    case "pypi": return parsePypiDeps(projectPath);
    case "go": return parseGoSum(projectPath);
    case "cargo": return parseCargoLock(projectPath);
    case "gem": return parseGemfileLock(projectPath);
    case "maven": return []; // Maven lockfile parsing is complex; skip for now
  }
}

const OSV_ECOSYSTEM_MAP: Record<Ecosystem, string> = {
  npm: "npm",
  pypi: "PyPI",
  go: "Go",
  cargo: "crates.io",
  gem: "RubyGems",
  maven: "Maven",
};

interface OSVQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

interface OSVVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  references?: Array<{ type: string; url: string }>;
}

interface OSVBatchResponse {
  results: Array<{ vulns?: OSVVuln[] }>;
}

function queryOSVBatch(queries: OSVQuery[]): Promise<OSVBatchResponse> {
  return new Promise((resolve) => {
    if (queries.length === 0) {
      resolve({ results: [] });
      return;
    }

    const body = JSON.stringify({ queries });
    const options = {
      hostname: "api.osv.dev",
      path: "/v1/querybatch",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve({ results: [] });
        }
      });
    });

    req.on("error", () => {
      resolve({ results: [] });
    });

    req.setTimeout(30000, () => {
      req.destroy();
      resolve({ results: [] });
    });

    req.write(body);
    req.end();
  });
}

function osvSeverityToLevel(vuln: OSVVuln): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  if (vuln.severity && vuln.severity.length > 0) {
    for (const s of vuln.severity) {
      if (s.type === "CVSS_V3" || s.type === "CVSS_V4") {
        // OSV score field can be either a numeric string ("7.5") or a
        // CVSS vector string ("CVSS:3.1/AV:N/AC:L/..."). Try numeric first.
        const directScore = parseFloat(s.score);
        if (!isNaN(directScore) && directScore <= 10) {
          if (directScore >= 9.0) return "CRITICAL";
          if (directScore >= 7.0) return "HIGH";
          if (directScore >= 4.0) return "MEDIUM";
          return "LOW";
        }
        // If it's a vector string, we can't extract a numeric score without
        // a full CVSS calculator. Fall through to default.
      }
    }
  }
  // Check database_specific severity if available
  const dbSeverity = (vuln as unknown as Record<string, unknown>).database_specific;
  if (dbSeverity && typeof dbSeverity === "object" && dbSeverity !== null) {
    const sev = (dbSeverity as Record<string, unknown>).severity;
    if (typeof sev === "string") {
      const upper = sev.toUpperCase();
      if (upper === "CRITICAL") return "CRITICAL";
      if (upper === "HIGH") return "HIGH";
      if (upper === "MODERATE" || upper === "MEDIUM") return "MEDIUM";
      if (upper === "LOW") return "LOW";
    }
  }
  return "MEDIUM"; // Default if no score
}

function extractFixedVersion(vuln: OSVVuln): string | undefined {
  if (!vuln.affected) return undefined;
  for (const affected of vuln.affected) {
    if (!affected.ranges) continue;
    for (const range of affected.ranges) {
      for (const event of range.events) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return undefined;
}

export async function scanDependencies(
  projectPath: string,
  ecosystem: string
): Promise<DependencyScanResult> {
  try {
  // Detect ecosystem if auto
  let detectedEcosystem: Ecosystem | null;
  if (ecosystem === "auto") {
    detectedEcosystem = detectEcosystem(projectPath);
    if (!detectedEcosystem) {
      return {
        ecosystem: "unknown",
        totalDependencies: 0,
        vulnerableDependencies: 0,
        vulnerabilities: [],
      };
    }
  } else {
    detectedEcosystem = ecosystem as Ecosystem;
  }

  // Parse dependencies
  const packages = parseDependencies(projectPath, detectedEcosystem);

  if (packages.length === 0) {
    return {
      ecosystem: detectedEcosystem,
      totalDependencies: 0,
      vulnerableDependencies: 0,
      vulnerabilities: [],
    };
  }

  // Query OSV in batches of 100
  const osvEcosystem = OSV_ECOSYSTEM_MAP[detectedEcosystem];
  const vulnerabilities: DependencyVulnerability[] = [];
  const batchSize = 100;

  for (let i = 0; i < packages.length; i += batchSize) {
    const batch = packages.slice(i, i + batchSize);
    const queries: OSVQuery[] = batch.map(pkg => ({
      package: { name: pkg.name, ecosystem: osvEcosystem },
      version: pkg.version,
    }));

    const response = await queryOSVBatch(queries);

    if (response.results) {
      for (let j = 0; j < response.results.length; j++) {
        const result = response.results[j];
        if (!result.vulns || result.vulns.length === 0) continue;

        const pkg = batch[j];
        for (const vuln of result.vulns) {
          const cveId = vuln.aliases?.find(a => a.startsWith("CVE-"));
          const ghsaId = vuln.aliases?.find(a => a.startsWith("GHSA-"));

          vulnerabilities.push({
            package: pkg.name,
            installedVersion: pkg.version,
            fixedVersion: extractFixedVersion(vuln),
            severity: osvSeverityToLevel(vuln),
            cveId,
            osvId: vuln.id,
            ghsaId,
            title: vuln.summary || vuln.id,
            description: vuln.details || vuln.summary || "No description available",
            references: vuln.references?.map(r => r.url) || [],
          });
        }
      }
    }
  }

  const vulnerablePackages = new Set(vulnerabilities.map(v => v.package));

  return {
    ecosystem: detectedEcosystem,
    totalDependencies: packages.length,
    vulnerableDependencies: vulnerablePackages.size,
    vulnerabilities,
  };
  } catch (err) {
    return {
      ecosystem: ecosystem === "auto" ? "unknown" : ecosystem,
      totalDependencies: 0,
      vulnerableDependencies: 0,
      vulnerabilities: [],
      error: err instanceof Error ? err.message : String(err),
    } as DependencyScanResult & { error: string };
  }
}
