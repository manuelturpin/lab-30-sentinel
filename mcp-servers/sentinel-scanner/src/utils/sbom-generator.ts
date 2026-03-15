/**
 * SBOM Generator — Generates CycloneDX Software Bill of Materials
 *
 * Parses project manifests (package.json, requirements.txt, go.mod, etc.)
 * to produce a CycloneDX 1.5 SBOM with optional vulnerability mapping.
 */

import { randomUUID } from "crypto";
import * as fs from "fs";
import * as path from "path";
import type { Finding } from "./types.js";

export interface CycloneDXBOM {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component: {
      type: "application";
      name: string;
      version: string;
    };
  };
  components: CycloneDXComponent[];
  vulnerabilities?: CycloneDXVulnerability[];
}

export interface CycloneDXComponent {
  type: "library" | "framework" | "application" | "container" | "device" | "firmware" | "file" | "operating-system";
  name: string;
  version: string;
  purl?: string; // Package URL
  licenses?: Array<{ license: { id: string } }>;
  externalReferences?: Array<{ type: string; url: string }>;
}

export interface CycloneDXVulnerability {
  id: string;
  source: { name: string; url: string };
  ratings: Array<{
    score: number;
    severity: string;
    method: string;
  }>;
  description: string;
  recommendation?: string;
  affects: Array<{
    ref: string;
    versions: Array<{ version: string; status: "affected" | "unaffected" }>;
  }>;
}

// --- Helper types ---

interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: string;
}

function generatePURL(ecosystem: string, name: string, version: string): string {
  // Handle scoped npm packages: @scope/name -> %40scope/name
  const encodedName = name.startsWith("@") ? name.replace("@", "%40") : name;
  return `pkg:${ecosystem}/${encodedName}@${version}`;
}

// --- Manifest parsers ---

function parsePackageJson(projectPath: string): ParsedDependency[] {
  const pkgPath = path.join(projectPath, "package.json");
  const deps: ParsedDependency[] = [];

  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    const allDeps: Record<string, string> = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };

    // Try to use package-lock.json for more precise versions
    let lockDeps: Record<string, string> = {};
    const lockPath = path.join(projectPath, "package-lock.json");
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));
      if (lock.packages) {
        for (const [pkgKey, pkgInfo] of Object.entries(lock.packages)) {
          if (pkgKey === "") continue; // root package
          const name = pkgKey.replace(/^node_modules\//, "");
          lockDeps[name] = (pkgInfo as { version?: string }).version || "";
        }
      } else if (lock.dependencies) {
        for (const [name, info] of Object.entries(lock.dependencies)) {
          lockDeps[name] = (info as { version?: string }).version || "";
        }
      }
    } catch {
      // No lock file, use package.json versions
    }

    for (const [name, versionRange] of Object.entries(allDeps)) {
      const version = lockDeps[name] || versionRange.replace(/^[\^~>=<]+/, "");
      deps.push({ name, version, ecosystem: "npm" });
    }
  } catch {
    return [];
  }

  return deps;
}

function parseRequirementsTxt(projectPath: string): ParsedDependency[] {
  const reqPath = path.join(projectPath, "requirements.txt");
  const deps: ParsedDependency[] = [];

  try {
    const content = fs.readFileSync(reqPath, "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

      // Match patterns: package==1.0.0, package>=1.0.0, package~=1.0.0
      const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*[>=~!<]=?\s*([a-zA-Z0-9_.]+)/);
      if (match) {
        deps.push({ name: match[1], version: match[2], ecosystem: "pypi" });
      } else {
        // Package without version specifier
        const nameMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)/);
        if (nameMatch) {
          deps.push({ name: nameMatch[1], version: "unknown", ecosystem: "pypi" });
        }
      }
    }
  } catch {
    return [];
  }

  return deps;
}

function parsePipfileLock(projectPath: string): ParsedDependency[] {
  const lockPath = path.join(projectPath, "Pipfile.lock");
  const deps: ParsedDependency[] = [];

  try {
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));
    for (const section of ["default", "develop"]) {
      const packages = lock[section];
      if (!packages) continue;
      for (const [name, info] of Object.entries(packages)) {
        const version = ((info as { version?: string }).version || "").replace(/^==/, "");
        deps.push({ name, version: version || "unknown", ecosystem: "pypi" });
      }
    }
  } catch {
    return [];
  }

  return deps;
}

function parseGoMod(projectPath: string): ParsedDependency[] {
  const modPath = path.join(projectPath, "go.mod");
  const deps: ParsedDependency[] = [];

  try {
    const content = fs.readFileSync(modPath, "utf-8");
    // Match require block or single require lines
    const requireBlockRegex = /require\s*\(([\s\S]*?)\)/g;
    const singleRequireRegex = /^require\s+(\S+)\s+(v[\S]+)/gm;

    // Parse require blocks
    let blockMatch;
    while ((blockMatch = requireBlockRegex.exec(content)) !== null) {
      const block = blockMatch[1];
      for (const line of block.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("//")) continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length >= 2) {
          deps.push({ name: parts[0], version: parts[1].replace(/^v/, ""), ecosystem: "golang" });
        }
      }
    }

    // Parse single require lines
    let singleMatch;
    while ((singleMatch = singleRequireRegex.exec(content)) !== null) {
      deps.push({ name: singleMatch[1], version: singleMatch[2].replace(/^v/, ""), ecosystem: "golang" });
    }
  } catch {
    return [];
  }

  return deps;
}

function parseGemfileLock(projectPath: string): ParsedDependency[] {
  const lockPath = path.join(projectPath, "Gemfile.lock");
  const deps: ParsedDependency[] = [];

  try {
    const content = fs.readFileSync(lockPath, "utf-8");
    let inSpecs = false;

    for (const line of content.split("\n")) {
      if (line.trim() === "specs:") {
        inSpecs = true;
        continue;
      }
      if (inSpecs) {
        // Specs entries are indented with 4+ spaces: "    name (version)"
        const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (match) {
          deps.push({ name: match[1], version: match[2], ecosystem: "gem" });
        } else if (line.trim() && !line.startsWith(" ")) {
          // No longer in specs section
          inSpecs = false;
        }
      }
    }
  } catch {
    return [];
  }

  return deps;
}

function parsePomXml(projectPath: string): ParsedDependency[] {
  const pomPath = path.join(projectPath, "pom.xml");
  const deps: ParsedDependency[] = [];

  try {
    const content = fs.readFileSync(pomPath, "utf-8");
    // Extract <dependency> blocks
    const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g;

    let match;
    while ((match = depRegex.exec(content)) !== null) {
      const groupId = match[1].trim();
      const artifactId = match[2].trim();
      const version = match[3].trim();
      deps.push({
        name: `${groupId}/${artifactId}`,
        version,
        ecosystem: "maven",
      });
    }
  } catch {
    return [];
  }

  return deps;
}

function parseBuildGradle(projectPath: string): ParsedDependency[] {
  const gradlePath = path.join(projectPath, "build.gradle");
  const deps: ParsedDependency[] = [];

  try {
    const content = fs.readFileSync(gradlePath, "utf-8");
    // Match patterns like: implementation 'group:artifact:version' or compile "group:artifact:version"
    const depRegex = /(?:implementation|compile|api|runtimeOnly|compileOnly|testImplementation|testCompile)\s+['"]([^'"]+)['"]/g;

    let match;
    while ((match = depRegex.exec(content)) !== null) {
      const parts = match[1].split(":");
      if (parts.length >= 3) {
        deps.push({
          name: `${parts[0]}/${parts[1]}`,
          version: parts[2],
          ecosystem: "maven",
        });
      }
    }
  } catch {
    return [];
  }

  return deps;
}

// --- Main SBOM generator ---

/**
 * Generate a CycloneDX SBOM from project dependencies.
 */
export function generateSBOM(
  projectPath: string,
  projectName?: string,
  projectVersion?: string,
  vulnerabilities?: Finding[]
): CycloneDXBOM {
  // Auto-detect project name/version from package.json if not provided
  const pkgJsonPath = path.join(projectPath, "package.json");
  if (!projectName || !projectVersion) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
      projectName = projectName || pkg.name || path.basename(projectPath);
      projectVersion = projectVersion || pkg.version || "0.0.0";
    } catch {
      projectName = projectName || path.basename(projectPath);
      projectVersion = projectVersion || "0.0.0";
    }
  }

  // Collect dependencies from all detected manifests
  const allDeps: ParsedDependency[] = [];
  const parsers = [
    parsePackageJson, parseRequirementsTxt, parsePipfileLock,
    parseGoMod, parseGemfileLock, parsePomXml, parseBuildGradle,
  ];
  for (const parser of parsers) {
    try { allDeps.push(...parser(projectPath)); } catch { /* skip */ }
  }

  // Deduplicate by name+ecosystem
  const seen = new Set<string>();
  const components: CycloneDXComponent[] = [];
  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    components.push({
      type: "library",
      name: dep.name,
      version: dep.version,
      purl: generatePURL(dep.ecosystem, dep.name, dep.version),
    });
  }

  // Map vulnerability findings to CycloneDX format
  const vulns: CycloneDXVulnerability[] = [];
  if (vulnerabilities) {
    for (const finding of vulnerabilities) {
      if (!finding.cwe && !finding.id.startsWith("CVE-")) continue;
      vulns.push({
        id: finding.id,
        source: { name: "Sentinel", url: "https://github.com/bonsai974/sentinel" },
        ratings: [{
          score: finding.cvss_v4 || 0,
          severity: finding.severity.toLowerCase(),
          method: "CVSSv4",
        }],
        description: finding.description,
        recommendation: finding.remediation,
        affects: [{
          ref: finding.location.file,
          versions: [{ version: "unknown", status: "affected" }],
        }],
      });
    }
  }

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "Sentinel", name: "sentinel-scanner", version: "0.1.0" }],
      component: { type: "application", name: projectName!, version: projectVersion! },
    },
    components,
    vulnerabilities: vulns.length > 0 ? vulns : undefined,
  };
}
