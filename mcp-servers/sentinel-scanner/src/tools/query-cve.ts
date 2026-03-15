/**
 * query-cve tool — CVE database query
 *
 * Queries local cache files (NVD, OSV, GitHub Advisories) for CVEs
 * affecting a specific component or package.
 */

import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

export interface CVEQueryResult {
  component: string;
  version?: string;
  ecosystem?: string;
  totalResults: number;
  vulnerabilities: CVEEntry[];
}

export interface CVEEntry {
  id: string; // CVE-YYYY-NNNNN
  osvId?: string;
  ghsaId?: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss_v4?: number;
  cvss_v3?: number;
  epss?: number;
  published: string;
  modified: string;
  affectedVersions: string;
  fixedVersions?: string;
  references: string[];
  cwe?: string[];
}

interface NVDCacheEntry {
  id: string;
  description?: string;
  severity?: string;
  cvss_v4?: number;
  cvss_v3?: number;
  epss?: number;
  published?: string;
  modified?: string;
  affected_packages?: Array<{
    name: string;
    ecosystem?: string;
    versions?: string;
    fixed?: string;
  }>;
  references?: string[];
  cwe?: string[];
}

interface OSVCacheEntry {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name: string; ecosystem?: string };
    ranges?: Array<{
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  published?: string;
  modified?: string;
  references?: Array<{ url: string }>;
}

interface GHSACacheEntry {
  id: string;
  ghsa_id?: string;
  summary?: string;
  description?: string;
  severity?: string;
  cvss_score?: number;
  published_at?: string;
  updated_at?: string;
  vulnerabilities?: Array<{
    package?: { name: string; ecosystem?: string };
    vulnerable_version_range?: string;
    first_patched_version?: string;
  }>;
  references?: string[];
  cwe?: string[];
}

function resolveCVECachePath(): string {
  const thisFile = fileURLToPath(import.meta.url);
  return path.resolve(path.dirname(thisFile), "..", "..", "..", "..", "knowledge-base", "cve-feed");
}

function loadJSONFile<T>(filePath: string, defaultValue: T): T {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  } catch {
    return defaultValue;
  }
}

function matchesComponent(name: string, component: string): boolean {
  return name.toLowerCase().includes(component.toLowerCase());
}

function parseSeverity(severity?: string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  if (!severity) return "MEDIUM";
  const upper = severity.toUpperCase();
  if (upper === "CRITICAL") return "CRITICAL";
  if (upper === "HIGH") return "HIGH";
  if (upper === "MEDIUM" || upper === "MODERATE") return "MEDIUM";
  return "LOW";
}

export async function queryCVE(
  component: string,
  version?: string,
  ecosystem?: string
): Promise<CVEQueryResult> {
  const cachePath = resolveCVECachePath();
  const vulnerabilities: CVEEntry[] = [];
  const seenIds = new Set<string>();

  // Load NVD cache
  const nvdCache = loadJSONFile<{ vulnerabilities: NVDCacheEntry[] }>(
    path.join(cachePath, "nvd-cache.json"),
    { vulnerabilities: [] }
  );

  for (const entry of nvdCache.vulnerabilities) {
    if (seenIds.has(entry.id)) continue;

    const matchesPackage = entry.affected_packages?.some(pkg => {
      if (!matchesComponent(pkg.name, component)) return false;
      if (ecosystem && pkg.ecosystem && pkg.ecosystem.toLowerCase() !== ecosystem.toLowerCase()) return false;
      return true;
    });

    if (!matchesPackage) continue;

    seenIds.add(entry.id);
    const affectedPkg = entry.affected_packages?.find(p => matchesComponent(p.name, component));

    vulnerabilities.push({
      id: entry.id,
      title: entry.description?.slice(0, 120) || entry.id,
      description: entry.description || "No description available",
      severity: parseSeverity(entry.severity),
      cvss_v4: entry.cvss_v4,
      cvss_v3: entry.cvss_v3,
      epss: entry.epss,
      published: entry.published || "",
      modified: entry.modified || "",
      affectedVersions: affectedPkg?.versions || "unknown",
      fixedVersions: affectedPkg?.fixed,
      references: entry.references || [],
      cwe: entry.cwe,
    });
  }

  // Load OSV cache
  const osvCache = loadJSONFile<{ vulnerabilities: OSVCacheEntry[] }>(
    path.join(cachePath, "osv-cache.json"),
    { vulnerabilities: [] }
  );

  for (const entry of osvCache.vulnerabilities) {
    const cveId = entry.aliases?.find(a => a.startsWith("CVE-")) || entry.id;
    if (seenIds.has(cveId)) continue;

    const matchesPackage = entry.affected?.some(aff => {
      if (!aff.package) return false;
      if (!matchesComponent(aff.package.name, component)) return false;
      if (ecosystem && aff.package.ecosystem &&
          aff.package.ecosystem.toLowerCase() !== ecosystem.toLowerCase()) return false;
      return true;
    });

    if (!matchesPackage) continue;

    seenIds.add(cveId);

    let fixedVersion: string | undefined;
    let affectedVersions = "unknown";
    const affectedEntry = entry.affected?.find(a =>
      a.package && matchesComponent(a.package.name, component)
    );
    if (affectedEntry?.ranges) {
      const events = affectedEntry.ranges[0]?.events || [];
      const introduced = events.find(e => e.introduced)?.introduced;
      const fixed = events.find(e => e.fixed)?.fixed;
      if (introduced) affectedVersions = `>=${introduced}`;
      if (fixed) {
        fixedVersion = fixed;
        affectedVersions += `, <${fixed}`;
      }
    }

    vulnerabilities.push({
      id: cveId,
      osvId: entry.id,
      title: entry.summary || cveId,
      description: entry.details || entry.summary || "No description available",
      severity: "MEDIUM", // OSV doesn't always have severity
      published: entry.published || "",
      modified: entry.modified || "",
      affectedVersions,
      fixedVersions: fixedVersion,
      references: entry.references?.map(r => r.url) || [],
    });
  }

  // Load GitHub Advisories cache
  const ghsaCache = loadJSONFile<{ advisories: GHSACacheEntry[] }>(
    path.join(cachePath, "github-advisories.json"),
    { advisories: [] }
  );

  for (const entry of ghsaCache.advisories) {
    const cveId = entry.id.startsWith("CVE-") ? entry.id : (entry.ghsa_id || entry.id);
    if (seenIds.has(cveId)) continue;

    const matchesPackage = entry.vulnerabilities?.some(vuln => {
      if (!vuln.package) return false;
      if (!matchesComponent(vuln.package.name, component)) return false;
      if (ecosystem && vuln.package.ecosystem &&
          vuln.package.ecosystem.toLowerCase() !== ecosystem.toLowerCase()) return false;
      return true;
    });

    if (!matchesPackage) continue;

    seenIds.add(cveId);

    const vulnEntry = entry.vulnerabilities?.find(v =>
      v.package && matchesComponent(v.package.name, component)
    );

    vulnerabilities.push({
      id: cveId,
      ghsaId: entry.ghsa_id,
      title: entry.summary || cveId,
      description: entry.description || entry.summary || "No description available",
      severity: parseSeverity(entry.severity),
      cvss_v3: entry.cvss_score,
      published: entry.published_at || "",
      modified: entry.updated_at || "",
      affectedVersions: vulnEntry?.vulnerable_version_range || "unknown",
      fixedVersions: vulnEntry?.first_patched_version,
      references: entry.references || [],
      cwe: entry.cwe,
    });
  }

  return {
    component,
    version,
    ecosystem,
    totalResults: vulnerabilities.length,
    vulnerabilities,
  };
}
