/**
 * scan-dependencies tool — Dependency vulnerability analysis
 *
 * Skeleton for Session 5 implementation.
 * Will: parse lock files, query OSV + NVD, report vulnerable deps.
 */

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

export async function scanDependencies(
  _projectPath: string,
  _ecosystem: string
): Promise<DependencyScanResult> {
  // Skeleton — implementation in Session 5
  return {
    ecosystem: _ecosystem,
    totalDependencies: 0,
    vulnerableDependencies: 0,
    vulnerabilities: [],
  };
}
