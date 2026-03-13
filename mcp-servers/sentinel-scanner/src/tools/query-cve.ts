/**
 * query-cve tool — CVE database query
 *
 * Skeleton for Session 5 implementation.
 * Will: query local cache (NVD + OSV + GitHub Advisories) for CVEs.
 */

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

export async function queryCVE(
  _component: string,
  _version?: string,
  _ecosystem?: string
): Promise<CVEQueryResult> {
  // Skeleton — implementation in Session 5
  return {
    component: _component,
    version: _version,
    ecosystem: _ecosystem,
    totalResults: 0,
    vulnerabilities: [],
  };
}
