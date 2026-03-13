/**
 * Risk Scorer — CVSS v4 + EPSS composite risk calculation
 *
 * Skeleton for Session 8 implementation.
 * CVSS v4: https://www.first.org/cvss/v4-0/
 * EPSS: https://www.first.org/epss/
 */

export interface RiskScore {
  cvss_v4: number;
  epss: number;
  composite: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  exploitability?: ExploitabilityFactors;
}

export interface ExploitabilityFactors {
  attackVector: "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL";
  attackComplexity: "LOW" | "HIGH";
  privilegesRequired: "NONE" | "LOW" | "HIGH";
  userInteraction: "NONE" | "PASSIVE" | "ACTIVE";
}

/**
 * Calculate composite risk score from CVSS v4 base score and EPSS probability.
 *
 * Formula: composite = cvss_v4 * (0.6 + 0.4 * epss)
 * - EPSS boosts the score when exploitation is likely
 * - Minimum composite is 60% of CVSS (even with 0 EPSS)
 */
export function calculateCompositeRisk(
  cvss_v4: number,
  epss: number = 0
): RiskScore {
  const clampedCVSS = Math.max(0, Math.min(10, cvss_v4));
  const clampedEPSS = Math.max(0, Math.min(1, epss));

  const composite = clampedCVSS * (0.6 + 0.4 * clampedEPSS);

  return {
    cvss_v4: clampedCVSS,
    epss: clampedEPSS,
    composite: Math.round(composite * 100) / 100,
    severity: scoreToSeverity(composite),
    exploitability: undefined, // Not computed from base score alone — requires full CVSS v4 vector
  };
}

function scoreToSeverity(
  score: number
): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score >= 0.1) return "LOW";
  return "INFO";
}

/**
 * Sort findings by composite risk score (highest first).
 */
export function sortByRisk<T extends { cvss_v4?: number; epss?: number }>(
  findings: T[]
): T[] {
  return [...findings].sort((a, b) => {
    const riskA = calculateCompositeRisk(a.cvss_v4 || 0, a.epss || 0);
    const riskB = calculateCompositeRisk(b.cvss_v4 || 0, b.epss || 0);
    return riskB.composite - riskA.composite;
  });
}
