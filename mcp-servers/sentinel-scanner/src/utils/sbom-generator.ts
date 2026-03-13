/**
 * SBOM Generator — Generates CycloneDX Software Bill of Materials
 *
 * Skeleton for Session 8 implementation.
 * CycloneDX spec: https://cyclonedx.org/specification/overview/
 */

import { randomUUID } from "crypto";

function generateUUID(): string {
  return randomUUID();
}

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

/**
 * Generate a CycloneDX SBOM from project dependencies.
 */
export function generateSBOM(
  projectName: string,
  projectVersion: string,
  _dependencies: Array<{ name: string; version: string; ecosystem: string }>
): CycloneDXBOM {
  // Skeleton — implementation in Session 8
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${generateUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        { vendor: "Sentinel", name: "sentinel-scanner", version: "0.1.0" },
      ],
      component: {
        type: "application",
        name: projectName,
        version: projectVersion,
      },
    },
    components: [],
    vulnerabilities: [],
  };
}
