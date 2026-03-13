/**
 * scan-project tool — Full project security scan
 *
 * Skeleton for Session 5 implementation.
 * Will: detect stack, run agents, aggregate SARIF results.
 */

import { detectStack, type StackDetectionResult } from "../utils/stack-detector.js";
import type { Finding, ScanSummary } from "../utils/types.js";

export type { Finding, ScanSummary };

export interface ScanResult {
  projectPath: string;
  timestamp: string;
  stack: StackDetectionResult;
  findings: Finding[];
  summary: ScanSummary;
}

export async function scanProject(
  projectPath: string,
  depth: "quick" | "standard" | "deep"
): Promise<ScanResult> {
  const startTime = Date.now();

  // Step 1: Detect stack
  const stack = await detectStack(projectPath);

  // Step 2-4: Will be implemented in Session 5
  // - Dispatch agents based on detected stack
  // - Collect and merge findings
  // - Score with CVSS v4 + EPSS

  const findings: Finding[] = [];

  return {
    projectPath,
    timestamp: new Date().toISOString(),
    stack,
    findings,
    summary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      agentsDispatched: stack.agents,
      duration_ms: Date.now() - startTime,
    },
  };
}
