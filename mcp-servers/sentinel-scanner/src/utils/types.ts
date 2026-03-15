/**
 * Shared types for Sentinel Scanner
 */

export interface Finding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  location: {
    file: string;
    line?: number;
    column?: number;
  };
  standard?: string;
  owasp?: string;
  cwe?: string;
  remediation: string;
  cvss_v4?: number;
  epss?: number;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  agentsDispatched: string[];
  duration_ms: number;
  error?: string;
}
