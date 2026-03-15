/**
 * scan-headers tool — Security headers verification
 *
 * Fetches a URL and analyzes HTTP security headers
 * (CSP, HSTS, X-Frame-Options, etc.).
 */

import * as http from "http";
import * as https from "https";
import { URL } from "url";

export interface HeaderScanResult {
  url: string;
  score: number; // 0-100
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  headers: HeaderCheck[];
  missingHeaders: string[];
}

export interface HeaderCheck {
  name: string;
  value: string | null;
  status: "present" | "missing" | "misconfigured";
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
  recommendation?: string;
}

export const SECURITY_HEADERS = [
  {
    name: "Content-Security-Policy",
    required: true,
    severity: "HIGH" as const,
  },
  {
    name: "Strict-Transport-Security",
    required: true,
    severity: "HIGH" as const,
  },
  {
    name: "X-Content-Type-Options",
    required: true,
    severity: "MEDIUM" as const,
  },
  {
    name: "X-Frame-Options",
    required: true,
    severity: "MEDIUM" as const,
  },
  {
    name: "Referrer-Policy",
    required: true,
    severity: "MEDIUM" as const,
  },
  {
    name: "Permissions-Policy",
    required: false,
    severity: "LOW" as const,
  },
  {
    name: "Cross-Origin-Opener-Policy",
    required: false,
    severity: "LOW" as const,
  },
  {
    name: "Cross-Origin-Resource-Policy",
    required: false,
    severity: "LOW" as const,
  },
  {
    name: "Cross-Origin-Embedder-Policy",
    required: false,
    severity: "INFO" as const,
  },
];

const SEVERITY_DEDUCTIONS: Record<string, number> = {
  HIGH: 20,
  MEDIUM: 10,
  LOW: 5,
  INFO: 2,
};

function fetchHeaders(
  targetUrl: string,
  maxRedirects: number = 3
): Promise<Record<string, string | string[]>> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === "https:" ? https : http;

    const req = client.get(targetUrl, (res) => {
      // Follow redirects
      if (
        res.statusCode &&
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location &&
        maxRedirects > 0
      ) {
        let redirectUrl = res.headers.location;
        // Handle relative redirects
        if (redirectUrl.startsWith("/")) {
          redirectUrl = `${parsed.protocol}//${parsed.host}${redirectUrl}`;
        }
        res.resume(); // Consume response data
        fetchHeaders(redirectUrl, maxRedirects - 1).then(resolve).catch(reject);
        return;
      }

      // Drain the response body
      res.resume();
      res.on("end", () => {
        resolve(res.headers as Record<string, string | string[]>);
      });
    });

    req.on("error", reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
  });
}

function evaluateCSP(value: string): string[] {
  const issues: string[] = [];

  if (value.includes("'unsafe-inline'")) {
    issues.push("CSP contains 'unsafe-inline' which weakens XSS protection");
  }
  if (value.includes("'unsafe-eval'")) {
    issues.push("CSP contains 'unsafe-eval' which allows code execution from strings");
  }
  if (!value.includes("default-src")) {
    issues.push("CSP is missing 'default-src' directive — no fallback policy");
  }
  if (/(?:default-src|script-src)\s+[^;]*\*/.test(value)) {
    issues.push("CSP uses wildcard '*' which allows loading resources from any origin");
  }

  return issues;
}

function evaluateHSTS(value: string): string[] {
  const issues: string[] = [];

  const maxAgeMatch = value.match(/max-age=(\d+)/);
  if (!maxAgeMatch) {
    issues.push("HSTS missing max-age directive");
  } else {
    const maxAge = parseInt(maxAgeMatch[1], 10);
    if (maxAge < 31536000) {
      issues.push(`HSTS max-age is ${maxAge}s — should be at least 31536000 (1 year)`);
    }
  }

  if (!value.includes("includeSubDomains")) {
    issues.push("HSTS missing includeSubDomains — subdomains are not protected");
  }

  return issues;
}

function scoreToGrade(score: number): "A+" | "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

export async function scanHeaders(url: string): Promise<HeaderScanResult> {
  let responseHeaders: Record<string, string | string[]>;

  try {
    responseHeaders = await fetchHeaders(url);
  } catch (error) {
    return {
      url,
      score: 0,
      grade: "F",
      headers: [],
      missingHeaders: SECURITY_HEADERS.filter(h => h.required).map(h => h.name),
    };
  }

  const headerChecks: HeaderCheck[] = [];
  const missingHeaders: string[] = [];
  let score = 100;

  // Normalize header keys to lowercase for lookup
  const normalizedHeaders: Record<string, string> = {};
  for (const [key, val] of Object.entries(responseHeaders)) {
    normalizedHeaders[key.toLowerCase()] = Array.isArray(val) ? val.join(", ") : val;
  }

  for (const headerDef of SECURITY_HEADERS) {
    const headerKey = headerDef.name.toLowerCase();
    const value = normalizedHeaders[headerKey] || null;

    if (!value) {
      // Header is missing
      headerChecks.push({
        name: headerDef.name,
        value: null,
        status: "missing",
        severity: headerDef.severity,
        recommendation: `Add the ${headerDef.name} header to improve security.`,
      });
      missingHeaders.push(headerDef.name);
      score -= SEVERITY_DEDUCTIONS[headerDef.severity];
      continue;
    }

    // Header is present — check for misconfigurations
    let misconfigured = false;
    let recommendation: string | undefined;

    if (headerDef.name === "Content-Security-Policy") {
      const cspIssues = evaluateCSP(value);
      if (cspIssues.length > 0) {
        misconfigured = true;
        recommendation = cspIssues.join(". ");
        score -= Math.floor(SEVERITY_DEDUCTIONS[headerDef.severity] / 2);
      }
    }

    if (headerDef.name === "Strict-Transport-Security") {
      const hstsIssues = evaluateHSTS(value);
      if (hstsIssues.length > 0) {
        misconfigured = true;
        recommendation = hstsIssues.join(". ");
        score -= Math.floor(SEVERITY_DEDUCTIONS[headerDef.severity] / 2);
      }
    }

    if (headerDef.name === "X-Content-Type-Options" && value !== "nosniff") {
      misconfigured = true;
      recommendation = "X-Content-Type-Options should be set to 'nosniff'.";
      score -= Math.floor(SEVERITY_DEDUCTIONS[headerDef.severity] / 2);
    }

    if (headerDef.name === "X-Frame-Options") {
      const upper = value.toUpperCase();
      if (upper !== "DENY" && upper !== "SAMEORIGIN") {
        misconfigured = true;
        recommendation = "X-Frame-Options should be 'DENY' or 'SAMEORIGIN'.";
        score -= Math.floor(SEVERITY_DEDUCTIONS[headerDef.severity] / 2);
      }
    }

    headerChecks.push({
      name: headerDef.name,
      value,
      status: misconfigured ? "misconfigured" : "present",
      severity: headerDef.severity,
      recommendation,
    });
  }

  // Check for dangerous headers that should NOT be present
  if (normalizedHeaders["server"]) {
    headerChecks.push({
      name: "Server",
      value: normalizedHeaders["server"],
      status: "misconfigured",
      severity: "LOW",
      recommendation: "Remove or obfuscate the Server header to prevent information disclosure.",
    });
    score -= 3;
  }

  if (normalizedHeaders["x-powered-by"]) {
    headerChecks.push({
      name: "X-Powered-By",
      value: normalizedHeaders["x-powered-by"],
      status: "misconfigured",
      severity: "LOW",
      recommendation: "Remove the X-Powered-By header to prevent technology disclosure.",
    });
    score -= 3;
  }

  score = Math.max(0, Math.min(100, score));

  return {
    url,
    score,
    grade: scoreToGrade(score),
    headers: headerChecks,
    missingHeaders,
  };
}
