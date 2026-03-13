/**
 * scan-secrets tool — Secret and credential detection
 *
 * Skeleton for Session 5 implementation.
 * Will: scan files for hardcoded secrets using regex patterns and entropy analysis.
 */

export interface SecretScanResult {
  totalFilesScanned: number;
  secretsFound: number;
  secrets: DetectedSecret[];
}

export interface DetectedSecret {
  type: SecretType;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  file: string;
  line: number;
  snippet: string; // Redacted snippet showing context
  description: string;
  remediation: string;
}

export type SecretType =
  | "api_key"
  | "password"
  | "token"
  | "private_key"
  | "connection_string"
  | "oauth_secret"
  | "webhook_url"
  | "encryption_key"
  | "high_entropy_string";

// Common secret patterns (redacted in output)
export const SECRET_PATTERNS: Record<SecretType, RegExp[]> = {
  api_key: [
    /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{16,}['"]/i,
    /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/,
    /sk-[a-zA-Z0-9]{20,}/,
  ],
  password: [
    /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]/i,
  ],
  token: [
    /(?:token|bearer)\s*[:=]\s*['"][^'"]{20,}['"]/i,
    /ghp_[a-zA-Z0-9]{36}/,
    /gho_[a-zA-Z0-9]{36}/,
    /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,
  ],
  private_key: [
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  ],
  connection_string: [
    /(?:mongodb|postgres|mysql|redis):\/\/[^:\s]+:[^@\s]+@/,
  ],
  oauth_secret: [
    /(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['"][^'"]{10,}['"]/i,
  ],
  webhook_url: [
    /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/,
    /https:\/\/discord\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/,
  ],
  encryption_key: [
    /(?:encrypt|cipher|aes)[_-]?key\s*[:=]\s*['"][^'"]{16,}['"]/i,
  ],
  high_entropy_string: [],
};

export async function scanSecrets(
  _projectPath: string,
  _includeGitHistory: boolean
): Promise<SecretScanResult> {
  // Skeleton — implementation in Session 5
  return {
    totalFilesScanned: 0,
    secretsFound: 0,
    secrets: [],
  };
}
