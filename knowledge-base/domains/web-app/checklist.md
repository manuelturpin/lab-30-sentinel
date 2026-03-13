# Web Application Security Checklist

Based on OWASP Top 10 2025. Rules: `rules.json` (22 rules). Patterns: `patterns/` (XSS, SQLi, CSRF, injection).

## A01 — Broken Access Control (3 rules)
- [ ] WEB-AC-001: Authorization middleware on all routes
- [ ] WEB-AC-002: IDOR — ownership check on resource access
- [ ] WEB-AC-003: Path traversal prevention in file operations

## A02 — Cryptographic Failures (3 rules)
- [ ] WEB-CRYPTO-001: No hardcoded secrets/API keys
- [ ] WEB-CRYPTO-002: Secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] WEB-CRYPTO-003: Strong password hashing (bcrypt/argon2)

## A03 — Injection (7 rules, 22 patterns)
- [ ] WEB-INJ-001: No innerHTML with unsanitized input
- [ ] WEB-INJ-002: React dangerous HTML prop sanitized
- [ ] WEB-INJ-003: Vue v-html sanitized
- [ ] WEB-INJ-004: No SQL string concatenation
- [ ] WEB-INJ-005: No OS command injection
- [ ] WEB-INJ-006: No dynamic code execution
- [ ] WEB-INJ-007: CSRF protection on POST/PUT/DELETE

## A04 — Insecure Design (1 rule)
- [ ] WEB-DESIGN-001: Rate limiting on auth endpoints

## A05 — Security Misconfiguration (3 rules)
- [ ] WEB-MISCONF-001: CSP header set
- [ ] WEB-MISCONF-002: Debug mode off in production
- [ ] WEB-MISCONF-003: Restrictive CORS config

## A06 — Vulnerable Components
- [ ] Delegated to supply-chain-audit agent

## A07 — Authentication Failures (2 rules)
- [ ] WEB-AUTH-001: JWT not in localStorage
- [ ] WEB-AUTH-002: JWT with proper expiration

## A08 — Data Integrity (1 rule)
- [ ] WEB-INTEGRITY-001: Safe deserialization

## A09 — Logging (1 rule)
- [ ] WEB-LOG-001: No sensitive data in logs

## A10 — SSRF (1 rule)
- [ ] WEB-SSRF-001: URL validation on server-side requests
