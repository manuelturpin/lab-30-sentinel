# Vulnerable Test App

**INTENTIONALLY VULNERABLE** — For Sentinel E2E testing only. DO NOT deploy.

This app contains 13 known vulnerability types for testing the web-audit agent:

1. SQL injection (x2) — string concatenation in queries
2. XSS — unsanitized user input in HTML
3. SSRF — user-controlled URL in fetch()
4. Missing authorization — admin endpoint with no auth
5. Hardcoded secrets (x3) — JWT secret, API key, DB credentials
6. .env exposure — dummy secrets in `dummy-env.txt` (fixture; renamed from `.env` per T3 audit-2026-04-21)
7. JWT without expiration
8. Permissive CORS — wildcard origin
9. Password in logs — console.log of sensitive data
10. No rate limiting — login endpoint unprotected

`dummy-env.txt` holds the plaintext-secrets fixture (was `.env`, renamed so credential hooks and real-secret scanners don't false-positive on the corpus). Keep dummy — never replace with production-looking values.
