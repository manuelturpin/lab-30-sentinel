# Vulnerable Test App

**INTENTIONALLY VULNERABLE** — For Sentinel E2E testing only. DO NOT deploy.

This app contains 13 known vulnerability types for testing the web-audit agent:

1. SQL injection (x2) — string concatenation in queries
2. XSS — unsanitized user input in HTML
3. SSRF — user-controlled URL in fetch()
4. Missing authorization — admin endpoint with no auth
5. Hardcoded secrets (x3) — JWT secret, API key, DB credentials
6. .env exposure — secrets in plaintext .env file
7. JWT without expiration
8. Permissive CORS — wildcard origin
9. Password in logs — console.log of sensitive data
10. No rate limiting — login endpoint unprotected

The `.env` file is intentionally tracked for test reproducibility.
