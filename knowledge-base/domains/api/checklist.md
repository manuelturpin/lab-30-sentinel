# API Security Checklist

Based on OWASP API Security Top 10 2023.

## API1 — Broken Object Level Authorization (BOLA)
- [ ] Every endpoint accessing resources by ID validates ownership
- [ ] List endpoints filter by authenticated user
- [ ] UUIDs preferred over sequential IDs

## API2 — Broken Authentication
- [ ] All sensitive endpoints require authentication
- [ ] JWT signatures properly verified with explicit algorithms
- [ ] Token expiration enforced (short-lived access + refresh rotation)

## API3 — Broken Object Property Level Authorization
- [ ] Request body fields explicitly whitelisted (no mass assignment)
- [ ] Response data filtered (no excessive exposure)
- [ ] Sensitive fields excluded from serialization

## API4 — Unrestricted Resource Consumption
- [ ] Rate limiting on all endpoints (differentiated by type)
- [ ] Pagination with enforced max page size
- [ ] GraphQL depth and complexity limits

## API5 — Broken Function Level Authorization
- [ ] Admin endpoints require role verification
- [ ] RBAC/ABAC consistently enforced

## API6 — Unrestricted Access to Sensitive Business Flows
- [ ] Automation protections on sensitive flows (CAPTCHA, rate limit)

## API7 — Server-Side Request Forgery (SSRF)
- [ ] User-supplied URLs validated against allowlist
- [ ] Internal/private IPs blocked
- [ ] Cloud metadata endpoints blocked

## API8 — Security Misconfiguration
- [ ] No stack traces in error responses
- [ ] Unnecessary HTTP methods disabled
- [ ] CORS properly configured

## API9 — Improper Inventory Management
- [ ] API versions documented and deprecated with sunset headers
- [ ] No shadow/undocumented endpoints

## API10 — Unsafe Consumption of APIs
- [ ] Third-party API responses validated against schemas
- [ ] TLS enforced for outbound API calls
