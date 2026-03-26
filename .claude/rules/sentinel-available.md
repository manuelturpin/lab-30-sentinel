---
description: Suggest Sentinel security scanning when security-sensitive code is modified
paths:
  - "**/*.js"
  - "**/*.ts"
  - "**/*.py"
  - "**/*.go"
  - "**/*.rb"
  - "**/*.java"
  - "**/*.swift"
  - "**/*.kt"
  - "Dockerfile"
  - "docker-compose.*"
  - "**/package.json"
  - "**/requirements.txt"
  - "**/go.mod"
  - "**/.env*"
---

Sentinel security scanning is available via `/sentinel-security`. Consider suggesting it when:
- Authentication, authorization, or session management code is modified
- Cryptographic functions or secret handling changes
- API endpoints or input validation logic is added/changed
- Dependencies are added or updated (package.json, requirements.txt, go.mod)
- Docker, infrastructure, or deployment configuration changes
- Environment variables or secrets configuration is modified

Do not suggest it for documentation-only changes, test files, or styling changes.
