#!/usr/bin/env bash
# Verify that the audit 2026-04-21 findings are closed.
# Exit 0 iff all checks pass.
set -euo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0
VENV_PY="${HOME}/.sentinel/rag/.venv/bin/python3"
PY="${VENV_PY}"
[ -x "${VENV_PY}" ] || PY="python3"

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[0;32m✓\033[0m %s\n' "${name}"
    pass=$((pass+1))
  else
    printf '  \033[0;31m✗\033[0m %s\n' "${name}"
    fail=$((fail+1))
  fi
}

echo "=== Audit closure verification 2026-04-21 ==="
echo ""
echo "--- T1: Runtime operational recovery ---"
check "T1.skill-deployed"         test -f "${HOME}/.claude/skills/sentinel-security/SKILL.md"
check "T1.crons-4-installed"      bash -c '[ "$(crontab -l 2>/dev/null | grep -c sentinel-)" -eq 4 ]'
check "T1.rag-deps"               "${PY}" -c 'import sentence_transformers, chromadb, rank_bm25, certifi'
check "T1.install-crons-script"   test -x scripts/install-crons.sh

echo ""
echo "--- T2: MCP architecture alignment ---"
check "T2.mcp-3-tools"            bash -c '[ "$(grep -c "server.tool(" mcp-servers/sentinel-scanner/src/index.ts)" -eq 3 ]'
check "T2.scan-project-removed"   bash -c '! test -f mcp-servers/sentinel-scanner/src/tools/scan-project.ts'
check "T2.scan-secrets-removed"   bash -c '! test -f mcp-servers/sentinel-scanner/src/tools/scan-secrets.ts'
check "T2.query-cve-removed"      bash -c '! test -f mcp-servers/sentinel-scanner/src/tools/query-cve.ts'
check "T2.query-kb-removed"       bash -c '! test -f mcp-servers/sentinel-scanner/src/tools/query-kb.ts'
check "T2.adr-documented"         test -f docs/adr/2026-04-21-mcp-tools-removal.md

echo ""
echo "--- T3: Security hardening ---"
check "T3.url-validator-ts"       test -f mcp-servers/sentinel-scanner/src/utils/url-validator.ts
check "T3.url-guard-py"           test -f scripts/lib/url_guard.py
check "T3.env-not-tracked"        bash -c '! git ls-files | grep -Eq "tests/.*\.env$"'
check "T3.model-whitelist"        grep -q "_ALLOWED_MODELS" scripts/pattern-gen.py
check "T3.ssrf-scan-headers"      grep -q "isPublicUrl" mcp-servers/sentinel-scanner/src/tools/scan-headers.ts
check "T3.ssrf-webhook"           grep -q "is_public_url" scripts/project-rescan.py

echo ""
echo "--- T4: Documentation ---"
check "T4.last-verified-stamp"    grep -Eq 'Last verified:\*?\*? 2026-(04-21|05-17)' CLAUDE.md
check "T4.mcp-3-tools-doc"        grep -q "3 outils" CLAUDE.md
check "T4.36804-docs"             grep -Eq "(36 804|26 242|105 002) docs" CLAUDE.md

echo ""
echo "--- T5: HTTP client refactor ---"
check "T5.http-client"            test -f scripts/lib/http_client.py
check "T5.no-certifi-duplication" bash -c '! grep -q "^import certifi" scripts/cve-sync.py scripts/anthropic-sync.py scripts/project-rescan.py'
check "T5.future-annotations"     bash -c '[ "$(grep -l "from __future__ import annotations" scripts/*.py | wc -l | tr -d " ")" -ge 7 ]'

echo ""
echo "--- Test suites ---"
check "tests.pytest"              "${PY}" -m pytest tests/ -q
check "tests.node-url-validator"  bash -c 'cd mcp-servers/sentinel-scanner && node --test dist/utils/url-validator.test.js'
check "tests.e2e-session10"       bash tests/e2e-session10.sh

echo ""
echo "=== Result: ${pass} passed, ${fail} failed ==="
[ "${fail}" -eq 0 ]
