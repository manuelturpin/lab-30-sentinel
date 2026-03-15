#!/usr/bin/env bash
# Sentinel — System Test Script
# Verifies that all components are properly set up

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Sentinel System Test ==="
echo ""

PASS=0
FAIL=0

check_file() {
  local name="$1"
  local path="$2"
  if [ -f "$path" ]; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

check_dir() {
  local name="$1"
  local path="$2"
  if [ -d "$path" ]; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

check_file_count() {
  local name="$1"
  local pattern="$2"
  local min="$3"
  local count
  count=$(ls $pattern 2>/dev/null | wc -l | tr -d ' ')
  if [ "$count" -ge "$min" ]; then
    echo "  PASS: $name ($count found)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name ($count found, need $min)"
    FAIL=$((FAIL + 1))
  fi
}

check_command() {
  local name="$1"
  local cmd="$2"
  if command -v "$cmd" &>/dev/null; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name (not installed)"
    FAIL=$((FAIL + 1))
  fi
}

# Structure checks
echo "--- Structure ---"
check_file "CLAUDE.md exists" "$PROJECT_DIR/CLAUDE.md"
check_file "SKILL.md exists" "$PROJECT_DIR/skills/security/SKILL.md"
check_file_count "12 agent files exist" "$PROJECT_DIR/skills/security/agents/*.md" 12
check_file "Stack detector exists" "$PROJECT_DIR/mcp-servers/sentinel-scanner/src/utils/stack-detector.ts"
check_file "MCP index exists" "$PROJECT_DIR/mcp-servers/sentinel-scanner/src/index.ts"
check_dir "Knowledge base dirs exist" "$PROJECT_DIR/knowledge-base/domains/web-app"

# MCP Server checks
echo ""
echo "--- MCP Server ---"
check_file "package.json exists" "$PROJECT_DIR/mcp-servers/sentinel-scanner/package.json"
check_file "tsconfig.json exists" "$PROJECT_DIR/mcp-servers/sentinel-scanner/tsconfig.json"
check_file_count "6 tool files exist" "$PROJECT_DIR/mcp-servers/sentinel-scanner/src/tools/*.ts" 6
check_file_count "5 util files exist" "$PROJECT_DIR/mcp-servers/sentinel-scanner/src/utils/*.ts" 5

# RAG checks
echo ""
echo "--- RAG System ---"
check_dir "ChromaDB directory exists" "$PROJECT_DIR/rag/chromadb"
check_file "RAG config.json exists" "$PROJECT_DIR/rag/config.json"
check_file "RAG indexer.py exists" "$PROJECT_DIR/rag/indexer.py"
check_file "RAG query.py exists" "$PROJECT_DIR/rag/query.py"

check_python() {
  local name="$1"
  local code="$2"
  if python3 -c "$code" 2>/dev/null; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

check_python "ChromaDB collection has >=1000 docs" "
import chromadb, json, os
cfg = json.load(open('$PROJECT_DIR/rag/config.json'))
client = chromadb.PersistentClient(path=os.path.join('$PROJECT_DIR/rag', cfg['chromadb_path']))
col = client.get_collection(cfg['collection_name'])
assert col.count() >= 1000, f'Only {col.count()} docs'
"

check_python "RAG query returns results for 'SQL injection'" "
import subprocess, json
r = subprocess.run(['python3', '$PROJECT_DIR/rag/query.py', '--query', 'SQL injection', '--limit', '3'], capture_output=True, text=True)
d = json.loads(r.stdout)
assert d['totalResults'] > 0, 'No results'
"

# KB integrity checks
echo ""
echo "--- KB Integrity ---"
for domain_dir in "$PROJECT_DIR"/knowledge-base/domains/*/; do
  domain=$(basename "$domain_dir")
  check_file "KB rules: $domain/rules.json" "$domain_dir/rules.json"
done

check_python "KB rules have required fields (id, severity, title)" "
import json, os
for domain in os.listdir('$PROJECT_DIR/knowledge-base/domains'):
    rpath = os.path.join('$PROJECT_DIR/knowledge-base/domains', domain, 'rules.json')
    rules = json.load(open(rpath))
    if isinstance(rules, list) and len(rules) > 0:
        r = rules[0]
        assert 'id' in r and 'severity' in r and 'title' in r, f'{domain}: missing fields in first rule'
"

# Report templates
echo ""
echo "--- Report Templates ---"
check_file "Full report template" "$PROJECT_DIR/reports/templates/full-report.md"
check_file "Executive summary template" "$PROJECT_DIR/reports/templates/executive-summary.md"
check_file "SARIF template" "$PROJECT_DIR/reports/templates/sarif-template.json"

# External tools checks (optional — failures here don't affect exit code)
echo ""
echo "--- External Tools (optional) ---"
OPT_PASS=0
OPT_FAIL=0
check_optional_command() {
  local name="$1"
  local cmd="$2"
  if command -v "$cmd" &>/dev/null; then
    echo "  PASS: $name"
    OPT_PASS=$((OPT_PASS + 1))
  else
    echo "  SKIP: $name (not installed)"
    OPT_FAIL=$((OPT_FAIL + 1))
  fi
}
check_optional_command "trivy installed" "trivy"
check_optional_command "semgrep installed" "semgrep"
check_optional_command "nuclei installed" "nuclei"
check_optional_command "osv-scanner installed" "osv-scanner"

echo ""
echo "=== Results: $PASS passed, $FAIL failed (+ $OPT_FAIL optional tools skipped) ==="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
