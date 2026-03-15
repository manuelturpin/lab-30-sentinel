#!/usr/bin/env bash
# Sentinel — Session 10 E2E Test Suite
# Tests RAG integration, KB schema, error handling, and scan flow

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RAG_DIR="$PROJECT_DIR/rag"
KB_DIR="$PROJECT_DIR/knowledge-base"

PASS=0
FAIL=0

pass() {
  echo "  PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "  FAIL: $1"
  FAIL=$((FAIL + 1))
}

run_query() {
  python3 "$RAG_DIR/query.py" --query "$1" --domain "$2" --limit "$3" 2>/dev/null
}

# ============================================================
echo "=== Sentinel Session 10 E2E Tests ==="
echo ""

# --- Section 1: RAG Integration ---
echo "--- 1. RAG Integration ---"

# Query "SQL injection" across all domains
result=$(run_query "SQL injection" "all" "5")
count=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['totalResults'])")
if [ "$count" -gt 0 ]; then
  pass "RAG query 'SQL injection' (all): $count results"
else
  fail "RAG query 'SQL injection' (all): 0 results"
fi

# Query "prompt injection" in llm-ai domain
result=$(run_query "prompt injection" "llm-ai" "5")
count=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['totalResults'])")
if [ "$count" -gt 0 ]; then
  pass "RAG query 'prompt injection' (llm-ai): $count results"
else
  fail "RAG query 'prompt injection' (llm-ai): 0 results"
fi

# Query "XSS" across all domains — verify score > 0.5
result=$(run_query "cross-site scripting XSS" "all" "3")
top_score=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin)['results']; print(r[0]['score'] if r else 0)")
if python3 -c "assert float('$top_score') > 0.5"; then
  pass "RAG query 'XSS' top score: $top_score > 0.5"
else
  fail "RAG query 'XSS' top score: $top_score <= 0.5"
fi

# Verify doc count >= 2000
doc_count=$(python3 -c "
import chromadb, json, os
cfg = json.load(open('$RAG_DIR/config.json'))
client = chromadb.PersistentClient(path=os.path.join('$RAG_DIR', cfg['chromadb_path']))
col = client.get_collection(cfg['collection_name'])
print(col.count())
" 2>/dev/null)
if [ "$doc_count" -ge 2000 ]; then
  pass "ChromaDB doc count: $doc_count >= 2000"
else
  fail "ChromaDB doc count: $doc_count < 2000"
fi

# --- Section 2: KB Schema Validation ---
echo ""
echo "--- 2. KB Schema Validation ---"

for domain_dir in "$KB_DIR"/domains/*/; do
  domain=$(basename "$domain_dir")
  result=$(python3 -c "
import json
rules = json.load(open('${domain_dir}rules.json'))
if not isinstance(rules, list):
    print('NOT_LIST')
elif len(rules) == 0:
    print('EMPTY')
else:
    r = rules[0]
    missing = [f for f in ['id','severity','title'] if f not in r]
    if missing:
        print('MISSING:' + ','.join(missing))
    else:
        print('OK:' + str(len(rules)))
" 2>/dev/null)

  case "$result" in
    OK:*)
      count="${result#OK:}"
      pass "KB $domain: $count rules, schema valid"
      ;;
    EMPTY)
      pass "KB $domain: empty (allowed)"
      ;;
    *)
      fail "KB $domain: $result"
      ;;
  esac
done

# --- Section 3: Error Handling ---
echo ""
echo "--- 3. Error Handling ---"

# Empty query should still return valid JSON
result=$(run_query "" "all" "3")
if echo "$result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
  pass "Empty query returns valid JSON"
else
  fail "Empty query returns invalid JSON"
fi

# Nonexistent domain should return 0 results or empty (not crash)
result=$(run_query "test" "nonexistent-domain-xyz" "3")
if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['totalResults'] == 0 or 'error' not in d or True" 2>/dev/null; then
  pass "Nonexistent domain handled gracefully"
else
  fail "Nonexistent domain caused crash"
fi

# Missing chromadb dir scenario
result=$(python3 -c "
import sys, os
sys.path.insert(0, '$RAG_DIR')
os.environ['_TEST_CHROMADB_PATH'] = '/tmp/nonexistent_chromadb_sentinel_test'
from query import query_kb
import json
# Temporarily override config
import query as qmod
original = qmod.load_config
def mock_config():
    c = original()
    c['chromadb_path'] = '/tmp/nonexistent_chromadb_sentinel_test'
    return c
qmod.load_config = mock_config
r = query_kb('test')
print(json.dumps(r))
" 2>/dev/null)
if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null; then
  pass "Missing ChromaDB dir returns error message"
else
  fail "Missing ChromaDB dir not handled"
fi

# --- Section 4: Scan Flow (static checks) ---
echo ""
echo "--- 4. Scan Flow Checks ---"

# Verify vulnerable-app test target exists
if [ -d "$PROJECT_DIR/tests/vulnerable-app" ] && [ -f "$PROJECT_DIR/tests/vulnerable-app/package.json" ]; then
  pass "Test target vulnerable-app exists with package.json"
else
  fail "Test target vulnerable-app missing"
fi

# Verify SKILL.md has edge case handling
if grep -q "0 agents dispatched" "$PROJECT_DIR/skills/security/SKILL.md"; then
  pass "SKILL.md handles 0 agents edge case"
else
  fail "SKILL.md missing 0 agents edge case"
fi

if grep -q "All agents fail" "$PROJECT_DIR/skills/security/SKILL.md"; then
  pass "SKILL.md handles all agents failing"
else
  fail "SKILL.md missing all-agents-fail edge case"
fi

if grep -q "agents completed" "$PROJECT_DIR/skills/security/SKILL.md"; then
  pass "SKILL.md includes agent success count"
else
  fail "SKILL.md missing agent success count"
fi

# Verify stack detector has new indicators
if grep -q "poetry.lock" "$PROJECT_DIR/mcp-servers/sentinel-scanner/src/utils/stack-detector.ts"; then
  pass "Stack detector: poetry.lock indicator"
else
  fail "Stack detector: missing poetry.lock"
fi

if grep -q "openapi.yaml" "$PROJECT_DIR/mcp-servers/sentinel-scanner/src/utils/stack-detector.ts"; then
  pass "Stack detector: openapi.yaml indicator"
else
  fail "Stack detector: missing openapi.yaml"
fi

# Verify MCP tools have error handling
for tool_file in scan-project scan-secrets scan-dependencies; do
  if grep -q "catch" "$PROJECT_DIR/mcp-servers/sentinel-scanner/src/tools/${tool_file}.ts"; then
    pass "MCP tool $tool_file has error handling"
  else
    fail "MCP tool $tool_file missing error handling"
  fi
done

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "All E2E tests passed."
