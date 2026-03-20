#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
INDEXER="$PROJECT_DIR/skills/sentinel-rag/knowledge/indexer.py"
CONFIG="$PROJECT_DIR/skills/sentinel-rag/knowledge/config.json"
SOURCES="$PROJECT_DIR/skills/sentinel-rag/knowledge/sources"

PASS=0; FAIL=0; TOTAL=0
check() {
  TOTAL=$((TOTAL+1))
  if eval "$2"; then
    echo "  [PASS] $1"; PASS=$((PASS+1))
  else
    echo "  [FAIL] $1"; FAIL=$((FAIL+1))
  fi
}

echo "=== Sentinel RAG Skill Tests ==="
echo ""

# --- Structure tests ---
echo "--- Structure ---"
check "config.json exists" "[ -f '$CONFIG' ]"
check "config has collection_name" "grep -q 'sentinel_rag_expertise' '$CONFIG'"
check "config has bge-base model" "grep -q 'bge-base-en-v1.5' '$CONFIG'"
check "config has query_prefix" "grep -q 'query_prefix' '$CONFIG'"
check "metadata.json exists" "[ -f '$PROJECT_DIR/skills/sentinel-rag/metadata.json' ]"
check "sources dir has 7 files" "[ \$(find \"$SOURCES\" -maxdepth 1 -name '*.md' | wc -l | tr -d ' ') -ge 7 ]"
check "indexer.py exists" "[ -f '$INDEXER' ]"

# --- Indexer tests ---
echo ""
echo "--- Indexer ---"
check "indexer runs without error" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 indexer.py 2>&1 | tail -1 | grep -q 'Indexing complete'"
check "chromadb created" "[ -d '$PROJECT_DIR/skills/sentinel-rag/knowledge/chromadb' ]"
check "indexed >50 chunks" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 -c \"
import chromadb, json
cfg = json.load(open('config.json'))
c = chromadb.PersistentClient(path='./chromadb')
col = c.get_collection(cfg['collection_name'])
assert col.count() > 50, f'Only {col.count()} docs'
print(f'{col.count()} docs indexed')
\""

# --- Query tests ---
echo ""
echo "--- Query ---"
QUERY="$PROJECT_DIR/skills/sentinel-rag/knowledge/query.py"
check "query.py exists" "[ -f '$QUERY' ]"
check "query returns results for 'embedding model'" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'best embedding model' --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"totalResults\"]>0, f\"got {d}\"'"
check "query returns results for 'hybrid search BM25'" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'hybrid search BM25 RRF' --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"totalResults\"]>0'"
check "query returns results for 'RAG poisoning OWASP'" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'RAG poisoning OWASP security' --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"totalResults\"]>0'"
check "query domain filter works" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 query.py --query 'embedding' --domain embedding --limit 3 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); r=d[\"results\"]; assert all(x[\"domain\"]==\"embedding\" for x in r) if r else True'"

# --- Golden dataset ---
echo ""
echo "--- Golden Dataset ---"
GOLDEN="$PROJECT_DIR/skills/sentinel-rag/knowledge/golden_dataset.json"
check "golden_dataset.json exists" "[ -f '$GOLDEN' ]"
check "golden dataset has 15 entries" "python3 -c 'import json; d=json.load(open(\"'$GOLDEN'\")); assert len(d)==15, f\"got {len(d)}\"'"
check "golden Hit@5 >= 80%" "cd '$PROJECT_DIR/skills/sentinel-rag/knowledge' && python3 -c \"
import json, sys
sys.path.insert(0, '.')
golden = json.load(open('golden_dataset.json'))
from query import query_kb
hits = 0
for entry in golden:
    r = query_kb(entry['query'], limit=5)
    sources_found = {x['source'] for x in r['results']}
    if any(s in sources_found for s in entry['expected_sources']):
        hits += 1
pct = hits / len(golden) * 100
print(f'Hit@5: {hits}/{len(golden)} ({pct:.0f}%)')
assert pct >= 80, f'Hit@5 too low: {pct:.0f}%'
\""

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
