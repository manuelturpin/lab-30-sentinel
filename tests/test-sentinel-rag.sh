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

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
