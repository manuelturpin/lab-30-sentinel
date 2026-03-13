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

# External tools checks
echo ""
echo "--- External Tools (optional) ---"
check_command "trivy installed" "trivy"
check_command "semgrep installed" "semgrep"
check_command "nuclei installed" "nuclei"
check_command "osv-scanner installed" "osv-scanner"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
