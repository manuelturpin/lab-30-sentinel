#!/bin/bash
# Test script for session-analyzer.py

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYZER="$SCRIPT_DIR/scripts/session-analyzer.py"
TESTS_PASSED=0
TESTS_FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
test_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
}

info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Test 1: Script exists
if [ -f "$ANALYZER" ]; then
    test_pass "Script exists at $ANALYZER"
else
    test_fail "Script not found at $ANALYZER"
    exit 1
fi

# Test 2: Script is executable
if [ -x "$ANALYZER" ] || python3 "$ANALYZER" --help > /dev/null 2>&1; then
    test_pass "Script is executable"
else
    test_fail "Script is not executable"
fi

# Test 3: Help works
if python3 "$ANALYZER" --help > /dev/null 2>&1; then
    test_pass "Script help works"
else
    test_fail "Script help failed"
fi

# Test 4: Single project analysis (using sentinel)
SENTINEL_HASH="-Users-manuelturpin-Desktop-bonsai974-claude-lab-lab-30-sentinel"
SENTINEL_PROJ="$HOME/.claude/projects/$SENTINEL_HASH"

if [ -d "$SENTINEL_PROJ" ]; then
    info "Testing single project analysis with sentinel project"
    OUTPUT=$(python3 "$ANALYZER" --project "$SENTINEL_PROJ" 2>/dev/null || echo "")

    if [ -n "$OUTPUT" ]; then
        test_pass "Single project analysis returns output"

        # Test 5: Output is valid JSON
        if echo "$OUTPUT" | python3 -m json.tool > /dev/null 2>&1; then
            test_pass "Output is valid JSON"
        else
            test_fail "Output is not valid JSON"
        fi

        # Test 6: Has required top-level keys
        REQUIRED_KEYS=("generated_at" "period" "projects")
        for key in "${REQUIRED_KEYS[@]}"; do
            if echo "$OUTPUT" | grep -q "\"$key\""; then
                test_pass "JSON contains key: $key"
            else
                test_fail "JSON missing key: $key"
            fi
        done

        # Test 7: Contains tool data
        if echo "$OUTPUT" | grep -q "\"tools\""; then
            test_pass "JSON contains tools section"
        else
            test_fail "JSON missing tools section"
        fi

        # Test 8: Contains features_detected
        if echo "$OUTPUT" | grep -q "\"features_detected\""; then
            test_pass "JSON contains features_detected"
        else
            test_fail "JSON missing features_detected"
        fi
    else
        test_fail "Single project analysis returned no output"
    fi
else
    info "Skipping single project test (sentinel project not found at $SENTINEL_PROJ)"
fi

# Test 9: --all mode (finds multiple projects)
info "Testing --all mode"
OUTPUT=$(python3 "$ANALYZER" --all 2>/dev/null || echo "")

if [ -n "$OUTPUT" ]; then
    test_pass "--all mode returns output"

    if echo "$OUTPUT" | python3 -m json.tool > /dev/null 2>&1; then
        test_pass "--all output is valid JSON"
    else
        test_fail "--all output is not valid JSON"
    fi

    # Check projects_analyzed count
    PROJECT_COUNT=$(echo "$OUTPUT" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['period']['projects_analyzed'])" 2>/dev/null || echo "0")
    if [ "$PROJECT_COUNT" -gt 0 ]; then
        test_pass "--all mode found $PROJECT_COUNT projects with sessions"
    else
        info "No projects with sessions found (expected on first run)"
    fi
else
    test_fail "--all mode returned no output"
fi

# Test 10: --global mode
info "Testing --global mode"
OUTPUT=$(python3 "$ANALYZER" --global 2>/dev/null || echo "")

if [ -n "$OUTPUT" ]; then
    test_pass "--global mode returns output"

    if echo "$OUTPUT" | python3 -m json.tool > /dev/null 2>&1; then
        test_pass "--global output is valid JSON"
    else
        test_fail "--global output is not valid JSON"
    fi

    if echo "$OUTPUT" | grep -q "\"global\""; then
        test_pass "--global mode includes global config"
    else
        test_fail "--global mode missing global config"
    fi
else
    test_fail "--global mode returned no output"
fi

# Test 11: No arguments returns error or help
if ! python3 "$ANALYZER" > /dev/null 2>&1; then
    test_pass "Script requires arguments (no silent failure)"
else
    info "Script runs without arguments (may show help)"
fi

# Summary
echo ""
echo "================================================"
echo "Test Summary"
echo "================================================"
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo "================================================"

if [ $TESTS_FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi
