#!/usr/bin/env bash
#
# Sentinel Cron Orchestrator
#
# Runs the Sentinel automated pipeline:
#   1. CVE Sync (daily)
#   2. KB Update (Monday only)
#   3. Project Rescan (Monday only, after KB update)
#
# Usage:
#   bash scripts/sentinel-cron.sh           # Normal run
#   bash scripts/sentinel-cron.sh --force   # Force all steps regardless of day
#
# Crontab installation:
#   crontab -e
#   0 6 * * * cd /path/to/lab-30-sentinel && bash scripts/sentinel-cron.sh >> logs/sentinel-cron.log 2>&1

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
PYTHON="${PYTHON:-python3}"
FORCE=false

# Parse args
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
    esac
done

# Ensure log dir exists
mkdir -p "$LOG_DIR"

# Logging helper
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Day of week (1=Monday ... 7=Sunday)
DOW=$(date +%u)
IS_MONDAY=false
if [ "$DOW" = "1" ]; then
    IS_MONDAY=true
fi

log "=========================================="
log "Sentinel Cron Pipeline"
log "=========================================="
log "Date: $(date '+%Y-%m-%d %H:%M:%S')"
log "Day: $(date +%A) (DOW=$DOW)"
log "Force: $FORCE"
log ""

ERRORS=0

# --- Step 1: CVE Sync (daily) ---
log "[1/3] CVE Sync (daily)"
"$PYTHON" "$PROJECT_ROOT/scripts/cve-sync.py" && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
    log "[1/3] CVE Sync: SUCCESS"
else
    log "[1/3] CVE Sync: FAILED (exit $rc)"
    ERRORS=$((ERRORS + 1))
fi
log ""

# --- Step 2: KB Update (Monday only, or --force) ---
if [ "$IS_MONDAY" = true ] || [ "$FORCE" = true ]; then
    log "[2/3] KB Update (weekly)"
    "$PYTHON" "$PROJECT_ROOT/scripts/kb-update.py" && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        log "[2/3] KB Update: SUCCESS"
    else
        log "[2/3] KB Update: FAILED (exit $rc)"
        ERRORS=$((ERRORS + 1))
    fi
else
    log "[2/3] KB Update: SKIPPED (not Monday)"
fi
log ""

# --- Step 3: Project Rescan (Monday only, or --force) ---
if [ "$IS_MONDAY" = true ] || [ "$FORCE" = true ]; then
    log "[3/3] Project Rescan (weekly)"
    "$PYTHON" "$PROJECT_ROOT/scripts/project-rescan.py" && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        log "[3/3] Project Rescan: SUCCESS"
    else
        log "[3/3] Project Rescan: FAILED (exit $rc)"
        ERRORS=$((ERRORS + 1))
    fi
else
    log "[3/3] Project Rescan: SKIPPED (not Monday)"
fi

log ""
log "=========================================="
if [ "$ERRORS" -gt 0 ]; then
    log "Pipeline finished with $ERRORS error(s)"
    exit 1
else
    log "Pipeline finished successfully"
    exit 0
fi
