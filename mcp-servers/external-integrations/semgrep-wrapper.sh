#!/usr/bin/env bash
# Semgrep wrapper for Sentinel — SAST with custom rules
set -euo pipefail

PROJECT_PATH="${1:-.}"
RULESET="${2:-auto}" # auto, owasp, security-audit, custom

case "$RULESET" in
  auto)
    semgrep scan --config auto --json "$PROJECT_PATH"
    ;;
  owasp)
    semgrep scan --config "p/owasp-top-ten" --json "$PROJECT_PATH"
    ;;
  security-audit)
    semgrep scan --config "p/security-audit" --json "$PROJECT_PATH"
    ;;
  custom)
    semgrep scan --config "$PROJECT_PATH/.semgrep.yml" --json "$PROJECT_PATH"
    ;;
  *)
    echo "Usage: semgrep-wrapper.sh <path> [auto|owasp|security-audit|custom]"
    exit 1
    ;;
esac
