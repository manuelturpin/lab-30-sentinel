#!/usr/bin/env bash
# Nuclei wrapper for Sentinel — Vulnerability scanning (6500+ templates)
set -euo pipefail

TARGET="${1:-}"
SEVERITY="${2:-critical,high,medium}"

if [ -z "$TARGET" ]; then
  echo "Usage: nuclei-wrapper.sh <target-url> [severity]"
  exit 1
fi

nuclei -u "$TARGET" -severity "$SEVERITY" -json -silent
