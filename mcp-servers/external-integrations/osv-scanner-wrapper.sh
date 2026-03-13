#!/usr/bin/env bash
# OSV-Scanner wrapper for Sentinel — Open source vulnerability detection
set -euo pipefail

PROJECT_PATH="${1:-.}"

osv-scanner --format json --recursive "$PROJECT_PATH"
