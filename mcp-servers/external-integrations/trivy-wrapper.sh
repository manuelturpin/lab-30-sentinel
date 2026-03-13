#!/usr/bin/env bash
# Trivy wrapper for Sentinel — Container, IaC, secrets, SBOM scanning
set -euo pipefail

PROJECT_PATH="${1:-.}"
SCAN_TYPE="${2:-fs}" # fs, image, config, sbom

case "$SCAN_TYPE" in
  fs)
    trivy fs --format json --severity CRITICAL,HIGH,MEDIUM "$PROJECT_PATH"
    ;;
  image)
    trivy image --format json --severity CRITICAL,HIGH,MEDIUM "$PROJECT_PATH"
    ;;
  config)
    trivy config --format json "$PROJECT_PATH"
    ;;
  sbom)
    trivy fs --format cyclonedx --output sbom.json "$PROJECT_PATH"
    ;;
  *)
    echo "Usage: trivy-wrapper.sh <path> [fs|image|config|sbom]"
    exit 1
    ;;
esac
