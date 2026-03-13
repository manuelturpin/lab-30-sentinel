#!/usr/bin/env bash
# Sentinel — External Security Tools Installation
# Installs Trivy, Semgrep, Nuclei, OSV-Scanner, Bearer, testssl.sh, CORScanner

set -euo pipefail

echo "=== Installing External Security Tools ==="

# Detect OS
OS="$(uname -s)"

install_brew_or_apt() {
  local tool="$1"
  if command -v brew &>/dev/null; then
    brew install "$tool" 2>/dev/null || echo "$tool: already installed or not in brew"
  elif command -v apt-get &>/dev/null; then
    sudo apt-get install -y "$tool" 2>/dev/null || echo "$tool: not available via apt"
  else
    echo "WARNING: Cannot install $tool — no supported package manager found"
  fi
}

# Trivy — Container, IaC, secrets, SBOM scanner
if ! command -v trivy &>/dev/null; then
  echo "Installing Trivy..."
  if [ "$OS" = "Darwin" ]; then
    brew install trivy
  else
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  fi
else
  echo "Trivy: already installed ($(trivy --version 2>/dev/null | head -1))"
fi

# Semgrep — SAST with custom rules
if ! command -v semgrep &>/dev/null; then
  echo "Installing Semgrep..."
  pip3 install semgrep
else
  echo "Semgrep: already installed ($(semgrep --version 2>/dev/null))"
fi

# Nuclei — Vulnerability scanner (6500+ templates)
if ! command -v nuclei &>/dev/null; then
  echo "Installing Nuclei..."
  if [ "$OS" = "Darwin" ]; then
    brew install nuclei
  else
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || echo "Nuclei: requires Go to install"
  fi
else
  echo "Nuclei: already installed ($(nuclei --version 2>/dev/null))"
fi

# OSV-Scanner — Open source vulnerability scanner
if ! command -v osv-scanner &>/dev/null; then
  echo "Installing OSV-Scanner..."
  if [ "$OS" = "Darwin" ]; then
    brew install osv-scanner
  else
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null || echo "OSV-Scanner: requires Go to install"
  fi
else
  echo "OSV-Scanner: already installed"
fi

# Bearer — Data flow analysis, PII detection
if ! command -v bearer &>/dev/null; then
  echo "Installing Bearer..."
  if [ "$OS" = "Darwin" ]; then
    brew install bearer/tap/bearer
  else
    curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh 2>/dev/null || echo "Bearer: manual installation required"
  fi
else
  echo "Bearer: already installed"
fi

# testssl.sh — SSL/TLS audit
if ! command -v testssl &>/dev/null && ! command -v testssl.sh &>/dev/null; then
  echo "Installing testssl.sh..."
  if [ "$OS" = "Darwin" ]; then
    brew install testssl
  else
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh 2>/dev/null || echo "testssl.sh: already cloned or failed"
  fi
else
  echo "testssl.sh: already installed"
fi

# CORScanner — CORS misconfiguration scanner
if ! command -v corscanner &>/dev/null; then
  echo "Installing CORScanner..."
  pip3 install corscanner 2>/dev/null || echo "CORScanner: pip install failed"
else
  echo "CORScanner: already installed"
fi

echo ""
echo "=== External tools installation complete ==="
echo "Note: Some tools may require additional configuration."
