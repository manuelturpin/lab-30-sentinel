#!/usr/bin/env bash
# Sentinel — Setup Script
# Installs all dependencies and external security tools

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Sentinel Security System — Setup ==="
echo "Project directory: $PROJECT_DIR"
echo ""

# 1. Install MCP Server dependencies
echo "--- Installing MCP Server dependencies ---"
cd "$PROJECT_DIR/mcp-servers/sentinel-scanner"
npm install
npm run build
echo "MCP Server ready."
echo ""

# 2. Install Python dependencies (RAG)
echo "--- Installing Python RAG dependencies ---"
cd "$PROJECT_DIR/rag"
if [ -f "requirements.txt" ]; then
  pip3 install -r requirements.txt
else
  pip3 install chromadb sentence-transformers
fi
echo "RAG dependencies ready."
echo ""

# 3. Install external security tools
echo "--- Installing external security tools ---"
bash "$SCRIPT_DIR/install-tools.sh"
echo ""

echo "=== Setup complete ==="
echo "Run '/security' in Claude Code to start auditing."
