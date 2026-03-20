#!/usr/bin/env bash
# Sentinel — Deployment Script
# Deploys Sentinel globally for all Claude Code instances
#
# Usage:
#   bash scripts/deploy.sh              # Deploy locally
#   bash scripts/deploy.sh --remote user@vps:/path  # Deploy to VPS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Target paths
SENTINEL_HOME="$HOME/.sentinel"
SKILL_DIR="$HOME/.claude/skills/sentinel-security"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; }

# ============================================================
# Parse args
# ============================================================
REMOTE=""
if [[ "${1:-}" == "--remote" ]] && [[ -n "${2:-}" ]]; then
  REMOTE="$2"
  info "Remote deployment target: $REMOTE"
fi

# ============================================================
# Local deployment
# ============================================================
deploy_local() {
  echo ""
  echo "=== Sentinel Deployment ==="
  echo ""

  # --- 1. Create directories ---
  info "Creating directories..."
  mkdir -p "$SENTINEL_HOME"
  mkdir -p "$SKILL_DIR/agents"

  # --- 2. Copy runtime to ~/.sentinel/ ---
  info "Copying Sentinel runtime to $SENTINEL_HOME..."

  # KB
  rsync -a --delete "$PROJECT_DIR/knowledge-base/" "$SENTINEL_HOME/knowledge-base/"

  # RAG (indexer + query + config, NOT chromadb data — will re-index)
  mkdir -p "$SENTINEL_HOME/rag"
  cp "$PROJECT_DIR/rag/indexer.py" "$SENTINEL_HOME/rag/"
  cp "$PROJECT_DIR/rag/query.py" "$SENTINEL_HOME/rag/"
  cp "$PROJECT_DIR/rag/config.json" "$SENTINEL_HOME/rag/"

  # MCP Server
  rsync -a --delete \
    --exclude='node_modules' \
    "$PROJECT_DIR/mcp-servers/" "$SENTINEL_HOME/mcp-servers/"

  # Install MCP deps if needed
  if [ ! -d "$SENTINEL_HOME/mcp-servers/sentinel-scanner/node_modules" ]; then
    info "Installing MCP server dependencies..."
    (cd "$SENTINEL_HOME/mcp-servers/sentinel-scanner" && npm install --production 2>/dev/null) || warn "npm install failed — install manually"
  fi

  # Build MCP if dist/ missing
  if [ ! -d "$SENTINEL_HOME/mcp-servers/sentinel-scanner/dist" ]; then
    info "Building MCP server..."
    (cd "$SENTINEL_HOME/mcp-servers/sentinel-scanner" && npm run build 2>/dev/null) || warn "npm build failed — build manually"
  fi

  # Reports, config, scripts, tests, crons
  rsync -a --delete "$PROJECT_DIR/reports/" "$SENTINEL_HOME/reports/"
  rsync -a --delete "$PROJECT_DIR/config/" "$SENTINEL_HOME/config/"
  rsync -a --delete "$PROJECT_DIR/scripts/" "$SENTINEL_HOME/scripts/"
  rsync -a --delete "$PROJECT_DIR/tests/" "$SENTINEL_HOME/tests/"
  rsync -a --delete "$PROJECT_DIR/crons/" "$SENTINEL_HOME/crons/"

  # CLAUDE.md for reference
  cp "$PROJECT_DIR/CLAUDE.md" "$SENTINEL_HOME/CLAUDE.md"

  # --- 3. Deploy skill to ~/.claude/skills/security/ ---
  info "Deploying skill to $SKILL_DIR..."

  # Generate production SKILL.md with absolute paths
  # Copy SKILL.md as-is (paths are already absolute in source)
  cp "$PROJECT_DIR/skills/security/SKILL.md" "$SKILL_DIR/SKILL.md"

  # Copy agents
  cp "$PROJECT_DIR/skills/security/agents/"*.md "$SKILL_DIR/agents/"

  # --- 4. Register MCP server globally ---
  info "Registering MCP server with Claude Code..."

  MCP_SERVER="$SENTINEL_HOME/mcp-servers/sentinel-scanner/dist/index.js"
  if [ -f "$MCP_SERVER" ]; then
    # Check if already registered
    if claude mcp list 2>/dev/null | grep -q "sentinel-scanner"; then
      warn "MCP server 'sentinel-scanner' already registered — removing old entry"
      claude mcp remove sentinel-scanner --scope user 2>/dev/null || true
    fi
    claude mcp add --scope user --transport stdio sentinel-scanner \
      -- node "$MCP_SERVER" 2>/dev/null \
      && info "MCP server registered globally" \
      || warn "MCP registration failed — register manually: claude mcp add --scope user --transport stdio sentinel-scanner -- node $MCP_SERVER"
  else
    warn "MCP server not built at $MCP_SERVER — build first: cd $SENTINEL_HOME/mcp-servers/sentinel-scanner && npm run build"
  fi

  # --- 5. Index RAG ---
  info "Indexing Knowledge Base into ChromaDB..."
  if command -v python3 &>/dev/null; then
    (cd "$SENTINEL_HOME/rag" && python3 indexer.py 2>&1) || warn "RAG indexing failed — run manually: cd $SENTINEL_HOME/rag && python3 indexer.py"
  else
    warn "python3 not found — install Python 3 and run: cd $SENTINEL_HOME/rag && python3 indexer.py"
  fi

  # --- 6. Verify ---
  echo ""
  info "Running verification..."
  ERRORS=0

  [ -f "$SKILL_DIR/SKILL.md" ] && info "Skill: OK" || { error "Skill: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -d "$SKILL_DIR/agents" ] && info "Agents: OK ($(ls "$SKILL_DIR/agents/"*.md 2>/dev/null | wc -l | tr -d ' ') files)" || { error "Agents: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -d "$SENTINEL_HOME/knowledge-base" ] && info "KB: OK" || { error "KB: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -f "$SENTINEL_HOME/rag/query.py" ] && info "RAG: OK" || { error "RAG: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -f "$MCP_SERVER" ] && info "MCP: OK" || { error "MCP: NOT BUILT"; ERRORS=$((ERRORS+1)); }

  echo ""
  if [ "$ERRORS" -eq 0 ]; then
    info "Deployment complete. /sentinel-security is now available in all Claude Code projects."
  else
    warn "Deployment done with $ERRORS warnings — check above."
  fi

  echo ""
  echo "Paths:"
  echo "  Skill:  $SKILL_DIR/SKILL.md"
  echo "  Home:   $SENTINEL_HOME/"
  echo "  MCP:    $MCP_SERVER"
  echo "  RAG DB: $SENTINEL_HOME/rag/chromadb/"
  echo ""
  echo "Commands:"
  echo "  /sentinel-security                         # Run audit in any project"
  echo "  bash $SENTINEL_HOME/scripts/test-sentinel.sh  # System tests"
  echo "  python3 $SENTINEL_HOME/rag/indexer.py      # Re-index KB"
  echo "  claude mcp list                            # Verify MCP registration"
}

# ============================================================
# Remote deployment (VPS)
# ============================================================
deploy_remote() {
  local target="$1"
  # Extract user@host and path
  local userhost="${target%%:*}"
  local remote_path="${target#*:}"

  if [ -z "$remote_path" ] || [ "$remote_path" = "$target" ]; then
    remote_path="\$HOME/.sentinel"
  fi

  info "Deploying to $userhost:$remote_path ..."

  # Create archive (exclude chromadb data, node_modules, dist, .git)
  info "Creating deployment archive..."
  local archive="/tmp/sentinel-deploy.tar.gz"
  tar -czf "$archive" \
    -C "$PROJECT_DIR" \
    --exclude='.git' \
    --exclude='rag/chromadb' \
    --exclude='mcp-servers/sentinel-scanner/node_modules' \
    --exclude='mcp-servers/sentinel-scanner/dist' \
    .

  # Upload
  info "Uploading to $userhost..."
  scp "$archive" "$userhost:/tmp/sentinel-deploy.tar.gz"

  # Remote setup
  info "Running remote setup..."
  ssh "$userhost" bash -s "$remote_path" << 'REMOTE_SCRIPT'
    set -euo pipefail
    SENTINEL_HOME="$1"
    SKILL_DIR="$HOME/.claude/skills/sentinel-security"

    echo "[+] Creating directories..."
    mkdir -p "$SENTINEL_HOME" "$SKILL_DIR/agents"

    echo "[+] Extracting archive..."
    tar -xzf /tmp/sentinel-deploy.tar.gz -C "$SENTINEL_HOME"
    rm /tmp/sentinel-deploy.tar.gz

    echo "[+] Deploying skill..."
    sed \
      -e "s|lab-30-sentinel/skills/security/agents/|$SKILL_DIR/agents/|g" \
      -e "s|lab-30-sentinel/reports/archive/|$SENTINEL_HOME/reports/archive/|g" \
      -e "s|knowledge-base/|$SENTINEL_HOME/knowledge-base/|g" \
      -e "s|reports/templates/|$SENTINEL_HOME/reports/templates/|g" \
      "$SENTINEL_HOME/skills/security/SKILL.md" > "$SKILL_DIR/SKILL.md"
    cp "$SENTINEL_HOME/skills/security/agents/"*.md "$SKILL_DIR/agents/"

    echo "[+] Installing MCP dependencies..."
    if command -v npm &>/dev/null; then
      cd "$SENTINEL_HOME/mcp-servers/sentinel-scanner"
      npm install --production 2>/dev/null && npm run build 2>/dev/null || echo "[!] MCP build failed"
    else
      echo "[!] npm not found — install Node.js first"
    fi

    echo "[+] Checking Python deps for RAG..."
    if command -v python3 &>/dev/null; then
      python3 -c "import chromadb; import sentence_transformers" 2>/dev/null \
        || echo "[!] Missing Python deps — run: pip install sentence-transformers chromadb"
    else
      echo "[!] python3 not found"
    fi

    echo "[+] Indexing RAG..."
    if command -v python3 &>/dev/null; then
      cd "$SENTINEL_HOME/rag" && python3 indexer.py 2>&1 || echo "[!] RAG indexing failed"
    fi

    echo "[+] Registering MCP server..."
    if command -v claude &>/dev/null; then
      MCP_SERVER="$SENTINEL_HOME/mcp-servers/sentinel-scanner/dist/index.js"
      claude mcp remove sentinel-scanner --scope user 2>/dev/null || true
      claude mcp add --scope user --transport stdio sentinel-scanner \
        -- node "$MCP_SERVER" 2>/dev/null || echo "[!] MCP registration failed"
    else
      echo "[!] claude CLI not found — register MCP manually after installing Claude Code"
    fi

    echo ""
    echo "[+] VPS deployment complete."
    echo "    Skill: $SKILL_DIR/SKILL.md"
    echo "    Home:  $SENTINEL_HOME/"
REMOTE_SCRIPT

  info "Remote deployment done."
  rm -f "$archive"
}

# ============================================================
# Main
# ============================================================
if [ -n "$REMOTE" ]; then
  deploy_remote "$REMOTE"
else
  deploy_local
fi
