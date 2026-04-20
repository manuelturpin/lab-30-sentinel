#!/usr/bin/env bash
# Sentinel — Deployment Script
# Deploys Sentinel globally for all Claude Code instances
#
# Usage:
#   bash scripts/deploy.sh                   # DRY RUN (default): simulate, no changes
#   DRY_RUN=0 bash scripts/deploy.sh         # Apply deployment locally
#   DRY_RUN=0 bash scripts/deploy.sh --remote user@vps:/path  # Apply to VPS
#
# Safety: DRY_RUN=1 by default since 2026-04-17 (H3 audit fix).
# Previous behaviour of rsync -a --delete wiped runtime-generated files
# (EIR reports, SARIF archives) when the source tree did not mirror them.

set -euo pipefail

# ============================================================
# Safety: DRY RUN by default (H3 audit fix)
# ============================================================
DRY_RUN="${DRY_RUN:-1}"
RSYNC_OPTS="-a --delete"
REPORT_EXCLUDES=(
  --exclude='archive/EIR-*.json'
  --exclude='archive/EIR-*.md'
  --exclude='archive/*.sarif.json'
  --exclude='archive/*.sbom.json'
  --exclude='audit-trail.log'
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Target paths
SENTINEL_HOME="$HOME/.sentinel"
SKILL_DIR="$HOME/.claude/skills/sentinel-security"

# Python: use venv with sentence_transformers (required for KB indexing)
VENV_PYTHON="python3"
if [ -f "$SENTINEL_HOME/rag/.venv/bin/python3" ]; then
  VENV_PYTHON="$SENTINEL_HOME/rag/.venv/bin/python3"
elif [ -f "$PROJECT_DIR/.venv/bin/python3" ]; then
  VENV_PYTHON="$PROJECT_DIR/.venv/bin/python3"
fi

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

  if [ "$DRY_RUN" = "1" ]; then
    RSYNC_OPTS="$RSYNC_OPTS --dry-run"
    warn "DRY RUN mode — no files will be modified."
    warn "rsync operations will be simulated; cp / npm / mcp / indexing steps will be skipped."
    warn "Pass DRY_RUN=0 to apply: DRY_RUN=0 bash scripts/deploy.sh"
    echo ""
  else
    warn "APPLY mode (DRY_RUN=0) — will write to $SENTINEL_HOME and $SKILL_DIR"
    echo ""
  fi

  # --- 1. Create directories ---
  info "Creating directories..."
  mkdir -p "$SENTINEL_HOME"
  mkdir -p "$SKILL_DIR/agents"

  # --- 2. Copy runtime to ~/.sentinel/ ---
  info "Copying Sentinel runtime to $SENTINEL_HOME..."

  # KB
  rsync $RSYNC_OPTS "$PROJECT_DIR/knowledge-base/" "$SENTINEL_HOME/knowledge-base/"

  # RAG (indexer + query + config, NOT chromadb data — will re-index)
  mkdir -p "$SENTINEL_HOME/rag"
  cp "$PROJECT_DIR/rag/indexer.py" "$SENTINEL_HOME/rag/"
  cp "$PROJECT_DIR/rag/query.py" "$SENTINEL_HOME/rag/"
  cp "$PROJECT_DIR/rag/config.json" "$SENTINEL_HOME/rag/"

  # MCP Server
  rsync $RSYNC_OPTS \
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

  # Reports: preserve runtime-generated EIR / SARIF / SBOM archives
  rsync $RSYNC_OPTS "${REPORT_EXCLUDES[@]}" "$PROJECT_DIR/reports/" "$SENTINEL_HOME/reports/"
  rsync $RSYNC_OPTS "$PROJECT_DIR/config/" "$SENTINEL_HOME/config/"
  rsync $RSYNC_OPTS "$PROJECT_DIR/scripts/" "$SENTINEL_HOME/scripts/"
  rsync $RSYNC_OPTS "$PROJECT_DIR/tests/" "$SENTINEL_HOME/tests/"
  rsync $RSYNC_OPTS "$PROJECT_DIR/crons/" "$SENTINEL_HOME/crons/"

  # Early exit for DRY RUN — do not run cp / npm / mcp / indexing
  if [ "$DRY_RUN" = "1" ]; then
    echo ""
    warn "DRY RUN complete. No changes were applied."
    warn "Re-run with DRY_RUN=0 to perform the deployment."
    return 0
  fi

  # CLAUDE.md for reference
  cp "$PROJECT_DIR/CLAUDE.md" "$SENTINEL_HOME/CLAUDE.md"

  # --- 3. Deploy skill to ~/.claude/skills/security/ ---
  info "Deploying skill to $SKILL_DIR..."

  # Generate production SKILL.md with absolute paths
  # Copy SKILL.md as-is (paths are already absolute in source)
  cp "$PROJECT_DIR/skills/security/SKILL.md" "$SKILL_DIR/SKILL.md"

  # Copy agents
  cp "$PROJECT_DIR/skills/security/agents/"*.md "$SKILL_DIR/agents/"

  # Copy rules (project conventions shipped with plugin)
  if [ -d "$PROJECT_DIR/skills/security/rules" ]; then
    mkdir -p "$SKILL_DIR/rules"
    cp "$PROJECT_DIR/skills/security/rules/"*.md "$SKILL_DIR/rules/"
    info "Rules: OK ($(ls "$SKILL_DIR/rules/"*.md 2>/dev/null | wc -l | tr -d ' ') files)"
  fi

  # --- 3b. Deploy sentinel-rag skill ---
  SENTINEL_RAG_SKILL_DIR="$HOME/.claude/skills/sentinel-rag"
  SENTINEL_RAG_HOME="$SENTINEL_HOME/skills/sentinel-rag"

  info "Deploying sentinel-rag skill..."
  mkdir -p "$SENTINEL_RAG_SKILL_DIR"
  mkdir -p "$SENTINEL_RAG_HOME/knowledge/sources"

  cp "$PROJECT_DIR/skills/sentinel-rag/SKILL.md" "$SENTINEL_RAG_SKILL_DIR/SKILL.md"

  # Knowledge scripts + sources (NOT chromadb data)
  cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/indexer.py" "$SENTINEL_RAG_HOME/knowledge/"
  cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/query.py" "$SENTINEL_RAG_HOME/knowledge/"
  cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/config.json" "$SENTINEL_RAG_HOME/knowledge/"
  rsync -a "$PROJECT_DIR/skills/sentinel-rag/knowledge/sources/" "$SENTINEL_RAG_HOME/knowledge/sources/"

  # Golden dataset
  [ -f "$PROJECT_DIR/skills/sentinel-rag/knowledge/golden_dataset.json" ] && \
    cp "$PROJECT_DIR/skills/sentinel-rag/knowledge/golden_dataset.json" "$SENTINEL_RAG_HOME/knowledge/"

  # Metadata: only copy if absent (don't overwrite runtime state)
  [ ! -f "$SENTINEL_RAG_HOME/metadata.json" ] && \
    cp "$PROJECT_DIR/skills/sentinel-rag/metadata.json" "$SENTINEL_RAG_HOME/metadata.json"

  # Index sentinel-rag KB
  info "Indexing sentinel-rag expertise KB..."
  (cd "$SENTINEL_RAG_HOME/knowledge" && "$VENV_PYTHON" indexer.py 2>&1) || warn "RAG expertise indexing failed"

  # --- 3c. Deploy sentinel-evolve skill ---
  SENTINEL_EVOLVE_SKILL_DIR="$HOME/.claude/skills/sentinel-evolve"
  SENTINEL_EVOLVE_HOME="$SENTINEL_HOME/skills/sentinel-evolve"

  info "Deploying sentinel-evolve skill..."
  mkdir -p "$SENTINEL_EVOLVE_SKILL_DIR"
  mkdir -p "$SENTINEL_EVOLVE_HOME/knowledge/sources"

  cp "$PROJECT_DIR/skills/sentinel-evolve/SKILL.md" "$SENTINEL_EVOLVE_SKILL_DIR/SKILL.md"

  # Knowledge scripts + sources (NOT chromadb data)
  cp "$PROJECT_DIR/skills/sentinel-evolve/knowledge/indexer.py" "$SENTINEL_EVOLVE_HOME/knowledge/"
  cp "$PROJECT_DIR/skills/sentinel-evolve/knowledge/query.py" "$SENTINEL_EVOLVE_HOME/knowledge/"
  cp "$PROJECT_DIR/skills/sentinel-evolve/knowledge/config.json" "$SENTINEL_EVOLVE_HOME/knowledge/"
  rsync -a "$PROJECT_DIR/skills/sentinel-evolve/knowledge/sources/" "$SENTINEL_EVOLVE_HOME/knowledge/sources/"

  # Metadata: only copy if absent (don't overwrite runtime state)
  [ ! -f "$SENTINEL_EVOLVE_HOME/metadata.json" ] && \
    cp "$PROJECT_DIR/skills/sentinel-evolve/metadata.json" "$SENTINEL_EVOLVE_HOME/metadata.json"

  # Index sentinel-evolve KB
  info "Indexing sentinel-evolve intelligence KB..."
  (cd "$SENTINEL_EVOLVE_HOME/knowledge" && "$VENV_PYTHON" indexer.py 2>&1) || warn "Evolve KB indexing failed"

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
  (cd "$SENTINEL_HOME/rag" && "$VENV_PYTHON" indexer.py 2>&1) || warn "RAG indexing failed — run manually: cd $SENTINEL_HOME/rag && python3 indexer.py"

  # --- 6. Verify ---
  echo ""
  info "Running verification..."
  ERRORS=0

  [ -f "$SKILL_DIR/SKILL.md" ] && info "Skill: OK" || { error "Skill: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -d "$SKILL_DIR/agents" ] && info "Agents: OK ($(ls "$SKILL_DIR/agents/"*.md 2>/dev/null | wc -l | tr -d ' ') files)" || { error "Agents: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -d "$SENTINEL_HOME/knowledge-base" ] && info "KB: OK" || { error "KB: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -f "$SENTINEL_HOME/rag/query.py" ] && info "RAG: OK" || { error "RAG: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -f "$MCP_SERVER" ] && info "MCP: OK" || { error "MCP: NOT BUILT"; ERRORS=$((ERRORS+1)); }
  [ -f "$SENTINEL_RAG_SKILL_DIR/SKILL.md" ] && info "Sentinel-RAG Skill: OK" || { error "Sentinel-RAG Skill: MISSING"; ERRORS=$((ERRORS+1)); }
  [ -f "$SENTINEL_EVOLVE_SKILL_DIR/SKILL.md" ] && info "Sentinel-Evolve Skill: OK" || { error "Sentinel-Evolve Skill: MISSING"; ERRORS=$((ERRORS+1)); }

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
  echo "  /sentinel-rag                              # RAG expert in any project"
  echo "  /sentinel-evolve                           # Evolve intelligence in any project"
  echo "  bash $SENTINEL_HOME/scripts/test-sentinel.sh  # System tests"
  echo "  python3 $SENTINEL_HOME/rag/indexer.py      # Re-index KB"
  echo "  claude mcp list                            # Verify MCP registration"
  echo ""
  echo "Note: Run /reload-plugins in active Claude Code sessions to pick up changes without restart (v2.1.98+)."
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

  if [ "$DRY_RUN" = "1" ]; then
    warn "DRY RUN mode — remote deployment to $userhost:$remote_path skipped."
    warn "Pass DRY_RUN=0 to apply: DRY_RUN=0 bash scripts/deploy.sh --remote $target"
    return 0
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
