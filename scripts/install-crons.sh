#!/usr/bin/env bash
# Install the 4 Sentinel crons from crons/*.md front-matter.
# Idempotent: strips existing "# sentinel-" lines before re-adding.
# Each cron invokes its target script directly via the RAG venv python so
# sentence_transformers / chromadb / rank_bm25 resolve correctly.
set -euo pipefail

SENTINEL_HOME="${SENTINEL_HOME:-$HOME/.sentinel}"
PY="${SENTINEL_HOME}/rag/.venv/bin/python3"
SCRIPTS="${SENTINEL_HOME}/scripts"
LOG_DIR="${SENTINEL_HOME}/logs"

if [ ! -x "$PY" ]; then
  echo "ERROR: $PY not found or not executable. Run deploy.sh first." >&2
  exit 1
fi

for s in cve-sync.py anthropic-sync.py project-rescan.py kb-update.py; do
  if [ ! -f "${SCRIPTS}/${s}" ]; then
    echo "ERROR: ${SCRIPTS}/${s} missing — run deploy.sh." >&2
    exit 1
  fi
done

mkdir -p "$LOG_DIR"

# Backup existing crontab
crontab -l 2>/dev/null > "/tmp/crontab.backup.$(date +%s)" || true

# Strip any previous sentinel entries
EXISTING="$(crontab -l 2>/dev/null | grep -v '# sentinel-' || true)"

# Schedules mirror crons/*.md front-matter
NEW="${EXISTING}
0 6 * * *   ${PY} ${SCRIPTS}/cve-sync.py        >> ${LOG_DIR}/cve-sync.log 2>&1       # sentinel-cve
0 7 * * 1,4 ${PY} ${SCRIPTS}/anthropic-sync.py  >> ${LOG_DIR}/anthropic-sync.log 2>&1 # sentinel-anthropic
0 8 * * 1   ${PY} ${SCRIPTS}/project-rescan.py  >> ${LOG_DIR}/project-rescan.log 2>&1 # sentinel-rescan
0 9 * * 1   ${PY} ${SCRIPTS}/kb-update.py       >> ${LOG_DIR}/kb-update.log 2>&1      # sentinel-kb
"

echo "${NEW}" | crontab -
installed="$(crontab -l | grep -c '# sentinel-' || true)"
echo "Installed ${installed} sentinel cron entries."
