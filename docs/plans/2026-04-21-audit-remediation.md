# Audit Remediation Plan — 2026-04-21

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommandé) ou `superpowers:executing-plans`. Steps use checkbox `- [ ]` syntax for tracking. **Checkpoint humain obligatoire après Task 2** (décision architecture MCP). Toutes les autres tâches = autonomes.

**Goal:** Clore les 10 findings Top du rapport d'audit `reports/audit-2026-04-21.md` pour faire passer Sentinel de 68/100 → ≥ 90/100 (composite A+B+C).

**Architecture:** 6 tâches séquentielles avec dépendances explicites. Chaque tâche = runnable froide par un subagent sans contexte préalable (preconditions vérifiables + commands + acceptance criteria + rollback). TDD partout où des tests fixtures existent déjà (`tests/fixtures/`, `tests/vulnerable-app/`, `tests/e2e-session10.sh`).

**Tech Stack:** Python 3.11+, TypeScript (MCP SDK), Bash, ChromaDB, Zod, pytest, cron.

**Durée cumulée estimée:** ~6h (T1 45min + T2 2h + T3 1h30 + T4 1h + T5 4h diluable + T6 30min).

---

## Context invariants (lus une fois, valables pour toutes les tasks)

**Repo racine :** `/Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel/`
**Runtime :** `~/.sentinel/` + `~/.claude/skills/security/` (cible du `deploy.sh`)
**Branche :** `main` (PR unitaire par task, merge direct si tests verts)
**Convention commit :** `<type>(<scope>): <subject>` — voir `git log --oneline -10`
**Décision projet Session 12 (2026-03-15) :** les 4 tools `scan-project`, `scan-secrets`, `query-kb`, `query-cve` doivent être supprimés du MCP server (décision prise, code non appliqué — cf. Task 2).
**Aujourd'hui :** 2026-04-21.

**Stopping conditions (valables pour chaque task) :**
1. Si une commande de verification retourne un code ≠ 0 et n'est pas listée comme "expected-fail", STOP et surface à l'humain.
2. Si un test dans `tests/e2e-session10.sh` casse alors qu'il passait avant la task, STOP.
3. Si `git status` montre des modifs inattendues hors du scope de la task, STOP.
4. Si plus de 3 iterations sur la même step, STOP.

---

## File Structure (vue globale des fichiers touchés)

| Task | Create | Modify | Delete |
|---|---|---|---|
| T1 | — | — | — (runtime seulement) |
| T2 | `docs/adr/2026-04-21-mcp-tools-removal.md` | `mcp-servers/sentinel-scanner/src/index.ts` | `src/tools/scan-project.ts`, `scan-secrets.ts`, `query-cve.ts`, `query-kb.ts` |
| T3 | `mcp-servers/sentinel-scanner/src/utils/url-validator.ts`, `scripts/lib/url_guard.py`, `tests/fixtures/url-validator/*` | `src/tools/scan-headers.ts:173-180`, `scripts/project-rescan.py:247-274`, `scripts/pattern-gen.py:210-236`, `tests/vulnerable-app/.env` → `.env.fixtures` + `.gitignore` | — |
| T4 | — | `CLAUDE.md` (5 sections chiffrées) | — |
| T5 | `scripts/lib/http_client.py`, `scripts/lib/__init__.py`, `tests/test_http_client.py` | `scripts/cve-sync.py:22-35`, `scripts/anthropic-sync.py:27-38` | — |
| T6 | `scripts/verify-audit-closure.sh` | `reports/audit-2026-04-21.md` (section "closure") | — |

---

## Task 1 — Runtime operational recovery (45 min, autonome)

**Dépend de :** rien. **Bloque :** T2 (les tests e2e ont besoin du runtime déployé).

**Ce que ça ferme :** Findings #2 (skills non déployés), #6 (crons dormants), #9 (RAG deps manquantes).

**Files:**
- Modify: runtime uniquement (`~/.claude/skills/security/`, `~/.sentinel/`, `crontab`)
- Create: `scripts/install-crons.sh` (si inexistant)

- [ ] **Step 1.1: Verify preconditions**

Run:
```bash
cd /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel
[ -f scripts/deploy.sh ] && echo "deploy.sh OK" || exit 1
[ -d crons ] && ls crons/*.md | wc -l
git status --porcelain | grep -v '^?? SESSION.md' | wc -l  # Expected: 0
```
Expected: `deploy.sh OK`, then `4`, then `0`. Si ≠, STOP.

- [ ] **Step 1.2: Run deploy.sh in DRY_RUN mode first (safety)**

Run:
```bash
DRY_RUN=1 bash scripts/deploy.sh 2>&1 | tee /tmp/deploy-dryrun.log
```
Expected: log listing source→dest mappings, aucune écriture. Scan pour la ligne mentionnant `skills/security/SKILL.md → ~/.claude/skills/security/SKILL.md`. Si absente → BUG dans deploy.sh, STOP et reporter.

- [ ] **Step 1.3: Execute real deploy**

Run:
```bash
DRY_RUN=0 bash scripts/deploy.sh 2>&1 | tee /tmp/deploy-real.log
```
Expected: exit 0. Erreurs "permission denied" sur `~/.claude/` = STOP.

- [ ] **Step 1.4: Verify skill deployment**

Run:
```bash
ls ~/.claude/skills/security/SKILL.md && \
ls ~/.claude/skills/security/agents/ | wc -l && \
ls ~/.sentinel/knowledge-base/domains/ | wc -l
```
Expected: le SKILL.md existe, `13` agents (12 + `_protocol.md`), `11` domains (api/cors/data-privacy/database/infrastructure/llm-ai/mobile/ssl-tls/static-sites/supply-chain/web-app).

- [ ] **Step 1.5: Install RAG dependencies**

Run:
```bash
pip install --quiet sentence-transformers chromadb rank_bm25 certifi
python3 -c "import sentence_transformers, chromadb, rank_bm25; print('OK')"
```
Expected: `OK`. Si erreur "externally-managed-environment" → utiliser `pip install --user` ou `python3 -m venv .venv && source .venv/bin/activate && pip install …`.

- [ ] **Step 1.6: Verify RAG query works**

Run:
```bash
python3 rag/query.py --query "ssrf" --domain all --limit 1 2>&1 | head -20
```
Expected: un résultat avec rule_id ou au minimum aucune `ImportError`. Si `No module named`, retour Step 1.5.

- [ ] **Step 1.7: Create `scripts/install-crons.sh`**

Write file `scripts/install-crons.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
# Install the 4 Sentinel crons from crons/*.md front-matter.
# Idempotent: removes existing sentinel lines before re-adding.

SENTINEL_HOME="${SENTINEL_HOME:-$HOME/.sentinel}"
CRON_ORCHESTRATOR="${SENTINEL_HOME}/scripts/sentinel-cron.sh"

if [ ! -x "${CRON_ORCHESTRATOR}" ]; then
  echo "ERROR: ${CRON_ORCHESTRATOR} not found or not executable. Run deploy.sh first." >&2
  exit 1
fi

# Backup existing
crontab -l 2>/dev/null > /tmp/crontab.backup.$(date +%s) || true

# Strip old sentinel lines
EXISTING=$(crontab -l 2>/dev/null | grep -v '# sentinel-' || true)

# Build new entries (schedules from crons/*.md)
NEW="${EXISTING}
0 6 * * * ${CRON_ORCHESTRATOR} cve-sync       # sentinel-cve
0 7 * * 1,4 ${CRON_ORCHESTRATOR} anthropic    # sentinel-anthropic
0 8 * * 1 ${CRON_ORCHESTRATOR} project-rescan # sentinel-rescan
0 9 * * 1 ${CRON_ORCHESTRATOR} kb-update      # sentinel-kb
"

echo "${NEW}" | crontab -
echo "Installed $(crontab -l | grep -c '# sentinel-') sentinel cron entries."
```

Then:
```bash
chmod +x scripts/install-crons.sh
```

- [ ] **Step 1.8: Install crons**

Run:
```bash
bash scripts/install-crons.sh
crontab -l | grep -c '# sentinel-'
```
Expected: `4`. Si `0` → bug dans install-crons.sh, STOP.

- [ ] **Step 1.9: Refresh stale anthropic-intel**

Run:
```bash
python3 scripts/anthropic-sync.py 2>&1 | tail -20
stat -f "%Sm" knowledge-base/anthropic-intel/claude-code-releases.json
```
Expected: exit 0, mtime = today. Si rate-limit GitHub → `GITHUB_TOKEN` absent, STOP pour humain (ou configurer token).

- [ ] **Step 1.10: Commit T1**

```bash
git add scripts/install-crons.sh
git commit -m "chore(ops): add install-crons.sh bootstrap (T1 audit-2026-04-21)"
git push
```

**Acceptance criteria T1:**
- `ls ~/.claude/skills/security/SKILL.md` → existe
- `crontab -l | grep -c '# sentinel-'` → `4`
- `python3 rag/query.py --query "test" --domain all --limit 1` → exit 0
- `stat -f "%Sm%" knowledge-base/anthropic-intel/claude-code-releases.json` → aujourd'hui

**Rollback :** `crontab /tmp/crontab.backup.<timestamp>`

---

## Task 2 — MCP architecture alignment (2h, HUMAN CHECKPOINT)

**Dépend de :** T1 (e2e tests need deployed runtime).
**Bloque :** T3 (url-validator va vivre dans `src/utils/`).
**⚠️ HUMAN CHECKPOINT avant Step 2.1 :** Confirmer Option A (suppression) vs Option B (documentation des 7). L'audit recommande A — la décision Session 12 (2026-03-15) était la suppression.

**Ce que ça ferme :** Finding #1 (MCP expose 7 tools vs 2).

**Files:**
- Create: `docs/adr/2026-04-21-mcp-tools-removal.md`
- Modify: `mcp-servers/sentinel-scanner/src/index.ts`
- Delete: `src/tools/scan-project.ts`, `scan-secrets.ts`, `query-cve.ts`, `query-kb.ts`

- [ ] **Step 2.1: Write ADR**

Create `docs/adr/2026-04-21-mcp-tools-removal.md`:
```markdown
# ADR 2026-04-21 — Suppression de 4 MCP tools

## Contexte
La décision Session 12 (2026-03-15) a basculé 4 tools locaux vers des équivalents natifs Claude Code (`Read`, `Grep`, `Bash`) pour éliminer la sérialisation MCP. Le code n'a jamais été nettoyé.

## Décision
Supprimer les 4 tools du MCP server :
- `scan-project` → remplacé par `Read rules.json + Grep patterns`
- `scan-secrets` → remplacé par `Grep regex secrets`
- `query-kb`     → remplacé par `Bash python3 rag/query.py`
- `query-cve`    → remplacé par `Read fichiers cache CVE`

Conserver : `scan-dependencies`, `scan-headers`, `generate-sbom` (réseau / utilitaire).

## Conséquences
- +performance : pas de sérialisation MCP pour scans locaux
- -surface MCP : 7 → 3 tools
- Breaking si un consommateur appelait ces tools directement (aucun connu).
```

- [ ] **Step 2.2: Capture current tool list (baseline)**

Run:
```bash
cd mcp-servers/sentinel-scanner
grep -n "server.tool(" src/index.ts > /tmp/mcp-tools-before.txt
cat /tmp/mcp-tools-before.txt
```
Expected: 7 lignes.

- [ ] **Step 2.3: Write failing e2e test**

Edit `tests/e2e-session10.sh` to add check :
```bash
# After existing tests, add:
EXPECTED_TOOLS=3
ACTUAL=$(grep -c "server.tool(" "${REPO}/mcp-servers/sentinel-scanner/src/index.ts")
if [ "$ACTUAL" -ne "$EXPECTED_TOOLS" ]; then
  echo "FAIL: expected ${EXPECTED_TOOLS} MCP tools, got ${ACTUAL}"
  exit 1
fi
echo "PASS: MCP exposes ${ACTUAL} tools as expected"
```

Run: `bash tests/e2e-session10.sh 2>&1 | tail -5`
Expected: `FAIL: expected 3 MCP tools, got 7` (rouge = attendu).

- [ ] **Step 2.4: Remove imports from index.ts**

Edit `mcp-servers/sentinel-scanner/src/index.ts` — supprimer les 4 imports :
```typescript
// REMOVE these lines:
import { scanProject } from "./tools/scan-project.js";
import { scanSecrets } from "./tools/scan-secrets.js";
import { queryCVE } from "./tools/query-cve.js";
import { queryKB } from "./tools/query-kb.js";
```

- [ ] **Step 2.5: Remove tool registrations**

Dans `index.ts`, supprimer les 4 blocs `server.tool("scan-project", …)`, `server.tool("scan-secrets", …)`, `server.tool("query-cve", …)`, `server.tool("query-kb", …)`. Garder `scan-dependencies`, `scan-headers`, `generate-sbom`.

- [ ] **Step 2.6: Delete tool files**

Run:
```bash
cd mcp-servers/sentinel-scanner
rm src/tools/scan-project.ts src/tools/scan-secrets.ts src/tools/query-cve.ts src/tools/query-kb.ts
ls src/tools/
```
Expected ls output: `scan-dependencies.ts scan-headers.ts`.

- [ ] **Step 2.7: Rebuild**

Run:
```bash
cd mcp-servers/sentinel-scanner
npm run build 2>&1 | tail -10
```
Expected: exit 0, no TS errors. Si erreur "Cannot find module" → un import oublié, retour Step 2.4.

- [ ] **Step 2.8: Run e2e test — now should pass**

Run:
```bash
cd /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel
bash tests/e2e-session10.sh 2>&1 | tail -10
```
Expected: `PASS: MCP exposes 3 tools as expected` + tous les autres tests passent.

- [ ] **Step 2.9: Redeploy MCP**

Run:
```bash
DRY_RUN=0 bash scripts/deploy.sh 2>&1 | grep -E "(mcp-server|build)"
```

- [ ] **Step 2.10: Commit T2**

```bash
git add docs/adr/2026-04-21-mcp-tools-removal.md \
        mcp-servers/sentinel-scanner/src/index.ts \
        tests/e2e-session10.sh
git rm mcp-servers/sentinel-scanner/src/tools/scan-project.ts \
       mcp-servers/sentinel-scanner/src/tools/scan-secrets.ts \
       mcp-servers/sentinel-scanner/src/tools/query-cve.ts \
       mcp-servers/sentinel-scanner/src/tools/query-kb.ts
git commit -m "refactor(mcp): remove 4 obsolete local tools (T2 audit-2026-04-21)

Session 12 decision finally applied. scan-project/scan-secrets/query-kb/query-cve
are now handled by native Read/Grep/Bash per CLAUDE.md §MCP Tools — Natif vs MCP."
git push
```

**Acceptance criteria T2:**
- `grep -c "server.tool(" mcp-servers/sentinel-scanner/src/index.ts` → `3`
- `ls mcp-servers/sentinel-scanner/src/tools/` → 2 fichiers seulement
- `bash tests/e2e-session10.sh` → exit 0
- MCP rebuild OK

**Rollback :** `git revert HEAD` + `npm run build` + redeploy.

---

## Task 3 — Security hardening (SSRF + model injection + .env fixtures) (1h30, autonome)

**Dépend de :** T2 (on touche aux fichiers MCP).
**Ce que ça ferme :** Findings #3 (SSRF scan-headers), #4 (.env tests trackés), #7 (SSRF webhook), #8 (model injection).

**Files:**
- Create: `mcp-servers/sentinel-scanner/src/utils/url-validator.ts`, `scripts/lib/url_guard.py`, `tests/fixtures/url-validator/{private,public}.txt`
- Modify: `src/tools/scan-headers.ts:173-180`, `scripts/project-rescan.py:247-274`, `scripts/pattern-gen.py:210-236`
- Rename: `tests/vulnerable-app/.env` → `tests/vulnerable-app/.env.fixtures`, add to `.gitignore`

- [ ] **Step 3.1: Create URL validator fixtures**

Create `tests/fixtures/url-validator/private.txt`:
```
http://127.0.0.1:6379
http://localhost:8080
http://10.0.0.1
http://172.16.5.4
http://192.168.1.1
http://169.254.169.254/latest/meta-data/
http://[::1]
http://metadata.google.internal/
```

Create `tests/fixtures/url-validator/public.txt`:
```
https://api.github.com/repos/anthropics/claude-code/releases
https://raw.githubusercontent.com/foo/bar/main/LICENSE
https://services.nvd.nist.gov/rest/json/cves/2.0
```

- [ ] **Step 3.2: Write failing TS test for url-validator**

Create `mcp-servers/sentinel-scanner/src/utils/url-validator.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { isPublicUrl } from "./url-validator.js";
import { readFileSync } from "node:fs";

const private_urls = readFileSync("../../tests/fixtures/url-validator/private.txt", "utf8").trim().split("\n");
const public_urls = readFileSync("../../tests/fixtures/url-validator/public.txt", "utf8").trim().split("\n");

describe("isPublicUrl", () => {
  it.each(private_urls)("rejects private URL: %s", (url) => {
    expect(isPublicUrl(url)).toBe(false);
  });
  it.each(public_urls)("accepts public URL: %s", (url) => {
    expect(isPublicUrl(url)).toBe(true);
  });
});
```

Run: `cd mcp-servers/sentinel-scanner && npx vitest run src/utils/url-validator.test.ts 2>&1 | tail -5`
Expected: FAIL (module does not exist).

- [ ] **Step 3.3: Implement url-validator.ts**

Create `mcp-servers/sentinel-scanner/src/utils/url-validator.ts`:
```typescript
import { URL } from "node:url";

const PRIVATE_V4_RANGES: Array<[number, number, number, number, number]> = [
  [10, 0, 0, 0, 8],     // 10.0.0.0/8
  [172, 16, 0, 0, 12],  // 172.16.0.0/12
  [192, 168, 0, 0, 16], // 192.168.0.0/16
  [127, 0, 0, 0, 8],    // 127.0.0.0/8
  [169, 254, 0, 0, 16], // 169.254.0.0/16 (link-local / AWS metadata)
  [0, 0, 0, 0, 8],      // 0.0.0.0/8
];

const PRIVATE_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
]);

function ipv4ToOctets(host: string): [number, number, number, number] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return octets as [number, number, number, number];
}

function inCidr(octets: [number, number, number, number], range: [number, number, number, number, number]): boolean {
  const [a, b, c, d, prefix] = range;
  const ipInt = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  const rangeInt = (a << 24) | (b << 16) | (c << 8) | d;
  const mask = prefix === 0 ? 0 : ~((1 << (32 - prefix)) - 1);
  return (ipInt & mask) === (rangeInt & mask);
}

export function isPublicUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return false;
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (PRIVATE_HOSTNAMES.has(host)) return false;
  if (host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:")) return false;
  const octets = ipv4ToOctets(host);
  if (octets) {
    return !PRIVATE_V4_RANGES.some((range) => inCidr(octets, range));
  }
  return true;
}
```

Run: `npx vitest run src/utils/url-validator.test.ts 2>&1 | tail -5`
Expected: all tests PASS.

- [ ] **Step 3.4: Apply validator to scan-headers.ts**

Edit `mcp-servers/sentinel-scanner/src/tools/scan-headers.ts` — à l'entrée de la fonction scanHeaders (~line 173) :
```typescript
import { isPublicUrl } from "../utils/url-validator.js";

export async function scanHeaders(url: string): Promise<…> {
  if (!isPublicUrl(url)) {
    throw new Error(`Refusing to scan private/local URL: ${url}`);
  }
  // … existing code
}
```

Run: `npm run build && npx vitest run 2>&1 | tail -10`
Expected: build OK, all tests PASS.

- [ ] **Step 3.5: Write failing Python test for url_guard**

Create `tests/test_url_guard.py`:
```python
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "scripts"))

from lib.url_guard import is_public_url

FIXTURES = pathlib.Path(__file__).parent / "fixtures/url-validator"

def test_private_urls_rejected():
    for url in (FIXTURES / "private.txt").read_text().strip().splitlines():
        assert is_public_url(url) is False, f"should reject: {url}"

def test_public_urls_accepted():
    for url in (FIXTURES / "public.txt").read_text().strip().splitlines():
        assert is_public_url(url) is True, f"should accept: {url}"
```

Run: `python3 -m pytest tests/test_url_guard.py -v 2>&1 | tail -5`
Expected: FAIL (ModuleNotFoundError: scripts.lib.url_guard).

- [ ] **Step 3.6: Implement scripts/lib/url_guard.py**

Create `scripts/lib/__init__.py` (empty).

Create `scripts/lib/url_guard.py`:
```python
"""URL validation to prevent SSRF against private/link-local/metadata endpoints."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_PRIVATE_HOSTNAMES = frozenset({
    "localhost", "metadata.google.internal", "metadata.goog", "instance-data",
})


def is_public_url(url: str) -> bool:
    """Return True iff url is http(s) and resolves to a public, routable address.

    Rejects: RFC 1918, loopback, link-local (incl. 169.254.169.254 AWS metadata),
    unique-local IPv6 (fc00::/7), known metadata hostnames, non-http(s) schemes.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in _PRIVATE_HOSTNAMES:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # public hostname — DNS resolution not attempted here
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )
```

Run: `python3 -m pytest tests/test_url_guard.py -v 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 3.7: Apply url_guard to project-rescan.py webhook**

Edit `scripts/project-rescan.py` autour de la ligne 247-274 (`notify_webhook`) :
```python
from lib.url_guard import is_public_url

def notify_webhook(webhook_url: str, payload: dict) -> None:
    if not is_public_url(webhook_url):
        raise ValueError(f"Refusing to POST to private/local webhook URL: {webhook_url}")
    # … existing code
```

- [ ] **Step 3.8: Fix model injection in pattern-gen.py**

Edit `scripts/pattern-gen.py` autour de la ligne 210 :
```python
_ALLOWED_MODELS = frozenset({"opus", "sonnet", "haiku"})

def call_claude(system: str, user: str, model: str = "opus", …) -> str:
    if model not in _ALLOWED_MODELS:
        raise ValueError(f"Invalid model {model!r}; allowed: {sorted(_ALLOWED_MODELS)}")
    cmd = ["claude", "-p", "--model", model, …]
    # … existing code
```

- [ ] **Step 3.9: Rename .env test fixture + gitignore**

Run:
```bash
git mv tests/vulnerable-app/.env tests/vulnerable-app/.env.fixtures
```

Edit `.gitignore` — ajouter à la section existante :
```gitignore
# Test fixtures with dummy credentials (never commit real-looking .env)
tests/**/.env
!tests/**/.env.fixtures
```

Verify:
```bash
git ls-files | grep -E 'tests/.*\.env$'
```
Expected: vide (aucun .env tracké).

- [ ] **Step 3.10: Run full test suite**

Run:
```bash
python3 -m pytest tests/ -v 2>&1 | tail -20
cd mcp-servers/sentinel-scanner && npm run build && npx vitest run 2>&1 | tail -10
cd - && bash tests/e2e-session10.sh 2>&1 | tail -10
```
Expected: tous PASS.

- [ ] **Step 3.11: Commit T3**

```bash
git add mcp-servers/sentinel-scanner/src/utils/url-validator.ts \
        mcp-servers/sentinel-scanner/src/utils/url-validator.test.ts \
        mcp-servers/sentinel-scanner/src/tools/scan-headers.ts \
        scripts/lib/__init__.py scripts/lib/url_guard.py \
        scripts/project-rescan.py scripts/pattern-gen.py \
        tests/fixtures/url-validator/ tests/test_url_guard.py \
        tests/vulnerable-app/.env.fixtures .gitignore
git commit -m "sec: SSRF guard + model whitelist + fixtures rename (T3 audit-2026-04-21)

- mcp-servers: isPublicUrl() rejects RFC1918 / loopback / link-local / AWS metadata
- scripts/lib/url_guard.py: Python counterpart for webhook hardening
- scan-headers.ts + project-rescan.py:notify_webhook: guard added
- pattern-gen.py: model restricted to {opus,sonnet,haiku}
- tests/vulnerable-app/.env renamed .env.fixtures, gitignored

Closes audit findings #3 #4 #7 #8."
git push
```

**Acceptance criteria T3:**
- `pytest tests/test_url_guard.py` → PASS
- `vitest run src/utils/url-validator.test.ts` → PASS
- `git ls-files | grep -E 'tests/.*\.env$'` → vide
- `grep "_ALLOWED_MODELS" scripts/pattern-gen.py` → présent
- `bash tests/e2e-session10.sh` → PASS

**Rollback :** `git revert HEAD` + `npm run build`.

---

## Task 4 — CLAUDE.md refresh (1h, autonome)

**Dépend de :** T1–T3 (certaines valeurs changent).
**Ce que ça ferme :** Finding #5 (docs stale).

**Files:** Modify `CLAUDE.md`.

- [ ] **Step 4.1: Recompute live metrics**

Run:
```bash
cd /Users/manuelturpin/Desktop/bonsai974/claude/lab/lab-30-sentinel
python3 - <<'EOF'
import json, pathlib, sys
kb = pathlib.Path("knowledge-base")

curated = sum(len(json.loads((d/"rules.json").read_text())) for d in (kb/"domains").iterdir() if (d/"rules.json").exists())
nvd = len(json.loads((kb/"cve-feed/nvd-cache.json").read_text())["vulnerabilities"])
osv = len(json.loads((kb/"cve-feed/osv-cache.json").read_text())["vulnerabilities"])
gh = len(json.loads((kb/"cve-feed/github-advisories.json").read_text())["advisories"])
standards = sum(1 for p in (kb/"standards").glob("*.json"))
fb = json.loads((kb/"feedback/feedback.json").read_text())
fb_total = len(fb.get("entries", []))

print(f"curated:{curated} nvd:{nvd} osv:{osv} gh:{gh} cve_total:{nvd+osv+gh} standards:{standards} feedback:{fb_total}")
EOF
```
Expected: line with current counts. Save these numbers for Step 4.2.

- [ ] **Step 4.2: Update CLAUDE.md numbers**

Edit `CLAUDE.md` — rechercher et remplacer :
- `115 regles domaine + 2273 NVD CVE + 1484 OSV + 100 GitHub + 94 standards` → valeurs Step 4.1
- `4088 documents (115 curated + 2273 NVD + 1484 OSV + 100 GitHub + 94 standards)` → idem
- `2 outils` (MCP) → `3 outils` (scan-dependencies + scan-headers + generate-sbom)
- `Les 4 outils locaux ont ete remplaces` → ajouter date : `remplacés Session 12 (2026-03-15), code nettoyé Session 15 (2026-04-21)`

- [ ] **Step 4.3: Add "Last verified" header**

À la fin de la section `## Statut`, ajouter :
```markdown
---

**Last verified:** 2026-04-21 (audit complet — cf. `reports/audit-2026-04-21.md`)
**Verification cmd:** `bash scripts/verify-audit-closure.sh`
```

- [ ] **Step 4.4: Update MCP Tools Natif vs MCP table**

Dans la section `## MCP Tools — Natif vs MCP` :
- Confirmer que `scan-project`, `scan-secrets`, `query-kb`, `query-cve` apparaissent bien comme "Remplacé par" (déjà le cas)
- Ajouter une ligne : `generate-sbom | **CONSERVÉ** (MCP) | Utilitaire format SBOM CycloneDX`

- [ ] **Step 4.5: Commit T4**

```bash
git add CLAUDE.md
git commit -m "docs(claude.md): refresh numbers post-audit + last-verified header (T4)

- Updated CVE/curated/standards/feedback counts to live values
- Aligned MCP section with T2 (3 tools actifs)
- Added 'Last verified' metadata + verification command reference"
git push
```

**Acceptance criteria T4:**
- `grep "Last verified: 2026-04-21" CLAUDE.md` → match
- Les chiffres dans `CLAUDE.md` matchent Step 4.1 output ±0
- `grep -c "2 outils" CLAUDE.md` → `0`

---

## Task 5 — HTTP client refactor + type hints (4h, autonome, diluable)

**Dépend de :** T3 (url_guard peut être réutilisé dans http_client).
**Ce que ça ferme :** Findings transverses Axis C (duplication SSL, type hints, silent failures).

**Files:**
- Create: `scripts/lib/http_client.py`, `tests/test_http_client.py`
- Modify: `scripts/cve-sync.py:22-35`, `scripts/anthropic-sync.py:27-38`, `scripts/pattern-gen.py` (type hints), `scripts/rule-tester.py` (type hints), `scripts/feedback-loop.py` (type hints)

- [ ] **Step 5.1: Write failing test for http_client**

Create `tests/test_http_client.py`:
```python
from __future__ import annotations
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "scripts"))

from lib.http_client import get_session, SSLConfigError

def test_session_has_certifi_ca_bundle():
    s = get_session()
    assert s.verify not in (None, False), "SSL verification must be enabled"

def test_session_rejects_private_urls(requests_mock):
    s = get_session()
    # Guard must raise before even attempting the request
    import pytest
    with pytest.raises(ValueError, match="private"):
        s.get("http://127.0.0.1:6379")
```

Run: `python3 -m pytest tests/test_http_client.py -v 2>&1 | tail -5`
Expected: FAIL (module missing).

- [ ] **Step 5.2: Implement scripts/lib/http_client.py**

```python
"""Centralized HTTP client with SSL context + SSRF guard.

Consolidates SSL/certifi boilerplate previously duplicated across
cve-sync.py and anthropic-sync.py. Every outbound request is routed
through url_guard.is_public_url() before being sent.
"""
from __future__ import annotations

import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .url_guard import is_public_url


class SSLConfigError(RuntimeError):
    """Raised when SSL cannot be configured safely."""


def _resolve_ca_bundle() -> str:
    try:
        import certifi
    except ImportError as exc:
        raise SSLConfigError(
            "certifi is required for SSL verification. Install: pip install certifi"
        ) from exc
    return certifi.where()


class _GuardedSession(requests.Session):
    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        if not is_public_url(url):
            raise ValueError(f"Refusing to send {method} to private/local URL: {url}")
        return super().request(method, url, **kwargs)


def get_session(
    *, retries: int = 3, backoff_factor: float = 0.5, user_agent: str = "sentinel/1.0"
) -> requests.Session:
    """Return a configured requests.Session with SSL + SSRF guard + retries."""
    session = _GuardedSession()
    session.verify = _resolve_ca_bundle()
    session.headers.update({"User-Agent": user_agent})
    retry = Retry(
        total=retries, backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD"}),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


logger = logging.getLogger(__name__)
```

Run: `python3 -m pytest tests/test_http_client.py -v 2>&1 | tail -5`
Expected: PASS (may need `pip install requests-mock` if not present).

- [ ] **Step 5.3: Migrate cve-sync.py**

Edit `scripts/cve-sync.py` — remplacer les lignes 22-35 (SSL boilerplate + session creation) par :
```python
from lib.http_client import get_session
session = get_session(user_agent="sentinel-cve-sync/1.0")
```
Remplacer tous les `requests.get(...)` par `session.get(...)`.

Run: `python3 scripts/cve-sync.py --days 1 --dry-run 2>&1 | tail -10`
Expected: exit 0 or explicit known error (rate-limit si pas de token), pas de `ImportError` ni `SSLError`.

- [ ] **Step 5.4: Migrate anthropic-sync.py**

Même traitement sur `scripts/anthropic-sync.py` lignes 27-38. Tester :
```bash
python3 scripts/anthropic-sync.py --dry-run 2>&1 | tail -10
```

- [ ] **Step 5.5: Add type hints on public functions (5 scripts)**

Pour chacun de `cve-sync.py`, `pattern-gen.py`, `rule-tester.py`, `feedback-loop.py`, `anthropic-sync.py` :
1. Ajouter en tête : `from __future__ import annotations`
2. Annoter les signatures des fonctions appelées par le CLI (`def main(...)`, `def cmd_xxx(...)`) avec types PEP 484
3. Exécuter : `python3 -m mypy --ignore-missing-imports scripts/<name>.py 2>&1 | tail -10`

Accept : 0 erreurs mypy bloquantes sur les signatures publiques (warnings internes OK à ce stade).

- [ ] **Step 5.6: Commit T5 (incrémental)**

Faire 3 commits séparés pour granularité :
```bash
# Commit 1 : http_client
git add scripts/lib/http_client.py tests/test_http_client.py
git commit -m "feat(scripts): add shared http_client with SSL + SSRF guard (T5.1)"

# Commit 2 : migration cve-sync + anthropic-sync
git add scripts/cve-sync.py scripts/anthropic-sync.py
git commit -m "refactor(scripts): migrate cve-sync + anthropic-sync to http_client (T5.2)"

# Commit 3 : type hints
git add scripts/*.py
git commit -m "chore(scripts): add type hints on public APIs (T5.3)"
git push
```

**Acceptance criteria T5:**
- `pytest tests/test_http_client.py` → PASS
- `python3 -m mypy --ignore-missing-imports scripts/cve-sync.py` → 0 erreurs
- `grep -c "import certifi" scripts/cve-sync.py scripts/anthropic-sync.py` → `0` (plus de duplication)
- `bash tests/e2e-session10.sh` → PASS

**Rollback :** 3 reverts incrémentaux possibles (commit atomiques).

---

## Task 6 — Verification script + closure (30 min, autonome)

**Dépend de :** T1–T5.

**Files:**
- Create: `scripts/verify-audit-closure.sh`
- Modify: `reports/audit-2026-04-21.md` (section closure)

- [ ] **Step 6.1: Create verify-audit-closure.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

pass=0; fail=0
check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "✅ ${name}"
    pass=$((pass+1))
  else
    echo "❌ ${name}"
    fail=$((fail+1))
  fi
}

echo "=== Audit closure verification 2026-04-21 ==="
check "T1.runtime-deployed" test -f "$HOME/.claude/skills/security/SKILL.md"
check "T1.crons-installed" bash -c '[ "$(crontab -l 2>/dev/null | grep -c sentinel-)" -eq 4 ]'
check "T1.rag-deps" python3 -c "import sentence_transformers, chromadb, rank_bm25"
check "T2.mcp-tools-count" bash -c '[ "$(grep -c "server.tool(" mcp-servers/sentinel-scanner/src/index.ts)" -eq 3 ]'
check "T2.obsolete-tools-removed" bash -c '! ls mcp-servers/sentinel-scanner/src/tools/scan-project.ts 2>/dev/null'
check "T3.url-validator-ts" test -f mcp-servers/sentinel-scanner/src/utils/url-validator.ts
check "T3.url-guard-py" test -f scripts/lib/url_guard.py
check "T3.env-renamed" bash -c '! git ls-files | grep -Eq "tests/.*\.env$"'
check "T3.model-whitelist" grep -q "_ALLOWED_MODELS" scripts/pattern-gen.py
check "T4.claude-md-verified" grep -q "Last verified: 2026-04-21" CLAUDE.md
check "T5.http-client" test -f scripts/lib/http_client.py
check "T5.no-certifi-duplication" bash -c '[ "$(grep -c "import certifi" scripts/cve-sync.py scripts/anthropic-sync.py 2>/dev/null)" -eq 0 ]'
check "e2e.session10" bash tests/e2e-session10.sh
check "pytest.all" python3 -m pytest tests/ -q

echo ""
echo "=== Result: ${pass} passed, ${fail} failed ==="
[ "${fail}" -eq 0 ]
```

Then: `chmod +x scripts/verify-audit-closure.sh`.

- [ ] **Step 6.2: Run verification**

Run: `bash scripts/verify-audit-closure.sh`
Expected: `14 passed, 0 failed`.

- [ ] **Step 6.3: Append closure section to audit report**

Edit `reports/audit-2026-04-21.md` — ajouter à la fin :
```markdown
---

## 7. Closure

**Date closure :** 2026-04-21
**Plan exécuté :** `docs/plans/2026-04-21-audit-remediation.md`
**Verification :** `bash scripts/verify-audit-closure.sh` → `14/14 passed`

**Findings fermés :** #1, #2, #3, #4, #5, #6, #7, #8, #9 (9/10)
**Finding restant :** #10 (duplication agents/`_protocol.md`) — traité hors-scope, ticket `T7-agent-dry` créé.

**Score post-remediation attendu :** ≥ 90/100 (à re-mesurer via /sentinel-evolve audit).
```

- [ ] **Step 6.4: Commit T6**

```bash
git add scripts/verify-audit-closure.sh reports/audit-2026-04-21.md
git commit -m "chore(audit): add closure verification script + report update (T6)"
git push
```

**Acceptance criteria T6:**
- `bash scripts/verify-audit-closure.sh` → exit 0, `14 passed, 0 failed`
- Report section `## 7. Closure` présente

---

## Agent-autonome execution instructions

**Dispatching pattern :** un subagent par task. Entre chaque :
1. Controller lit le commit du subagent.
2. Controller exécute les `acceptance criteria` listées.
3. Si tous passent → dispatcher la task suivante.
4. Sinon → re-dispatcher le même subagent avec le diff des acceptance failures comme contexte.

**Checkpoint humain :** avant T2.1 seulement (décision Option A vs B confirmée).

**Dépendances :**
```
T1 ─┬─> T2 ──> T3 ─┬─> T4 ─┐
    │               │      ├─> T6
    │               │      │
    └───────> T5 ───┴──────┘
```
T1 peut lancer T5 en parallèle si bandwidth. T4 après T1–T3. T6 en dernier.

**Budget global :** 6h. Si > 8h cumulées → STOP + surface à humain.

**Reprise :** si interruption mid-task, rerun depuis la première step non-cochée. Les commits atomiques permettent `git reset --hard HEAD~N` pour revenir à un état propre.

---

## DRY / YAGNI / TDD checklist

- ✅ DRY : `url-validator.ts` + `url_guard.py` sont des modules partagés, pas dupliqués inline.
- ✅ DRY : `http_client.py` élimine la duplication SSL entre `cve-sync.py` et `anthropic-sync.py`.
- ✅ YAGNI : pas d'ajout de tools MCP, pas de nouvelle dépendance non-requise.
- ✅ TDD : T3 et T5 suivent Red-Green-Refactor (test first, pattern écrit dans la plan).
- ✅ Frequent commits : 6 tasks × 1-3 commits chacune = granularité atomique.
