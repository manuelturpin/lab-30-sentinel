---
paths:
  - "skills/**/*.md"
  - "skills/**/agents/*.md"
  - "knowledge-base/**/*"
  - "scripts/*.py"
  - "mcp-servers/**/*"
---

# Deploy Reminder

After modifying skills, agents, KB rules, scripts, or MCP server code:
- **Commit and push first, then deploy** — `CLAUDE.md` fixes this order. Deploying an uncommitted
  state puts the runtime ahead of git and recreates the very drift this rule exists to prevent.
- Run `DRY_RUN=0 bash scripts/deploy.sh` to sync changes to `~/.claude/skills/` and `~/.sentinel/`.
  **`DRY_RUN=0` is mandatory**: the script defaults to `DRY_RUN=1` since 2026-04-17, so the bare
  `bash scripts/deploy.sh` is a silent no-op.
- The deploy copies files and re-indexes all ChromaDB collections
- **Never edit files directly in the deployed skills** — always edit in this repo and deploy. The
  deployed paths are `~/.claude/skills/sentinel-security/`, `~/.claude/skills/sentinel-rag/` and
  `~/.claude/skills/sentinel-evolve/`.

> Corrigé le 2026-07-27 (finding F9 de la revue croisée). Cette règle gardait auparavant
> `~/.claude/skills/security/`, **un chemin qui n'existe pas** : le runtime réel est
> `sentinel-security/`. Le garde-fou pointait dans le vide, ce qui explique en partie que la
> violation du 25/07 — édition directe du runtime déployé — soit passée inaperçue.
