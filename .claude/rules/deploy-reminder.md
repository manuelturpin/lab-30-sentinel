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
- Run `bash scripts/deploy.sh` to sync changes to `~/.claude/skills/` and `~/.sentinel/`
- The deploy copies files and re-indexes all ChromaDB collections
- Never edit files directly in `~/.claude/skills/security/` — always edit in this repo and deploy
