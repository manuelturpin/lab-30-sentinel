# ADR 2026-04-21 — Suppression de 4 MCP tools

## Contexte

La décision Session 12 (2026-03-15) a basculé 4 tools locaux vers des
équivalents natifs Claude Code (`Read`, `Grep`, `Bash`) pour éliminer la
sérialisation MCP sur des opérations purement locales. Le code n'a
jamais été nettoyé — jusqu'à l'audit 2026-04-21 qui a relevé l'écart
entre la documentation (2 tools annoncés dans CLAUDE.md) et la réalité
(7 tools encore exposés).

## Décision

Supprimer les 4 tools du MCP server :

- `scan-project` → remplacé par `Read rules.json + Grep patterns`
- `scan-secrets` → remplacé par `Grep regex secrets`
- `query-kb`     → remplacé par `Bash ~/.sentinel/rag/.venv/bin/python3 rag/query.py`
- `query-cve`    → remplacé par `Read fichiers cache CVE`

Conserver : `scan-dependencies`, `scan-headers`, `generate-sbom`
(appels réseau ou utilitaire de format).

## Conséquences

- **+performance** : pas de sérialisation MCP pour scans locaux
- **-surface MCP** : 7 → 3 tools
- **Breaking** si un consommateur appelait ces tools directement (aucun connu)
- **Doc** : CLAUDE.md §MCP Tools — Natif vs MCP confirme la bascule ;
  à mettre à jour côté chiffres par T4 (2 → 3 tools actifs)

## Statut

Appliqué 2026-04-21 via T2 du plan de remédiation audit.
