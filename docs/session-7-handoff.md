# Session 7 Handoff — Agent Implementation

**Date**: 2026-03-15
**Status**: Complete
**Commits**: `017fa30` (Tasks 1-4), `ca016c9` (Task 5 E2E)

---

## Ce qui a ete fait

### Task 1: Protocole d'execution commun
- **Fichier cree**: `skills/security/agents/_protocol.md`
- Workflow 4 etapes: MCP Scan → Grep Scan → KB Enrichment → Deduplicate & Return
- Schema Finding[] copie exacte de `types.ts`
- Regles: redaction secrets `[REDACTED]`, severite conservative, pas de faux positifs

### Task 2: 12 agents mis a jour
Chaque agent a recu:
- `## MCP Tools to Use` — table + exemples d'appels avec parametres corrects (`projectPath`, etc.)
- `## Execution Protocol` — instructions specifiques au domaine, reference `_protocol.md`
- `## Output Format` — aligne sur Finding interface, JSON-only output
- Regle de deduplication agent/scan-project

### Task 3: SKILL.md orchestrateur
- Step 2: prompt enrichi (read agent + _protocol, use MCP tools, return JSON only)
- Step 3: parsing JSON avec validation + fallback (warning si agent echoue, continue)
- Step 4: deduplication `file + line + id`, composite risk = `cvss_v4 * (1 + epss)`

### Task 4: KB ssl-tls + cors
- `knowledge-base/domains/ssl-tls/rules.json` — 5 regles (protocol, cipher, HSTS, cert, pinning)
- `knowledge-base/domains/cors/rules.json` — 4 regles (wildcard origin, credentials, null origin, vary)
- RAG re-indexe: **231 documents**, 11 domaines

### Task 5: E2E Tests
- Test app vulnerable creee: `tests/vulnerable-app/` (13 vulns intentionnelles)
- **web-audit**: 13/13 vulns detectees, JSON valide, secrets rediges
- **llm-ai-audit** sur Sentinel: 13 findings (filesystem traversal, SSRF, ReDoS, RAG poisoning)
- Rapports sauves: `reports/archive/vulnerable-app_2026-03-14_web-audit.json`, `sentinel_2026-03-14_llm-ai-audit.json`

---

## Code Reviews effectuees

3 cycles review/fix:
1. **Review 1**: CORS ID format (`CORS-{number}` → `CORS-{category}-{number}`), parametres MCP (`path` → `projectPath`), domaines query-kb invalides → fixes
2. **Review 2**: 6/6 checks PASS — tous les fixes valides
3. **Review 3 (E2E)**: rapports non persistes, .env tracking → fixes, artifacts sauves

---

## Etat actuel du systeme

```
skills/security/
├── SKILL.md                    ← Orchestrateur (dispatch enrichi, JSON parsing, fallback)
└── agents/
    ├── _protocol.md            ← Protocole commun (NEW)
    ├── web-audit.md            ← + Execution Protocol + MCP Tools
    ├── api-audit.md            ← idem
    ├── llm-ai-audit.md         ← idem (depth: deep)
    ├── mobile-audit.md         ← idem
    ├── infrastructure-audit.md ← idem
    ├── supply-chain-audit.md   ← idem (scan-deps + query-cve)
    ├── database-audit.md       ← idem
    ├── data-privacy-audit.md   ← idem (redaction critique)
    ├── websocket-audit.md      ← idem
    ├── cors-audit.md           ← idem
    ├── ssl-tls-audit.md        ← idem (pas de scan-project, scan-headers only)
    └── static-site-audit.md    ← idem

knowledge-base/domains/        ← 11 domaines (ssl-tls + cors = NEW)
mcp-servers/sentinel-scanner/  ← 6 outils operationnels
rag/                           ← 231 docs indexes
reports/archive/               ← 2 rapports E2E sauves
tests/vulnerable-app/          ← App test avec 13 vulns (NEW)
```

---

## Ce qui reste: Session 8

### Objectif: Orchestrator finalization + Reports

Les skeletons existent deja dans le MCP server — il faut les completer:

### 1. SARIF Generator (`sarif-generator.ts`) — QUASI COMPLET
- Le code existe et fonctionne (genere SARIF 2.1.0 valide)
- **A faire**: valider contre le schema SARIF officiel, ajouter `invocations` (timestamp, args), ajouter `artifacts` (liste des fichiers scannes)
- Deja utilise dans `scan-project` (ligne 37: `generateSARIF(result.findings)`)

### 2. SBOM Generator (`sbom-generator.ts`) — SKELETON
- Interfaces CycloneDX definies (CycloneDXBOM, Component, Vulnerability)
- `generateSBOM()` retourne un squelette vide (`components: [], vulnerabilities: []`)
- **A faire**:
  - Parser les manifestes de dependances (package.json, requirements.txt, go.mod, etc.)
  - Generer les Package URLs (purl) pour chaque composant
  - Croiser avec les resultats de `scan-dependencies` pour peupler `vulnerabilities`
  - Exposer comme MCP tool ou integrer dans le flow du SKILL.md

### 3. Risk Scorer (`risk-scorer.ts`) — FONCTIONNEL
- `calculateCompositeRisk()` implemente: `composite = cvss_v4 * (0.6 + 0.4 * epss)`
- `sortByRisk()` implemente
- **A faire**: integrer dans le flow SKILL.md Step 4 (actuellement le SKILL.md utilise une formule differente `cvss_v4 * (1 + epss)` — harmoniser)

### 4. Report Rendering
- Template Markdown existe: `reports/templates/full-report.md` (Handlebars-style)
- **A faire**:
  - Le SKILL.md doit rendre ce template avec les donnees reelles (pas juste le format dans Step 5)
  - Generer le rapport Markdown final
  - Sauvegarder SARIF + SBOM + Markdown dans `reports/archive/`

### 5. Orchestration end-to-end
- **A faire**: tester `/security` sur la vulnerable-app avec le flow complet:
  1. Stack detection → dispatch agents → collect JSON → aggregate → score → report → save
  2. Verifier que SARIF est valide
  3. Verifier que SBOM contient les composants
  4. Verifier que le rapport Markdown est lisible

---

## Points d'attention pour Session 8

1. **Formule composite risk**: harmoniser SKILL.md (`cvss * (1+epss)`) avec risk-scorer.ts (`cvss * (0.6 + 0.4*epss)`) — la version TS est meilleure
2. **scan-project ne retourne qu'un finding par regle par fichier** (break apres premier match) — les agents compensent via Grep mais c'est un gap potentiel
3. **DetectedSecret → Finding conversion**: scan-secrets retourne des `DetectedSecret[]`, pas des `Finding[]` — les agents doivent convertir manuellement
4. **Format de redaction**: scan-secrets utilise `***REDACTED***`, protocole utilise `[REDACTED]` — harmoniser
5. **query-kb domain enum**: ne supporte pas cors, ssl-tls, websocket, static-sites — les agents utilisent `domain: "all"` comme workaround

---

## Fichiers cles a modifier en Session 8

| Fichier | Action |
|---------|--------|
| `mcp-servers/sentinel-scanner/src/utils/sbom-generator.ts` | Implementer (skeleton → complet) |
| `mcp-servers/sentinel-scanner/src/utils/sarif-generator.ts` | Enrichir (invocations, artifacts) |
| `skills/security/SKILL.md` | Harmoniser risk formula, integrer report rendering |
| `mcp-servers/sentinel-scanner/src/index.ts` | Ajouter MCP tool `generate-sbom` si necessaire |
