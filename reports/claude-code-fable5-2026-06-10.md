# Claude Code (v2.1.163→v2.1.170) + Claude Fable 5 — Recherche pour évolution Sentinel

> **Deep Research v4** · niveau L4 · 2026-06-10 · sortie sur Opus 4.8 (fan-out Sonnet)
> Sujet : intégrer dans l'outillage de cybersécurité Sentinel les capacités du dernier
> update Claude Code et du nouveau modèle Fable 5. Sources priorisées : officielles Anthropic.

---

## Résumé exécutif

Entre le **2026-06-04 (v2.1.162)** et le **2026-06-09 (v2.1.170)**, Anthropic a publié
**7 versions de Claude Code** (v2.1.164 sautée) et lancé **Claude Fable 5**, un modèle de
**classe « Mythos » positionné au-dessus d'Opus 4.8** [1][4][5]. Fable 5 (`claude-fable-5`,
1M ctx / 128K out, **$10/$50 per MTok**) est exposé dans Claude Code à partir de **v2.1.170**,
accessible via `--model fable` ou `--model claude-fable-5` [3]. Sa surface API est celle
d'Opus 4.8 avec **une nouvelle breaking change** : thinking adaptatif **toujours actif**, donc
`thinking:{type:"disabled"}` renvoie **HTTP 400** (omettre le paramètre) [5].

Pour Sentinel, les éléments à fort impact sont : (1) **intégrer Fable 5** dans
`feature-inventory.json`, la whitelist `pattern-gen.py` et les tiers de modèles ; (2) **4 nouveaux
env vars sécurité-pertinents** (dont `CLAUDE_CODE_SAFE_MODE` qui désactive hooks/MCP/skills, et
`OTEL_LOG_USER_PROMPTS` qui fait fuiter les prompts en télémétrie) [CONFIDENCE: HIGH] ; (3) la
**CVE-2026-0621** (ReDoS dans le MCP TypeScript SDK, fix v1.25.2) [9][10] ; (4) des durcissements
plateforme (Confused-Deputy, glob deny rules, version pinning) à refléter côté KB.

---

## 1. Releases Claude Code v2.1.163 → v2.1.170

Source de vérité : changelog officiel (cache local `~/.claude/cache/changelog.md`, 367 KB,
horodaté 2026-06-10) + GitHub releases [1][2].

| Version | Date | Points saillants |
|---|---|---|
| **2.1.170** | 2026-06-09 | **Claude Fable 5** (classe Mythos) disponible — modèle le plus capable jamais rendu GA ; fix transcripts VS Code [1] |
| **2.1.169** | 2026-06-08 | `--safe-mode` + `CLAUDE_CODE_SAFE_MODE` ; `/cd` (change cwd sans casser le cache) ; `disableBundledSkills` + `CLAUDE_CODE_DISABLE_BUNDLED_SKILLS` ; hook post-session ; durcissement MCP policy enterprise (reconnect + IDE) [1] |
| 2.1.168 | 2026-06-06 | Bug fixes / fiabilité (pas de détail public) |
| 2.1.167 | 2026-06-06 | Bug fixes / fiabilité |
| **2.1.166** | 2026-06-06 | `fallbackModel` (chaîne jusqu'à 3 modèles) ; **glob dans les deny rules** (`*` deny all) ; `MAX_THINKING_TOKENS=0` / `--thinking disabled` par modèle ; **durcissement cross-session messaging — SendMessage ne porte plus l'autorité utilisateur (mitigation Confused Deputy)** [1] |
| 2.1.165 | 2026-06-05 | Bug fixes / fiabilité |
| ~~2.1.164~~ | — | **non publiée** (sautée) |
| **2.1.163** | 2026-06-04 | `requiredMinimumVersion` / `requiredMaximumVersion` (refus de démarrer hors plage — anti-downgrade) ; `/plugin list` ; Stop/SubagentStop hooks → `additionalContext` ; `API_FORCE_IDLE_TIMEOUT` (timeout idle 5 min Vertex/Foundry) ; **trust gate sur les chemins de certificat OTEL des settings projet non fiables** [1] |

**Dernière version confirmée : v2.1.170 (2026-06-09)** [1][2].

---

## 2. Modèle Claude Fable 5 — fiche technique

Sources : models overview, launch guide Fable 5/Mythos 5, pricing, effort, prompt-caching [4][5][7][8].
Recoupé avec la référence Anthropic embarquée (claude-api, cachée 2026-05-26).

| Attribut | Valeur | Source |
|---|---|---|
| Model ID | `claude-fable-5` | [4] |
| Positionnement | Classe **Mythos**, **au-dessus d'Opus 4.8** — modèle le plus capable en GA (⚠️ vendor) | [4][5][6] |
| Fenêtre de contexte | **1 000 000 tokens** | [4] |
| Max output | **128K (131 072)** tokens | [4] |
| Pricing | **$10 / MTok input · $50 / MTok output** (Batch : $5/$25) | [4] |
| Cache | min prefix **512 tokens** (API) ; write $12.50 (5 min)/$20 (1 h) ; read $1 | [8] |
| Effort | `low · medium · high (défaut) · xhigh · max` | [7] |
| Thinking | **adaptatif toujours actif** ; raw CoT jamais renvoyé ; `display` `omitted` (défaut) / `summarized` | [5] |
| **Breaking change** | `thinking:{type:"disabled"}` → **HTTP 400** (omettre le param) | [5] |
| Sampling | `temperature` / `top_p` **non supportés** (comme Opus 4.7/4.8) | [5][6] |
| Refus | `stop_reason:"refusal"` renvoyé en **HTTP 200** (pas une erreur) | [5] |
| Tokenizer | famille 4.7+ (~30 % tokens en plus vs pré-4.7) | [4] |
| Knowledge cutoff | janvier 2026 | [4] |
| Disponibilité | GA 2026-06-09 : Claude API, AWS, Bedrock, Vertex, Foundry | [4][5] |
| Variant | **Mythos 5** (safeguards levés) — accès restreint (partenaires) [SINGLE SOURCE] | [5][6] |

**Garde-fous (sécurité)** : classifieurs temps-réel (cyber, bio/chem) ; requêtes flaggées →
fallback Opus 4.8 (mitigation partielle, pas un blocage dur) ; déclenchement <5 % des sessions
(⚠️ vendor) ; rétention données 30 j (classification « Covered Model ») [5][6].

---

## 3. Fable 5 dans Claude Code (CLI)

| Question | Réponse | Confiance |
|---|---|---|
| **Token `--model` / `/model`** | **`fable`** (alias) **et** `claude-fable-5` (nom complet) — les deux valides | [CONFIDENCE: HIGH] — vérifié sur `claude --help` v2.1.170 local [3] |
| Version d'ajout | **v2.1.170** | HIGH [1] |
| Fast mode | **Non** (Fast mode reste limité à Opus 4.6/4.7/4.8 ; absent du changelog Fable 5) | MED (inférence par absence) [1] |
| `--fallback-model` | Supporté (ajouté v2.1.166, s'applique à tous les modèles) | HIGH [1] |
| Effort par défaut | Non documenté explicitement pour Fable 5 | [SINGLE SOURCE] / gap |

> Citation `claude --help` (v2.1.170, install locale) : *« --model <model> … Provide an alias for
> the latest model (e.g. 'fable', 'opus', or 'sonnet') or a model's full name (e.g.
> 'claude-fable-5'). »* [3]

---

## 4. Implications sécurité (prisme Sentinel)

### 4.1 Nouveaux env vars (à transformer en règles de détection)

Tous **confirmés verbatim** dans le changelog local [1] [CONFIDENCE: HIGH].

| Env var | Effet | Risque sécurité | Hint de détection |
|---|---|---|---|
| `CLAUDE_CODE_SAFE_MODE` / `--safe-mode` | Désactive CLAUDE.md, plugins, **skills, hooks, MCP** | **Bypass des contrôles de sécurité** (un hook d'audit, un guardrail MCP, un skill de policy sautent) | `CLAUDE_CODE_SAFE_MODE\s*=\s*1` / `--safe-mode` dans CI, scripts, dockerfiles |
| `CLAUDE_CODE_DISABLE_BUNDLED_SKILLS` / `disableBundledSkills` | Cache skills/workflows/commandes built-in au modèle | Réduction de surface défensive / contournement de skills de contrôle | `CLAUDE_CODE_DISABLE_BUNDLED_SKILLS\s*=\s*1` ; clé `disableBundledSkills` dans settings.json |
| `API_FORCE_IDLE_TIMEOUT=0` | Désactive le timeout idle 5 min (Vertex/Foundry) | Hang de stream indéfini → **DoS / exfiltration lente** | `API_FORCE_IDLE_TIMEOUT\s*=\s*0` |
| `OTEL_LOG_USER_PROMPTS` | Émet `user_system_prompt` / `user_prompt` (avec `command_name`/`source`) dans les spans OTEL | **Fuite de prompts utilisateur / system prompt** en télémétrie | `OTEL_LOG_USER_PROMPTS\s*=\s*(1\|true)` |

> **Déjà couvert** par EIR-2026-06-04 (règle `LLM-DEBUG-001`) : `OTEL_LOG_TOOL_DETAILS=1`
> (params bash/MCP dans `tool_decision`/`tool_result`) et `OTEL_LOG_TOOL_CONTENT=1`. À **étendre**
> avec `OTEL_LOG_USER_PROMPTS` (même famille de fuite télémétrie) plutôt que dupliquer.

### 4.2 Durcissements plateforme (informationnel / KB)

- **Confused Deputy mitigé (v2.1.166)** : les messages relayés via `SendMessage` ne portent plus
  l'autorité utilisateur ; la session réceptrice rejette les demandes de permission relayées [1].
  → pattern de menace à documenter (élévation de privilège cross-session).
- **Glob dans les deny rules (v2.1.166)** : `*` = deny-all (config whitelist-style) ; les allow rules
  rejettent désormais les globs non-MCP [1]. → bonne pratique de hardening à recommander.
- **Anti-downgrade (v2.1.163)** : `requiredMinimumVersion` / `requiredMaximumVersion` [1].
- **OTEL cert trust gate (v2.1.163)** : settings projet non fiables ne peuvent plus fixer un chemin
  de certificat client OTEL sans confirmation de trust [1]. → contre une injection de cert via repo.
- **MCP policy enterprise (v2.1.169)** : application cohérente startup/reconnect/IDE [1].

### 4.3 Fable 5 — notes sécurité

- `thinking:{type:"disabled"}` → **400** : un scanner qui audite du code appelant l'API Fable 5
  doit détecter ce paramètre comme bug bloquant (cf. règle de migration modèle) [5].
- Garde-fous cyber par classifieur **évitables par prompting** ; fallback Opus 4.8 = mitigation
  partielle, **pas un blocage dur** [CONTESTED — caractérisation, source vendor] [5][6].
- `stop_reason:"refusal"` en HTTP 200 : le code appelant doit le gérer comme un refus, pas un succès [5].

### 4.4 Chaîne d'approvisionnement MCP / SDK

- **CVE-2026-0621** — ReDoS dans `UriTemplate` du **MCP TypeScript SDK** (`partToRegExp`,
  backtracking catastrophique sur patterns RFC 6570 exploded `{/id*}`). Affecté **≤ v1.25.1**,
  **corrigé en v1.25.2**. CWE-1333. GHSA-8r9q-7v3j-jr4g [9][10] [CONFIDENCE: HIGH].
  → règle CVE candidate ; cible `@modelcontextprotocol/sdk` (TS) < 1.25.2.
- **MCP Python SDK v1.27.0** : fix command injection + validation OAuth **RFC 8707** (resource).
  Protection DNS-rebinding **non confirmée** [11] [PARTIAL].
- **MCP spec 2025-11-25** : Tasks (SEP-1686, async « call-now/fetch-later ») ; **URL elicitation
  (SEP-1036)** = mécanisme de **prévention SSRF** (HTTPS-only + validation d'URL **requise**),
  **PAS** un vecteur SSRF [12] [correction vs Wave 1].
- **anthropic-sdk-python v0.108.0 (2026-06-09)** : ajoute `claude-fable-5` + `claude-mythos-5` +
  fallbacks server-side sur refus [13]. (SDK TS v0.103.x non vérifiable — 404 [gap].)

---

## 5. Ce que Sentinel doit intégrer (actionnable → evolve)

| # | Action | Cible Sentinel | Priorité |
|---|---|---|---|
| 1 | Ajouter `claude-fable-5` (id, pricing $10/$50, 1M/128K, classe Mythos, breaking `thinking:disabled`→400, dispo 2026-06-09) | `knowledge-base/anthropic-intel/feature-inventory.json` | P1 |
| 2 | Étendre la whitelist modèles : accepter **`fable`** et **`claude-fable-5`** | `scripts/pattern-gen.py:212` `_ALLOWED_MODELS` | P1 |
| 3 | Mettre à jour tiers d'agents + cost-monitoring + model-migration notes Fable 5 | `skills/security/SKILL.md` (+ miroir `skills/sentinel-evolve/SKILL.md`) | P1 |
| 4 | Étendre `LLM-DEBUG-001` à `OTEL_LOG_USER_PROMPTS` (fuite prompts télémétrie) | `knowledge-base/domains/llm-ai/rules.json` | P2 |
| 5 | Nouvelle règle « security-control bypass » : `CLAUDE_CODE_SAFE_MODE` / `--safe-mode` désactive hooks/MCP/skills | `knowledge-base/domains/llm-ai/` (ou `infra/`) | P2 |
| 6 | Règle DoS/exfil : `API_FORCE_IDLE_TIMEOUT=0` ; règle `CLAUDE_CODE_DISABLE_BUNDLED_SKILLS` | KB domaine approprié | P3 |
| 7 | Règle CVE : `@modelcontextprotocol/sdk` (TS) < 1.25.2 — ReDoS CVE-2026-0621 (CWE-1333) | `knowledge-base/cve-feed/` / supply-chain | P2 |
| 8 | Documenter patterns de menace : Confused-Deputy cross-session ; recommander glob deny-all + version pinning + OTEL cert trust | KB / SKILL.md hardening | P3 |

---

## Limitations & lacunes de couverture

- **Effort par défaut de Fable 5 dans Claude Code** non documenté explicitement (gap).
- **Fast mode Fable 5** : conclusion « non supporté » par **inférence d'absence** au changelog,
  pas par une affirmation positive [MED].
- **Mythos 5** (variant safeguards levés) : détails d'accès en source unique vendor [SINGLE SOURCE].
- **DNS-rebinding MCP Python v1.27.0** : revendiqué Wave 1, **non confirmé** en triangulation.
- **SDK TypeScript Anthropic v0.103.x** : page release inaccessible (404) — non vérifié.
- Caractérisation « garde-fous évitables » repose sur des sources vendor + presse — à traiter comme
  orientation, pas comme fait dur.
- Fenêtre temporelle étroite (6 jours) : v2.1.167/168 sans détail public publié.

---

## Sources

| # | Source | Tier | Biais |
|---|---|---|---|
| 1 | Claude Code CHANGELOG (`raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md` + cache local `~/.claude/cache/changelog.md`) | 1 | GREEN |
| 2 | Claude Code releases (`github.com/anthropics/claude-code/releases`) | 1 | GREEN |
| 3 | `claude --help` v2.1.170 (install locale) | 1 | GREEN |
| 4 | Models overview (`platform.claude.com/docs/en/about-claude/models/overview`) | 1 | GREEN |
| 5 | Launch guide Fable 5 / Mythos 5 (`platform.claude.com/.../introducing-claude-fable-5-and-claude-mythos-5`) | 1 | YELLOW (⚠️ vendor pour positionnement) |
| 6 | Annonce Anthropic (`anthropic.com/news/claude-fable-5-mythos-5`) | 1 | YELLOW (⚠️ vendor) |
| 7 | Effort docs (`platform.claude.com/docs/en/build-with-claude/effort`) | 1 | GREEN |
| 8 | Prompt caching docs (`platform.claude.com/docs/en/build-with-claude/prompt-caching`) | 1 | GREEN |
| 9 | GitHub Advisory GHSA-8r9q-7v3j-jr4g (CVE-2026-0621) | 1 | GREEN |
| 10 | MCP TypeScript SDK releases (fix v1.25.2) | 1 | GREEN |
| 11 | MCP Python SDK releases (v1.27.0) | 1 | GREEN |
| 12 | MCP spec 2025-11-25 changelog (`modelcontextprotocol.io`) | 1 | GREEN |
| 13 | anthropic-sdk-python releases (v0.108.0) | 1 | GREEN |
| 14 | CNBC / TechCrunch (lancement Fable 5, 2026-06-09) | 2 | YELLOW |
| 15 | AWS blog (Fable 5 sur Bedrock) | 2 | YELLOW (⚠️ commercial) |

---

*Méthodologie : Deep Research v4, L4. Wave 1 = 5 agents (5 angles, fan-out Sonnet). Phase 2 =
triangulation des claims pilotant du code (env vars vérifiés sur changelog local ; CVE vérifié
NVD/GHSA — 2 corrections appliquées). Phase 3 vote inline-mergée (sujet factuel, sources Tier-1
primaires). Tous les claims tracés à une URL/artefact fetché.*
