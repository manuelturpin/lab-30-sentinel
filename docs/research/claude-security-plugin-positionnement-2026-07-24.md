# Positionnement Sentinel face au plugin Claude Security — options ouvertes

> Établi le 2026-07-24 à partir du rapport deep-research L3 `reports/claude-security-plugin-2026-07-24.md` (score éval 4.57/5, fact-check 5/5 sur sources primaires). **Décision à trancher avant le 2026-08-24** (échéance 30 j fixée par le rapport). Ce document expose les options — il ne tranche pas ; la décision donnera lieu à un ADR dans `docs/adr/`.

## Le fait nouveau

Anthropic a lancé le 22/07/2026 le plugin `claude-security` (bêta, marketplace officiel) : scan de vulnérabilités multi-agents en 6 phases (inventory → threat model → research → sweep → panel → adversarial), quorum 2-sur-3 par finding, patches vérifiés jamais auto-appliqués. Inclus dans le forfait payant (chaque scan consomme les limites du plan, **aucun quota dédié**), licence propriétaire (code lisible sur GitHub, non réutilisable). C'est un concurrent officiel, gratuit à la marge, installé en une commande, sur le cœur de `/sentinel-security` : le scan de code à la demande.

Deux faits confirment des findings Sentinel existants (REC-003/004, cycle Evolve 2026-06-10) :
- Le fallback Fable 5 → Opus sur contenu sécurité est désormais **documenté officiellement** comme comportement attendu du plugin, et il est **persistant** (la session reste sur Opus). Notre règle « ne pas orchestrer Sentinel sur Fable 5 » est validée par l'éditeur.
- `CLAUDE_CODE_SUBAGENT_MODEL` écrase les frontmatters `model:` des agents de plugin (précédence n°1 officielle) — vrai pour le plugin d'Anthropic comme pour les agents Sentinel. La variable globale `=sonnet` de la machine dégrade silencieusement tout scan (le sien comme le nôtre si on pinne des modèles par agent).

## Cartographie du recouvrement

| Capacité | Plugin Claude Security | Sentinel aujourd'hui |
|---|---|---|
| Scan de code à la demande (injection, auth, mémoire, crypto/secrets) | ✅ cœur du produit, quorum 2/3 | ✅ 12 agents, KB 130 règles curées + CVE rules |
| Vérification adversariale des findings | ✅ panel 3 lentilles + red-team effort max | ❌ (agents parallèles sans vote croisé) |
| Patches vérifiés | ✅ clone scratch + agent vérificateur | ❌ |
| Scan headers HTTP déployés (runtime) | ❌ | ✅ MCP `scan-headers` + garde SSRF |
| Dépendances / OSV / supply-chain | ❌ (hors périmètre) | ✅ MCP `scan-dependencies`, feed NVD/OSV/GitHub/KEV |
| SBOM CycloneDX | ❌ | ✅ MCP `generate-sbom` |
| Scoring CVSS v4 + EPSS, sortie SARIF 2.1.0 | ❌ (rapport MD/JSONL maison) | ✅ |
| Veille CVE continue (crons), confidence bayésienne | ❌ (scan ponctuel) | ✅ 4 crons, feedback-loop |
| RAG sécurité (105k docs runtime) | ❌ | ✅ |
| Mobile, WebSocket, CORS, SSL/TLS, data-privacy, static-site | ❌ (4 catégories code fixes) | ✅ agents dédiés |
| Audit skills IA / MCP / config Claude Code | ❌ | ✅ (`/sentinel-evolve audit`, skill-audit) |

Lecture honnête : le recouvrement frontal est limité au **scan de code source à la demande** — mais c'est la partie la plus visible de Sentinel. Sur ce segment, le plugin est mieux armé (quorum, patches, intégration native). Tout le reste (runtime, supply-chain, formats compliance, veille continue, domaines hors-code) reste hors de son périmètre.

## Les options

### Option A — Cannibaliser (adopter les patterns du plugin dans Sentinel)
Intégrer dans `/sentinel-security` : quorum 2-sur-3 avec confiance plafonnée sur vote partagé, panel à lentilles (reachability/impact/defenses), revision stamps liant rapport et commit, tiers d'effort paramétrés, skip des règles mémoire sur langages memory-safe. La licence propriétaire interdit la reprise de code, pas des idées d'architecture.
- **Pour** : améliore directement la faiblesse n°1 de Sentinel (pas de vérification croisée des findings → faux positifs).
- **Contre** : investit dans le segment où Anthropic est le plus fort et itérera le plus vite ; course perdue d'avance à ressources égales.
- **Coût estimé** : 2-3 sessions (protocole de vote dans `_protocol.md` + agrégateur).

### Option B — Se différencier (repositionner Sentinel sur le hors-périmètre)
Acter que le scan de code à la demande revient au plugin, et recentrer Sentinel sur : runtime (headers), supply-chain (OSV/SBOM), compliance (SARIF/CVSS/EPSS), veille continue (crons/CVE/KEV), domaines non couverts (mobile, WebSocket, CORS, SSL/TLS, data-privacy), audit skills/MCP/config IA. Le pitch devient « ce que le plugin ne voit pas ».
- **Pour** : zéro concurrence frontale avec l'éditeur de la plateforme ; les différenciateurs existent déjà et fonctionnent.
- **Contre** : abandonne l'identité historique « scanner de code » ; demande une refonte du SKILL.md orchestrateur et du discours.
- **Coût estimé** : 1-2 sessions (repositionnement doc + orchestration qui délègue le scan code au plugin quand il est installé).

### Option C — Hybride orchestré (recommandation du rapport, à valider)
`/sentinel-security` devient l'orchestrateur de défense en profondeur : il **invoque le plugin Claude Security** pour le scan de code quand il est installé (ou le recommande), garde ses agents pour les domaines hors-périmètre, et enrichit les findings du plugin avec ce que lui seul sait faire (scoring CVSS v4 + EPSS via la KB CVE, export SARIF, corrélation feed KEV). Adopter au passage les patterns de vérification (quorum) pour les agents restants.
- **Pour** : additionne les forces au lieu de dupliquer ; le JSONL du plugin (`CLAUDE-SECURITY-RESULTS.jsonl`) est machine-readable, donc enrichissable en SARIF ; cohérent avec la philosophie « defense-in-depth stack » affichée par Anthropic elle-même.
- **Contre** : dépendance à une bêta non versionnée-stable (v0.10.0) ; le format JSONL peut changer sans préavis.
- **Coût estimé** : 2-4 sessions (adaptateur JSONL→SARIF + orchestration conditionnelle + quorum sur agents restants).

### Option D — Statu quo documenté
Ne rien changer, surveiller via `/sentinel-evolve` (le cron anthropic-sync bi-hebdo détectera les évolutions du plugin).
- **Pour** : coût nul immédiat.
- **Contre** : le rapport la qualifie explicitement de « seule mauvaise option » — Sentinel perdrait sa pertinence sur son segment le plus visible face à un outil gratuit inclus dans Claude Code.

## Étape préalable commune (quelle que soit l'option)

**Benchmark empirique** : lancer le plugin sur `tests/vulnerable-app/` et le corpus `tests/fixtures/` (7 vulnérables + 6 safe), comparer précision/rappel/coût tokens avec `/sentinel-security` sur le même corpus. C'est le seul moyen d'objectiver le recouvrement réel — aucun benchmark tiers n'existe (plugin à J+2). Précautions machine : `unset CLAUDE_CODE_SUBAGENT_MODEL` avant le scan, session Opus (pas Fable 5), mode auto recommandé par le plugin.

## Prochaines actions

1. Benchmark plugin vs Sentinel sur le corpus de test (1 session, produit les chiffres pour trancher)
2. Trancher A/B/C/D avant le **2026-08-24** → ADR dans `docs/adr/`
3. Si C : spécifier l'adaptateur JSONL→SARIF (le schéma JSONL du plugin est dans le rapport, section 1)
4. Ajouter le plugin à la veille `config/evolve-targets.json` pour suivi de version par `/sentinel-evolve`

## Sources

Rapport complet (33 sources, code source du plugin fetché, analyse contrarian Checkmarx/Semgrep/Snyk incluse) : `reports/claude-security-plugin-2026-07-24.md`. Canonique : `lab/reports/claude-security-plugin-fable5-openai.md`.
