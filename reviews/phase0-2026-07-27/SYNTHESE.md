# Synthèse de la revue croisée — phase 0 du cycle evolve, 2026-07-27

**Objet** : les 6 recommandations P1 que Claude Opus 5 a écrites, puis appliquées lui-même, au cours
d'un cycle `/sentinel-evolve`. Aucun tiers n'était intervenu entre le diagnostic et l'implémentation.

**Protocole** : gabarit scellé de lab-73 (`reviews/GABARIT-MANDAT-REVUE.md`, 26/07), seul le bloc
« Objet du round » renseigné — la règle 23 interdit à l'évalué de rédiger son propre mandat. Mandat
strictement identique aux deux évaluateurs, appelés en headless à `xhigh`, stdin fermé, timeout 2400 s.

| Évaluateur | Verdict | Findings | Coût / durée | Modèle résolu |
|---|---|---|---|---|
| Claude Fable 5 | **`revise`** | 10 (5 majeurs) | 7,54 $ · 51 832 tok | `canonicalModel: claude-fable-5` — **aucun basculement** |
| GPT-5.6-Sol | **`revise`** | 8 (1 blocker, 6 majeurs) | ~14 min | `gpt-5.6-sol` |

Les deux convergent sur `revise`. **Aucun n'a conclu `seal`.**

---

## 1. Ce sur quoi les deux convergent — le noyau fiable

| Défaut | Statut après vérification de première main |
|---|---|
| **Le corpus soumis était périmé** | Confirmé, et c'est ma faute : la copie de revue (11:59) est un préfixe tronqué de l'archive (12:03). Toute la section 7 manquait — dont `FIND-001` et le test de faux positifs, que le mandat demandait précisément d'éprouver |
| **Le pseudo-code de dispatch assignait encore `haiku`** | Confirmé par lecture directe : ligne 128 corrigée en `sonnet`, ligne 152 laissée en `haiku`. J'avais corrigé la documentation et laissé le code |
| **Patterns sandbox inopérants sur leur cible réelle** | Confirmé et mesuré : sur un `settings.json` indenté, 1 seul réglage sur 4 était détecté en ligne-par-ligne. Règle promue HIGH 7.1 sans passer par le gate `rule-tester.py` du dépôt |
| **Le « ≈ 84 % » n'est pas mesuré** | Confirmé — les deux le classent `avance_sans_preuve`. Aucun tableau de classification ne produit ce chiffre |
| **« Patterns validés » était faux au moment où c'était écrit** | Les deux le classent `faux`. Seuls les positifs avaient été testés |
| **`FIND-001` est réel** | Les deux l'ont reproduit dans le code |
| **Notes de migration modèles dupliquées entre les deux skills** | Retenu en sur-ingénierie par les deux |

## 2. Ce que chacun a vu seul — la partie informative

C'est exactement le motif que la doctrine du 26/07 prédit : **la famille opposée voit le contenu et la
logique, la même famille voit la posture.**

**GPT-5.6-Sol seul** — défauts de logique et d'exécution :

- 🔴 **Blocker** : le pipeline `auto` **déploie (6) avant de commiter (7)**, alors que `CLAUDE.md`
  impose l'ordre inverse. Il déploie donc un état non versionné — **il recrée exactement le drift
  qu'il prétend réparer**. Fable ne l'a pas vu.
- `bash scripts/deploy.sh` nu est un **no-op depuis le 2026-04-17** (`DRY_RUN=1` par défaut). Le hook
  d'auto-redéploiement est mort depuis quatre mois. J'avais édité cette ligne le matin même sans le voir.
- Les `negative_patterns` sont globaux à la règle : un `allowAppleEvents: false` bénin **masque** un
  `strictAllowlist: false` réel. Générateur de faux négatifs, vérifié par rejeu.
- Les consignes Opus 5 sont **purement documentaires** : ni branche `stop_reason: "refusal"`, ni filtre
  de sévérité aval ne sont implémentés. Un scan partiellement refusé peut rendre zéro finding et
  paraître propre.
- La récupération runtime→repo **inverse la source de vérité sans gate de provenance** : j'ai importé
  en bloc du contenu dont l'origine n'était pas vérifiée.

**Claude Fable 5 seul** — défauts de posture et de portée :

- Les 6 exclusions anti-faux-positifs vivaient dans les **règles**, donc s'appliquaient à **tout projet
  audité**. J'avais échangé 7 faux positifs contre un **trou de détection générique** — le mode d'échec
  n°1 documenté du lab, reproduit une heure après l'avoir lu dans le gabarit.
- `.claude/rules/deploy-reminder.md` gardait `~/.claude/skills/security/`, **un chemin qui n'existe
  pas**. Le garde-fou censé empêcher l'édition directe du runtime pointait dans le vide — ce qui
  explique largement que la violation du 25/07 soit passée.
- Phrase anglaise orpheline restée accrochée en fin de note française ; pattern
  `OTEL_CONTENT_MAX_LENGTH` à seuil arbitraire (≥10 M) qui laisse passer des caps 16× le défaut.

## 3. Leur seul désaccord

**Sévérité de `FIND-001`.** Fable le tient pour un défaut grave et établi. Sol dit `HIGH` excessif tant
qu'aucun consommateur automatique n'applique `pending-updates.json` — l'impact reste conditionné à une
action humaine. **Tranché en faveur de Sol** : rétrogradé en `MEDIUM`. La proportionnalité prime.

## 4. Ce que j'ai contesté

Fable affirme que les patterns sandbox « ne détectent ni `filesystem.disabled` ni `credentials` ».
Mesuré : `filesystem.disabled` **matche** sur lecture fichier entier, il n'échoue qu'en ligne-par-ligne ;
`credentials` ne matche effectivement jamais. Comme les agents grepent ligne par ligne, le fond tient —
mais la formulation est trop absolue et je ne l'ai pas reprise telle quelle.

## 5. Corrections appliquées — 10

1. Exclusions sorties des règles → `.sentinel.json` du dépôt (portée locale rétablie)
2. `negative_patterns` réduits aux seules annotations — la neutralisation croisée est fermée (rejeu : 1 positif, 0 négatif)
3. Patterns sandbox réécrits pour le matching ligne-par-ligne (1 → 2 réglages détectés) + limite documentée
4. `LLM-CCSANDBOX-001` : HIGH 7.1 → **MEDIUM 6.3**, avec vecteur CVSS v4 explicite et bloc `validation` honnête
5. Pattern `OTEL_CONTENT_MAX_LENGTH` retiré → remédiation textuelle
6. Pseudo-code de dispatch : `haiku` → `sonnet`
7. Consignes Opus 5 marquées explicitement **documentaires et non implémentées**
8. `.claude/rules/deploy-reminder.md` : chemin mort corrigé + ordre commit→deploy inscrit
9. `security/SKILL.md` : `DRY_RUN=0` rendu obligatoire, no-op documenté
10. Pipeline `auto` : **ordre inversé** en commit → deploy, avec contrôle de santé à fermeture d'échec

## 6. Ce qui reste ouvert

- **Sourcer les affirmations Opus 5** (System Card, docs pricing/features). Les deux l'ont relevé.
  Relève de la phase 1 de l'audit complet — la recherche documentaire n'a pas encore eu lieu.
- **Implémenter** la branche `refusal` et le filtre de sévérité aval. Travail de code, pas de doc.
- **Passer les 3 règles par `rule-tester.py`** avec des fixtures `settings.json` multi-lignes réalistes.
- **Refaire un round sur corpus à jour.** Celui qui a été jugé était périmé : les deux verdicts portent
  en partie sur un objet qui n'existait plus. Les affirmations 2, 3, 6 et 7 ont en revanche été
  vérifiées de première main dans le dépôt et restent valides.

## 7. Réserves de méthode que je porte

- **J'ai modifié `rules.json` pendant que les relecteurs le lisaient.** Sol a lu la version
  post-correctif, Fable a pu lire l'une ou l'autre. Le corpus a bougé sous eux, par ma faute.
- **Le test de faux positifs mesure la précision sur du bruit** : ce dépôt ne contient aucun vrai
  positif. Il ne dit rien du recall sur de vraies configurations vulnérables.
- **Le panel reste à moitié endogame** : deux des trois modèles sont d'Anthropic, et l'un d'eux est
  l'auteur. Fable l'a signalé lui-même en angle mort.
- **Aucune exécution réelle** de Claude Code v2.1.220 n'a validé les branches concernées. Tout a été
  tracé statiquement.
