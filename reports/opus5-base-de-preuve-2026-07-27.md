# Base de preuve Opus 5 pour Sentinel — phase 1

**Date** : 2026-07-27 · **Niveau** : L2 ciblé · **Mandat** : vérifier sur sources primaires les affirmations Opus 5 que la revue croisée du 27/07 avait signalées comme non sourcées.

> **Recalibrage assumé.** La phase 1 était cadrée en L4. Le skill interne `claude-api`, chargé en amont, a résolu 7 des 9 affirmations : le périmètre résiduel s'est réduit à 4 questions factuelles ponctuelles avec sources primaires connues. Un L4 (60+ sources) y aurait été disproportionné.

---

## Verdict par question

### Q1 — « Classifieurs cyber renforcés sur Opus 5, refus plus probables » → ❌ **FAUX, direction inversée**

Source primaire : [Introducing Claude Opus 5](https://www.anthropic.com/news/claude-opus-5) [1]

> « proportionally **less restrictive** than those on Fable 5 […] we expect the classifiers to **intervene around 85% less often** than they do for Fable 5 »

Le régime d'Opus 5 est **similaire à Opus 4.8**, avec un durcissement circonscrit à une gamme étroite de tâches cyber. L'affirmation déployée disait exactement l'inverse.

**Ce qui est bloqué**, par [le centre d'aide](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude) [2] :

| Catégorie | Contenu | Statut |
|---|---|---|
| *Prohibited use* | Exfiltration massive de données, développement de ransomware | Toujours bloqué |
| *High-Risk Dual use* | Exploitation de vulnérabilités, outillage offensif | Bloqué par défaut, levable via CVP |

**La recherche de vulnérabilités dans du code source est explicitement autorisée** — c'est le cœur d'activité de Sentinel, qui lit du source et applique des règles. Il ne fait ni exploitation, ni outillage offensif.

### Q2 — « Le System Card note que les benchmarks multi-agents ont été mesurés sans safeguards actifs » → ⚠️ **NON CORROBORÉ**

L'annonce Opus 5 ne mentionne **ni** benchmarks sans safeguards, **ni** délégation multi-agents, **ni** lien entre classifieurs et contextes parallèles. Le System Card complet (PDF > 10 Mo) n'a **pas pu être fetché** — l'affirmation n'est donc pas formellement réfutée, mais elle n'est corroborée par aucune source accessible.

Ce que le System Card rapporte en sens contraire, via recherche : Opus 5 montre **les plus forts gains en robustesse aux prompt injections** sur coding, computer use et browser use. [CONFIANCE : MOYENNE — via résumé de recherche, PDF non fetché]

### Q3 — Effort recommandé pour un workload agentique → ✅ **`high`, et la doctrine machine avait raison**

Source primaire : [docs — Effort](https://platform.claude.com/docs/en/build-with-claude/effort.md) [3]

> « **Start with `high`, the default**, and adjust based on your evals: step up to `xhigh` for demanding coding and agentic work […] and use `low` and `medium` **liberally** as your primary control for token cost and response time wherever your evals show quality holds. »

**Piège identifié.** La même page dit l'**inverse** pour Opus 4.7 et 4.8 : « **Start with `xhigh` for coding and agentic use cases** ». La recommandation a changé avec Opus 5 — et la doc l'anticipe : « If you carried effort settings over from an earlier model, run a fresh effort sweep on your evals rather than reusing them. »

C'est cette transposition 4.7/4.8 → Opus 5 que porte le skill interne `claude-api`, et qui m'avait fait douter à tort du passage `xhigh` → `high` du 25/07. **Ce passage est correct.**

Corollaires sourcés :
- « Effort controls thinking volume, **not** visible response length: on Claude Opus 5, changing effort does not reliably shorten responses » → pour de la concision, prompter, ne pas baisser l'effort.
- À `xhigh`/`max`, `thinking:{type:"disabled"}` → **HTTP 400**. `max_tokens` ≥ 64 K recommandé.

### Q4 — Cyber Verification Program → ✅ **documenté, et non nécessaire pour Sentinel**

Portail [portal.anthropic.com/programs/cvp](http://portal.anthropic.com/programs/cvp), décision sous **2 jours ouvrés**. ⚠️ **Le CVP exige la rétention de données activée** — un compte en Zero Data Retention doit créer un workspace séparé.

Vu le régime déjà permissif d'Opus 5 sur l'audit de source, **le CVP n'apporte rien à Sentinel en l'état**. Il ne deviendrait utile que pour de l'exploitation de vulnérabilités ou de l'outillage offensif — hors périmètre.

---

## Conséquences opérationnelles

1. **Abandonner la posture défensive sur Opus 5.** La note « classifieurs renforcés » poussait à une sur-ingénierie (gestion de refus, fallbacks, prudence sur le fan-out) calibrée sur un risque qui n'existe pas à ce niveau. Garder la garde `stop_reason` — bon réflexe, coût nul.
2. **La doctrine « ne pas orchestrer Sentinel sur Fable 5 » est confirmée et renforcée** : Fable 5 est bien le modèle restrictif, avec ~7× plus d'interventions de classifieur qu'Opus 5.
3. **`effort: high` sur `sentinel-security` est validé** par la source primaire.
4. **Le claim non sourcé a essaimé** : il vit aussi dans `lab-35-deep-research/skill/SKILL.md` (§ *Agent spawning discipline*), où il justifie le cap à 12 agents par wave. Le cap reste défendable — limite matérielle Claude Code, et Opus 5 délègue plus volontiers — mais sa justification est à corriger là-bas.

---

## Limites de cette recherche

- **Le System Card n'a pas été lu** (PDF > 10 Mo, limite de fetch). La question Q2 reste ouverte sur le fond, close sur la direction.
- **Résumés de recherche pour deux points** : la robustesse aux prompt injections et la comparaison Opus 4.8 viennent d'un résumé de résultats, pas d'une lecture directe. Marqués [CONFIANCE : MOYENNE].
- **Niveau L2** : 5 sources primaires, pas de triangulation multi-angles ni de phase de vote. Suffisant pour des questions factuelles à source unique faisant autorité ; insuffisant pour une question ouverte.
- **Aucun test empirique** : rien n'a été exécuté contre l'API pour mesurer un taux de refus réel.

## Sources

1. [Introducing Claude Opus 5](https://www.anthropic.com/news/claude-opus-5) — Anthropic — Tier 1 primaire — 🟢
2. [Real-time cyber safeguards on Claude](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude) — Anthropic — Tier 1 primaire — 🟢
3. [Effort — Claude Docs](https://platform.claude.com/docs/en/build-with-claude/effort.md) — Anthropic — Tier 1 primaire — 🟢
4. [Claude Opus 5 System Card (PDF)](https://www-cdn.anthropic.com/b514064af1408018e64b1ad24e7d5e75850b4ffd/Claude%20Opus%205%20System%20Card.pdf) — Anthropic — Tier 1 primaire — 🟢 — **non fetché (> 10 Mo)**
5. Skill interne `claude-api` (bundled, v2.1.220) — Anthropic — Tier 1 — 🟢 — *contient l'erreur de transposition d'effort signalée en Q3*
