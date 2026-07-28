# Plan d'audit qualité de Sentinel — v3

**Auteur** : Claude Opus 5 · **Round 3 sur 3 — le dernier.** Sans double `seal`, l'audit n'est pas lancé et la main revient à l'utilisateur.

**Historique** : v1 `revise`/`revise`, v2 `revise`/`revise`. Six défauts convergents au round 2, corrigés ci-dessous.

---

## 0. Correctifs du round 2 — ce qui ferme, et ce qui ne ferme pas

| Défaut r2 (les deux) | Correctif v3 | Ferme ? |
|---|---|---|
| L'« exécution réelle » est un no-op — aucune règle n'atteint la validation | **Sonde exécutée** : 48 règles remises en `untested` sur copie temporaire, code réel du testeur réutilisé. Résultat : **0/48 matchent**. Journal `gate-probe.log` au corpus | Oui — l'exécution mesure enfin quelque chose |
| Frontière du manifeste : `tests/vulnerable-app/src/server.js` réellement consommé, absent | **`tests/vulnerable-app/**` inclus** (l'entrée réelle du gate) + `rule-tester-run.log` + `gate-probe.log` | Oui |
| Aucune sortie du pipeline au corpus | **`pipeline-output-active.json`** : les **31 règles `status=active`**, c'est-à-dire exactement celles promues par le gate. Critère de sélection neutre et vérifiable (pas d'échantillonnage arbitraire) | Oui |
| Composants référencés absents | **`rag/query.py`, `rag/indexer.py`, config RAG, template de rapport** ajoutés | Oui |
| Chaîne de preuve de la publication : promesse | **Le dossier de revue entier est commité dans git.** Plan, mandat, schéma, manifeste, verdicts bruts des rounds 1 et 2 : épinglés et horodatés par l'historique. L'ordre de publication devient vérifiable après coup | Oui — c'est un mécanisme, pas une déclaration |
| §5 invalide trop largement, sans reprise | **Réécrit** (§5) : le siège défaillant est relancé une fois, l'autre verdict est conservé, et une relance ne consomme pas de round | Oui |

**Ce que je ne ferme pas, et je le dis** : les 3 244 règles CVE sans statut restent hors corpus. Les inclure ajouterait ~2 Mo pour des règles dont la sonde montre qu'elles ne matchent rien de mesurable. Les 31 `active` + les 11 `rules.json` curées suffisent à juger la **logique** du pipeline. À contester si vous pensez que le volume lui-même est le sujet.

## 1. Ce que l'audit doit établir

1. **L'architecture tient-elle ?** Orchestrateur → 12 agents parallèles → `Finding[]` → SARIF, adossé à une base de règles alimentée par un pipeline automatisé. Qu'est-ce qui casse à l'échelle, en échec partiel, quand deux agents se contredisent ?
2. **La logique est-elle correcte ?** Les agents font-ils ce que `_protocol.md` prétend ? Le pipeline produit-il des détecteurs valides, et le gate mesure-t-il ce qu'il annonce ?
3. **Le design est-il proportionné ?** Qu'est-ce qui disparaîtrait sans perte ?

## 2. Corpus — gelé, 70 fichiers, 633 222 octets

Épinglé au commit du manifeste, SHA-256 par fichier (`CORPUS-MANIFEST.json`). **Les artefacts du round lui-même** — ce plan, le mandat, le schéma, les verdicts bruts r1 et r2 — ne sont pas hashés dans le manifeste : ils sont **commités dans git**, ce qui les épingle et les horodate mieux qu'un hash que j'aurais moi-même calculé.

| Bloc | Fichiers |
|---|---|
| Orchestrateur + 12 agents + `_protocol.md` | 14 |
| Pipeline (`cve-sync`, `pattern-gen`, `rule-tester`, `feedback-loop`) | 4 |
| `knowledge-base/domains/*/rules.json` — **les 11** | 11 |
| `tests/fixtures/**` + `tests/vulnerable-app/**` — l'étalon réel du gate | ~20 |
| `mcp-servers/sentinel-scanner/src/**/*.ts` | 11 |
| `rag/query.py`, `rag/indexer.py`, config, template de rapport | ~4 |
| Sortie du pipeline : 31 règles `active` + 2 journaux d'exécution | 3 |

## 3. Faits d'exécution versés au corpus — données, pas conclusions

**a. `rule-tester.py` en l'état** (`rule-tester-run.log`) : charge 8 fichiers vulnérables / 512 lignes et 6 sains / 422 lignes, puis `Untested rules: 0`.

**b. Distribution des statuts** sur les 3 390 règles CVE du dépôt : **3 244 sans aucun statut**, 100 `no-matches`, 31 `active`, 15 `needs-review`. `rule-tester.py:87` filtre sur `status == "untested"` exactement — les 3 244 sont donc invisibles au gate.

**c. Sonde de précision** (`gate-probe.log`) : 48 règles sans statut (5 par domaine, seed 42) remises en `untested` sur copie temporaire, évaluées par le code réel du testeur. **0/48 produisent une précision calculable** — aucune ne matche le corpus vulnérable.

> **Réserve que je porte moi-même** : le corpus du gate fait 8 fichiers et 512 lignes. Une règle CVE visant une bibliothèque absente de ce corpus ne peut pas matcher. « 0/48 » ne démontre donc pas que les règles sont mauvaises — il démontre que **le gate ne peut pas les évaluer**. Aux relecteurs de dire si cette lecture tient ou si elle est encore trop généreuse.

## 4. Mon rôle : répondant, pas juge

- **Je ne rends pas de verdict.** Deux évaluateurs, tous deux extérieurs à l'auteur.
- **Je réponds** : sur chaque finding, acceptation ou contestation **avec la vérification qui la fonde** (commande, fichier, ligne).
- **Les verdicts bruts sont commités dans git avant toute synthèse** — l'historique prouve l'ordre. C'est ce qui manquait aux rounds 1 et 2.
- **Règle de traitement, pré-engagée** : les deux d'accord → retenu. Divergence → publiée telle quelle. Un seul le voit → retenu, marqué « non corroboré ». Je conteste → contestation et preuve publiées, **le finding reste au rapport**.

## 5. Incidents d'exécution — avec reprise

- **Bascule `canonicalModel`** : le siège défaillant est **relancé une fois**. L'autre verdict est **conservé** — il est sain, l'écarter serait disproportionné. Si la relance bascule encore, le round est rendu avec **un seul évaluateur** et l'annonce explicite que la diversité de famille est perdue. **Une relance ne consomme pas de round.**
- **Timeout / sortie non conforme au schéma** : même traitement — relance une fois, puis rendu dégradé annoncé.
- **Divergence de hash** entre un fichier lu et le manifeste : là oui, round invalide — le corpus n'est plus celui qui a été validé.

## 6. Ce que l'audit ne fera pas

- Pas de scan `/sentinel-security` de bout en bout sur un vrai projet.
- Aucun jugement de couverture réelle des vulnérabilités.
- Aucune comparaison au plugin officiel (échéance 24/08).
- Panel à deux évaluateurs, une seule famille extérieure.
- **Défaut connu et non porté au round 2, déclaré ici** : Sentinel a 12 agents pour 11 domaines de règles ; l'agent websocket lit un fichier qui n'existe ni en repo ni en runtime. Signalé par Sol au round 1, je ne l'avais pas repris. Il est dans le périmètre de l'audit.

## 7. Coût

Rounds 1 et 2 : ~10,6 $ et 89k tokens de sortie côté Fable, ~25 min côté Sol. L'audit porte sur 633 Ko. Ordre de grandeur : **25-40 $ côté Fable**, 35-50 min côté Sol.
