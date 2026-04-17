# Sentinel — Diagnostic produit et plan d'exécution

- **Date** : 2026-04-17
- **Auteur** : Claude Opus 4.7, posture Senior Product Engineer
- **Complément de** : `audits/AUDIT-OPUS-47-2026-04-17.md` (audit technique)

---

## 1. Diagnostic produit — 5 points

### 1.1 Zero dogfooding réel
Sur `~/.sentinel/reports/archive/` : **toutes** les SARIF archives ciblent `vulnerable-app` (l'app de test interne). Aucun scan sur les 7 labs actifs qui mentionnent Sentinel dans leur CLAUDE.md (`lab-00`, `lab-16`, `lab-25`, `lab-32`, `lab-32-newsletter`, `lab-32-editorial`). Le seul usage réel de `/sentinel-security` sur un vrai codebase depuis 5 semaines, c'est **zéro**.

> Conclusion : on a construit un scanner dont le propriétaire n'éprouve pas le besoin de l'utiliser.

### 1.2 Trois skills, aucun récit
- `/sentinel-security` : audite un projet.
- `/sentinel-rag` : conseille sur n'importe quel RAG (pas Sentinel-spécifique).
- `/sentinel-evolve` : s'améliore tout seul.

Ce sont **trois ambitions empilées**, pas trois briques d'un même produit. `/sentinel-rag` n'a rien à voir avec la sécurité — il a été placé dans le namespace sentinel parce qu'il est né du besoin d'optimiser la KB de `/sentinel-security`. Un utilisateur qui installe Sentinel pour faire de la sécu découvre qu'il y a aussi un skill RAG-conseil : ça ajoute du bruit, pas de la valeur.

### 1.3 Auto-evolve = théâtre de progrès
- 9 entrées dans `metadata.json.update_history` (le vrai compteur d'événements significatifs).
- Mais 15+ commits `perf(evolve): apply EIR-...` en 3 semaines.
- `feature-inventory.json` track **151 features Anthropic sur 21 catégories**. Le skill récite tout l'univers Claude Code et prétend "exploiter" tout ce qu'il cite. Score auto-100 %.
- Les 6 recommandations du dernier EIR : *Opus 4.7 integration* (cosmétique : 3 lignes de texte ajoutées), *effort: xhigh* activé (1 ligne YAML), *cost monitoring tiers explicites* (tableau markdown).

C'est de l'entretien documentaire, pas de l'amélioration produit. Le "evolve score 94 %→100 %" est le **vanity metric** typique : augmente par construction dès qu'on ajoute un item au feature-inventory et qu'on écrit "USED" en commentaire.

### 1.4 Pas de positionnement vs `/security-review` natif
Claude Code v2.1.108+ embarque `/security-review` (comme skill intégré) et `/ultrareview` pour le multi-agent review. Ce sont les **concurrents directs** de `/sentinel-security`. Le SKILL.md de Sentinel les mentionne à la fin comme *optional cross-validation* — c'est-à-dire : "mon skill est le primary, le leur est l'optional". Inversion : sur un projet réel aujourd'hui, l'ordre serait l'inverse. `/security-review` fonctionne, a l'autorité Anthropic, et ne nécessite ni RAG ni KB locale.

La seule différence défendable de Sentinel aujourd'hui : **la KB CVE domain-spécialisée avec scoring CVSS/EPSS**. Mais vu la qualité réelle (22 règles actives, validées sur 13 fixtures), ce différenciateur n'existe pas encore en pratique.

### 1.5 Tension non résolue : lab privé ou produit public
- CLAUDE.md et scripts parlent de "`/sentinel-security` est disponible dans tous les projets Claude Code" (tournure produit).
- Les paths sont en dur sur `/Users/manuelturpin/...` (tournure lab privé).
- `sentinel-plugin/` existe (mais vide) → ambition packaging.
- `deploy.sh --remote user@vps:` existe → ambition multi-machine.
- Aucun README, aucun LICENSE, aucun fichier `INSTALL.md` → rien pour un utilisateur externe.

Le projet vit dans le flou : trop de structure pour rester un simple lab solo, pas assez de rigueur pour être un produit. C'est le pire des deux mondes — tu paies la complexité d'un produit sans en tirer les bénéfices.

---

## 2. Où la logique casse — user journey simulé

Je simule le parcours d'un dev externe qui découvrirait Sentinel aujourd'hui (ou de toi-même dans 6 mois, sur un autre lab).

| Étape | Ce que l'utilisateur cherche | Ce qu'il trouve | Verdict |
|-------|------------------------------|-----------------|---------|
| **Découverte** | "C'est quoi Sentinel ?" | Pas de README, CLAUDE.md parle de "systeme complet de cybersecurite IA" sans démo | **Flou** |
| **Install** | "Comment j'installe ?" | `bash scripts/setup.sh` + `scripts/deploy.sh` mais aucun guide. Prérequis : abo Max Claude Code, Python, Node, ChromaDB | **Friction élevée** |
| **1er scan** | "Montre-moi la valeur" | `/sentinel-security` lance 8-12 agents, produit un SARIF | **Lent mais impressionnant** |
| **1er insight utile** | "Qu'est-ce qui est grave ?" | 22 règles actives + scan-dependencies OSV. Sur un projet moyen, l'output sera majoritairement `scan-dependencies` (qui est juste un wrapper OSV). | **Déception** |
| **Retour** | "Je l'utilise combien de fois par semaine ?" | 0. L'utilisateur revient à `npm audit + gitleaks + /security-review`. | **Pas de rétention** |
| **Recommandation** | "Je le dis à qui ?" | À personne — la valeur n'a pas été démontrée | **Pas de bouche-à-oreille** |

Le seul scenario où Sentinel gagne : **scans réguliers automatisés avec CVE feed frais** — mais cet argument est valable pour `osv-scanner`, `trivy`, `snyk`, et `dependabot`, tous matures et gratuits. Sentinel n'a pas encore son moat.

---

## 3. Pistes d'amélioration produit (en complément de l'audit technique)

### P1 — Choisir un persona et un seul
Aujourd'hui Sentinel parle à : (a) toi en mode lab, (b) un futur utilisateur de plugin, (c) un LLM qui évolue tout seul. Les trois ont des contraintes opposées.

**Choix à faire** (je recommande (a)) :
- **Option (a) — Lab privé premium "mon scanner à moi"** : assumer. Simplifier. 1 utilisateur (toi), 47 labs à couvrir. Accepter les paths absolus. Jeter `sentinel-plugin/`, `deploy.sh --remote`. Se concentrer sur la qualité des 22 règles et leur utilité sur tes projets réels.
- **Option (b) — Plugin public** : demande 20x le travail. Réécrire l'install, doc, tests, isolation, pas de paths en dur, remplacer `claude -p` par une API key optionnelle, ajouter LICENSE, CI/CD, sécurité multi-user.
- **Option (c) — Skill auto-évolutif de démonstration** : assumer que c'est un objet de recherche, pas un outil. Publier un article "Ralphe loop appliqué à la sécu : 6 semaines d'observations". Arrêter de prétendre que c'est aussi un scanner.

### P2 — Tuer `/sentinel-evolve` comme skill user-facing
`/sentinel-evolve` est de l'infrastructure, pas un produit utilisateur. Le garder comme user-invocable expose la complexité d'ingénierie à quelqu'un qui voulait juste auditer son code. Le transformer en :
- Un script cron `scripts/evolve.py` qui tourne la nuit, silencieusement.
- Un rapport hebdomadaire `reports/evolve-week-{N}.md` généré par le script, pas par un skill.
- Plus de commande slash. Plus de "mode auto". Plus d'auto-commit.

Bénéfice : l'utilisateur ne voit que `/sentinel-security` (et éventuellement `/sentinel-rag` si on le garde). La surface produit divise par 3.

### P3 — Abandonner la RAG pour la détection
22 règles actives n'ont pas besoin de ChromaDB. Un `dict[str, Rule]` en mémoire fait le job. La RAG coûte :
- ~4088 docs indexés (le reste étant du bruit)
- `sentence-transformers` + `chromadb` en deps Python
- Un venv de ~500 MB
- Un temps d'indexation non négligeable à chaque `deploy.sh`

**Proposition** : garder la RAG pour la KB `/sentinel-rag` (100 docs d'expertise RAG curated — là elle a du sens). Retirer la RAG de `/sentinel-security`. Les agents lisent directement le `rules.json` filtré. Gain : démarrage instant, pas de deps Python lourdes pour la détection.

### P4 — Changer les métriques de succès
Abandonner :
- `exploitation_score` (100 % ornementale)
- "active rules count" (22 aujourd'hui, pourrait devenir 50 demain, sans que ça change la valeur)
- "4088 docs in RAG"

Adopter :
- **Real-project precision** : sur le portefeuille de 7 labs qui mentionnent Sentinel, combien de true positives / false positives par mois ?
- **Time to first real finding** : combien de minutes entre `/sentinel-security` et la première vraie remédiation appliquée ?
- **Rules that caught something** : sur les 22 actives, lesquelles ont déjà identifié un truc dans un de tes projets réels ? (Aujourd'hui probablement 0 à 2 max.)

### P5 — Dogfooding organisé ("Sentinel week")
Un sprint de 3-4 jours dédiés à scanner **tous** les labs actifs (00, 16, 25, 32, 32-newsletter, 32-editorial, 33, 34, 35, 43, 45, 46, 47) et documenter dans chaque lab : "Sentinel a trouvé X, j'ai fixé Y, j'ai ignoré Z (false positives)". Le livrable : un `reports/real-world-2026-04.md` avec les stats par projet. C'est le seul moyen de savoir si le produit marche.

### P6 — Publier un artefact utile pour le monde
Si `sentinel-plugin` reste un objectif moyen-terme, le **préparer en produisant** aujourd'hui un artefact qui existe indépendamment du plugin : une **liste "Top 25 Claude Code skill security rules"** en JSON/Markdown, issue des 22 règles actives + 3 rules LLM-safety curated. Cet artefact peut être :
- Ingéré par d'autres skills (y compris `/security-review`)
- Shared sur GitHub comme single-file reference
- Cité dans des posts de blog

Un artefact autonome = un test de la valeur réelle des règles. S'il n'intéresse personne, les règles sont pauvres.

### P7 — Redéfinir la cadence
- `/sentinel-evolve auto` bi-weekly → overkill pour un projet solo. Claude Code release every ~2 weeks, mais 80 % des releases n'impactent pas Sentinel.
- Passer à : **monthly review** manuelle (30 min toi, lire les release notes, décider si ça vaut une adoption), et seulement quand c'est significatif.
- Cron : garder uniquement le CVE sync (utile pour alimenter `cve-feed/`), abandonner l'auto-commit.

### P8 — Rétrécir le namespace
Le namespace `sentinel-*` promet un écosystème. Trois produits sous le même parapluie, c'est peu défendable quand aucun n'est mature. 
- Option light : renommer `/sentinel-rag` en `/rag-expert` (standalone). C'est une skill distincte, même auteur, même repo, pas besoin du namespace.
- Option radicale : tout fusionner sous `/sentinel` avec sous-commandes (`/sentinel scan`, `/sentinel rag`, `/sentinel evolve`). Un seul entry point, moins de choix pour l'utilisateur.

### P9 — Écrire UN vrai README produit
Actuellement : zéro README à la racine. CLAUDE.md fait office de doc mais s'adresse au LLM, pas à un humain curieux.
Un README.md de 60 lignes max avec :
- Qu'est-ce que c'est, en 2 phrases
- Ce que ça ne fait PAS (c'est plus important)
- Install 3 commandes
- Premier scan : `claude "/sentinel-security"`
- Exemple d'output réel (vrai finding sur un vrai projet, pas sur vulnerable-app)
- Limitations honnêtes
- License

### P10 — Instaurer une "honesty policy" dans les commits et reports
Inscrire dans CLAUDE.md, comme règle :
> Les scores `/sentinel-evolve` ne doivent jamais dépasser 85 % par construction. Les messages de commit `perf(evolve)` doivent contenir au moins un détail factuel vérifiable (ex: "+2 rules, fixed 1 false-positive on X") et non juste "apply EIR-{date}".

C'est une discipline d'écriture, pas un code change. Mais c'est ce qui rend un projet solo sérieux sur la durée.

---

## 4. Plan d'exécution — 6 semaines

Chaque phase a : (1) objectif unique, (2) livrables concrets, (3) critère d'arrêt, (4) effort estimé. Le plan assume l'**Option (a)** du P1 (lab privé premium) car c'est le choix à moindre risque. Si tu choisis (b) ou (c), la phase 3+ change complètement.

### Phase 1 — Honnêteté (semaine 1, ~1 journée totale)
> *Arrêter les mensonges avant tout le reste. Le code ne peut pas être meilleur que ses claims.*

| # | Tâche | Réf audit | Effort | Impact |
|---|-------|----------|--------|--------|
| 1.1 | Rotation du token Telegram + `chmod 600 .claude/settings.local.json` + passage via `$SENTINEL_TG_BOT_TOKEN` | H1 | 15 min | Security |
| 1.2 | `cd mcp-servers/sentinel-scanner && npm audit fix && npm run build` | H2 | 10 min | Security |
| 1.3 | Reproduire `/sentinel-evolve auto` avec logs verbose, identifier pourquoi `EIR-2026-04-*` n'atterrit pas sur disque, corriger le step commit dans `skills/sentinel-evolve/SKILL.md` pour `git add reports/archive/EIR-{date}.{json,md}` explicitement | H4 | 1 h | Trust |
| 1.4 | Patcher `scripts/deploy.sh` : `DRY_RUN=1` par défaut, exclure `archive/EIR-*.json` et `archive/*.sarif.json` du `--delete`, logger les opérations destructives | H3 | 30 min | Trust |
| 1.5 | Dans `scripts/rule-tester.py` et EIR template : remplacer "precision" par "fixture-match-rate". Dans outputs : changer "100%" → "{score}% (fixtures only — not validated on real code)" | C1 | 30 min | Honesty |
| 1.6 | Ajouter borne supérieure 85 % dans `exploitation_score` calculé (dans `skills/sentinel-evolve/SKILL.md` Step 5) + commenter pourquoi | M2 | 15 min | Honesty |
| 1.7 | Mettre à jour CLAUDE.md : passer "14 régles actives" à la vraie valeur, préciser "0 audits réels sur projets externes à ce jour", ajouter section "Limitations connues" | — | 30 min | Honesty |

**Critère d'arrêt** : `git log` récent ne contient plus de "100%", tous les EIR cités existent sur disque, CLAUDE.md reflète la réalité, pas de secret en clair.

### Phase 2 — Dégonfle (semaine 2, ~1,5 journée)
> *Retirer tout ce qui n'apporte pas de valeur démontrée. Moins, mais mieux.*

| # | Tâche | Réf audit | Effort | Impact |
|---|-------|----------|--------|--------|
| 2.1 | Retirer les 5 MCP tools inutilisés dans `mcp-servers/sentinel-scanner/src/index.ts` (scan-project, scan-secrets, query-cve, query-kb, generate-sbom si non utilisé). Supprimer les `src/tools/*.ts` correspondants. Rebuild + retest `claude mcp list` | C3 | 45 min | Surface |
| 2.2 | Purger les 3291 règles CVE vides : déplacer vers `knowledge-base/domains/*/cve-rules.staging.json` (non indexé par RAG). `cve-rules.json` ne garde que `status: active` et `needs-review` | C2 | 45 min | Perf |
| 2.3 | Re-indexer la RAG : `python3 rag/indexer.py`. Vérifier que le nouveau nombre de docs indexés passe de 4088 à ~300 (22 actives + 100 RAG expertise + 87 evolve intel + 94 standards) | C2 | 15 min | Perf |
| 2.4 | `rm -rf sentinel-plugin/` (décision P1 = Option a) | L3 | 1 min | Clarity |
| 2.5 | `git rm reports/archive/vulnerable-app_*` + mettre `reports/archive/vulnerable-app_*` dans `.gitignore` | L5 | 5 min | Clarity |
| 2.6 | `mv tests/vulnerable-app/.env tests/vulnerable-app/.env.example` | L1 | 2 min | Hygiene |
| 2.7 | Réécrire `skills/security/SKILL.md` : cible 250 lignes max, sortir les sections Optional/Plugin/OTEL/HTTP/CI dans `docs/cookbook/*.md` chargées à la demande (via file-links depuis le SKILL.md) | M1 | 2 h | Context cost |
| 2.8 | Même exercice sur `skills/sentinel-evolve/SKILL.md` : cible 250 lignes. Transformer `auto` mode en script externe `scripts/evolve.py` invoqué via Bash, retirer les modes audit/maintain/apply individuels (P2) ou les regrouper | M1 + P2 | 2 h | Clarity |
| 2.9 | Retirer l'auto-commit/auto-push de `/sentinel-evolve auto`. Le cron peut proposer, le dev valide | P7 | 20 min | Safety |

**Critère d'arrêt** : `wc -l skills/*/SKILL.md` < 800 total, `python3 rag/indexer.py` termine en <30s, `/sentinel-security` n'a aucune référence à un tool inactif.

### Phase 3 — Focus (semaine 3, ~1 journée)
> *Définir précisément ce que Sentinel fait et ce qu'il ne fait pas.*

| # | Tâche | Effort | Impact |
|---|-------|--------|--------|
| 3.1 | Écrire un `README.md` racine de 60 lignes max : value prop en 2 phrases, ce que ça ne fait PAS, install 3 commandes, premier scan, 1 exemple d'output réel (TBD semaine 4), limitations. Pas de marketing. | 1 h | Positioning |
| 3.2 | Décider définitivement : garder `/sentinel-rag` en skill séparé ou le sortir du namespace. Recommandation : le renommer `/rag-expert` et le déplacer dans un autre lab (il n'a pas sa place dans lab-30). | 30 min decision + 1 h si move | Clarity |
| 3.3 | Écrire `docs/POSITIONING.md` : table comparative Sentinel vs `/security-review` vs `gitleaks` vs `trivy` vs `osv-scanner` avec 5 dimensions (coverage, precision, speed, offline, customizability). Identifier le cell où Sentinel gagne. Si aucun : revoir le scope. | 1 h | Moat |
| 3.4 | Écrire `docs/ROADMAP-2026.md` : 3 objectifs max pour les 3 prochains mois. Si un objectif demande du travail qu'on ne peut pas s'imaginer livrer en continu, le retirer. | 1 h | Focus |
| 3.5 | Décision explicite dans CLAUDE.md : "Sentinel reste un lab privé en 2026. Pas de packaging public. Toute feature envisagée doit améliorer la qualité des scans sur les 47 labs de Manuel." (ou autre selon P1). | 15 min | Commitment |

**Critère d'arrêt** : un humain qui ouvre le repo pour la première fois comprend en 5 minutes ce que ça fait et pour qui. Toi dans 6 mois, idem.

### Phase 4 — Preuve (semaine 4, ~2 jours)
> *Faire tourner Sentinel sur des vrais projets et documenter ce que ça trouve (ou pas).*

| # | Tâche | Effort | Impact |
|---|-------|--------|--------|
| 4.1 | **Sentinel Week** : scanner les 7 labs actifs qui mentionnent déjà sentinel (lab-00, 16, 25, 32, 32-newsletter, 32-editorial, 33). Noter : true positives, false positives, findings utiles mais hors scope | 1,5 j | Product truth |
| 4.2 | Consolider dans `reports/real-world-2026-04.md` : par lab, combien de findings, combien actionnables, combien ignorés (et pourquoi). Ajouter : "Rules actually useful" (ID des règles qui ont matché quelque chose de réel) | 2 h | Accountability |
| 4.3 | Pour chaque règle qui n'a matché nulle part : décider keep / rewrite / remove. Règle qui ne match rien en 3 mois = candidate à la suppression | 1 h | Quality |
| 4.4 | Si < 5 findings actionables au total sur les 7 labs : c'est le signal que le produit a un problème de fond, pas de forme. Reprendre la réflexion à la Phase 3. | — | Reality check |

**Critère d'arrêt** : `reports/real-world-2026-04.md` existe, contient ≥1 finding par lab scanné (ou un "no findings" documenté), et identifie au moins 3 règles qui ont prouvé leur utilité.

### Phase 5 — Rigueur (semaine 5, ~1,5 journée)
> *Poser les fondations de test pour ne pas régresser après.*

| # | Tâche | Réf audit | Effort | Impact |
|---|-------|----------|--------|--------|
| 5.1 | Créer `tests/test_scripts.py` (pytest) avec ≥5 tests : `parse_llm_output`, `prioritize_rules`, `load_empty_rules`, `load_kev_cve_ids`, `load_reference_rules` | M3 | 2 h | Regression |
| 5.2 | Ajouter `.github/workflows/ci.yml` (si repo GitHub public) ou `.git/hooks/pre-commit` local qui lance `pytest tests/` + `npm run build` + `shellcheck scripts/*.sh` | M3 | 1 h | Regression |
| 5.3 | Intégrer un corpus externe dans `rule-tester.py` : OWASP Benchmark subset ou 3 projets open-source avec CVE connues. Séparer fixture-match-rate de external-precision dans le rapport | C1 | 3 h | Honesty |
| 5.4 | Ajouter rotation logs `~/.sentinel/logs/*.log` via cron ou hook | M4 | 30 min | Ops |
| 5.5 | Créer un `CHANGELOG.md` qui consigne les changements fonctionnels (pas les auto-commits evolve) pour faire émerger le vrai rythme d'évolution | — | 30 min | Accountability |

**Critère d'arrêt** : `pytest tests/ -v` passe green, CI (ou pre-commit) refuse les changements qui cassent.

### Phase 6 — Itération (semaine 6, flottant)
> *Observer ce qui émerge après 4 semaines de discipline, ajuster.*

À cette étape, deux scénarios réalistes :

**Scénario A — Le produit s'est clarifié**
Tu as trouvé entre 5 et 20 findings utiles sur tes labs, tu utilises `/sentinel-security` vraiment avant chaque PR importante, tu as identifié 5-10 règles qui pull their weight. Décision : **investir sur ces règles, enrichir, doubler**. L'objectif devient de passer de 22 à 40 règles actives dont tu es fier.

**Scénario B — Le produit reste utilisé uniquement par toi sur vulnerable-app**
Tu n'as pas trouvé plus de 2-3 vrais findings sur les labs réels. Le feedback-loop continue de tourner à vide. Les vraies alertes viennent de `npm audit` et `/security-review`. Décision : **archiver Sentinel comme expérience de recherche**, garder `/sentinel-rag` (qui a sa valeur propre), publier un article honnête "J'ai construit un security scanner auto-évolutif et ça n'a pas marché — voici pourquoi". C'est aussi une forme de succès.

---

## 5. Trois règles pour la suite

1. **Pas d'ajout sans suppression**. Pour chaque nouvelle feature envisagée, retirer une feature existante équivalente en complexité. Le budget mental est la ressource rare.
2. **Pas de score qui dépasse 85 %**. Tout scoring borné à 85 par construction — les 15 points restants représentent la marge d'incertitude honnête du système.
3. **Pas de commit `perf(evolve)` sans preuve**. Un commit de type `perf(evolve)` doit obligatoirement citer au moins un fait vérifiable : "+3 true positives sur lab-16", "-12 false positives après revue", "pattern X retiré car 0 match en 60 jours". Sinon c'est un commit `chore(evolve)` ou `docs(evolve)`.

---

## 6. Ce que je ne ferais PAS en priorité

Pour lever l'ambiguïté, voici ce qui ne figure pas dans le plan et pourquoi :

- **Publier le plugin** : prématuré. Repousser à Q4 2026 minimum, et seulement si Phase 4 donne des résultats concrets.
- **Ajouter de nouveaux domaines** (ex: "cloud-audit", "docker-audit") : la couverture actuelle n'est pas maîtrisée, pas la peine d'élargir.
- **Intégrer semgrep ou trivy via wrapper** : transformerait Sentinel en méta-orchestrateur, diluerait son identité.
- **Ajouter du fine-tuning / embeddings custom pour la RAG** : over-engineering, 22 règles ne méritent pas ça.
- **Construire un dashboard web** : pas de valeur pour un lab solo.

---

## 7. Synthèse

| Axe | Aujourd'hui | Après plan (6 semaines) |
|-----|-------------|-------------------------|
| **Identité** | 3 skills qui se marchent dessus, ambition floue | 1 skill principal `/sentinel-security`, positionnement explicite vs concurrents |
| **Qualité** | 22 règles dont 0 validée sur code réel | 15-25 règles validées sur ≥7 projets réels, metrics honnêtes |
| **Automation** | Auto-evolve auto-commit auto-push, "100 %" permanent | Cron CVE sync, evolve manuel mensuel, scores bornés à 85 % |
| **Surface** | 7 MCP tools dont 5 morts, SKILL.md 661 lignes, 3391 règles | 2 MCP tools vivants, SKILL.md 250 lignes, 30 règles actives |
| **Preuve** | 0 scan externe réel | `reports/real-world-2026-04.md` avec données par projet |
| **Charge mentale** | Élevée (self-evolving méta-système) | Modérée (scanner + cron) |

Le projet a de la substance — surtout l'architecture multi-agent et le protocole Finding[]. Ce qui le bride n'est pas technique, c'est **un excès d'ambition non calibrée**. 6 semaines disciplinées suffisent à en faire un outil que tu utiliseras vraiment, ou à l'enterrer honorablement.

Le pire choix c'est de continuer exactement comme avant — parce que l'auto-evolve va continuer de tourner et de produire des EIR 100 %, en consommant ton contexte mental sans livrer de progrès réel. Tu l'as sûrement senti : la sensation d'avancer sans avancer.
