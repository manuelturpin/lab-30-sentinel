## Audit terminé — `orders-api` / `vulnerable-test-app`

**18 findings : 7 CRITICAL, 6 HIGH, 4 MEDIUM, 1 LOW.** Projet de 4 fichiers, audité en contexte unique — le fan-out multi-agents du skill n'était pas justifié à cette taille.

Le service n'a pas de faiblesses de sécurité, il n'a pas de sécurité. Les 7 endpoints sont tous atteignables sans authentification.

**Chaîne d'attaque la plus courte — 3 requêtes, aucun outil :**
1. `POST /api/login` avec `{"username":"admin"}` → renvoie un JWT valide et signé. **Aucun mot de passe n'est lu ni vérifié** (`src/server.js:43`) — c'est un contournement d'authentification total, et le finding le plus facile à survoler puisque le code *a la forme* d'un login.
2. `GET /api/users/1` → `SELECT *` non authentifié, renvoie toutes les colonnes de `users` (hash de mots de passe inclus) ; l'injection SQL sur le même paramètre étend la lecture à toute la base.
3. `DELETE /api/admin/users/1 OR 1=1` → vide la table. Le segment `admin` dans le chemin est la seule chose qui marque la route comme privilégiée.

Les autres CRITICAL : SSRF avec renvoi de la réponse au client (`fetch(req.body.url)` → métadonnées cloud, réseau interne), et les secrets — secret JWT, clé d'API, credentials PostgreSQL — codés en dur **et** présents dans le commit `a1da5c0` via `.env` tracké. Les trois sont à faire tourner immédiatement ; `git rm --cached` ne les retire pas de l'historique.

Un HIGH qui sort du lot commun : les 3 handlers `async` sans `try/catch`. Express 4 ne capture pas les rejets, et Node 22 termine le processus sur rejet non géré — `POST /api/fetch-url` avec une `url` invalide **arrête le serveur**. DoS non authentifié en une requête.

### Deux réserves sur la fiabilité du run

- **L'outil MCP `scan-dependencies` a renvoyé `totalDependencies: 0`** sur un projet qui en déclare 4. J'ai écarté le résultat et refait l'analyse à la main. Conséquence : le finding sur `jsonwebtoken` 8.x (CVE-2022-23529/23539/23540/23541) est **non confirmé par OSV**, et aucune CVE transitive n'a pu être évaluée. `generate-sbom` lit correctement les 4 dépendances sur le même chemin — le bug est donc bien dans le parsing de `scan-dependencies`, pas dans le projet. Ça mérite un correctif côté Sentinel.
- Le tri par risque composite `cvss × (0.6 + 0.4 × epss)` prévu par le pipeline n'a pas été appliqué : hors ce finding, aucun ne se rattache à une CVE, donc l'EPSS vaut zéro partout et la formule dégrade uniformément les vulnérabilités de code. J'ai classé au CVSS v4.

J'ai laissé de côté le rapport `claude-security` présent dans l'arborescence, pour que cet audit reste indépendant.

### Artefacts

Écrits dans `~/.sentinel/reports/archive/`, suffixés à l'heure pour ne pas écraser le run du jour déjà présent :

- `vulnerable-test-app_2026-07-29_053912.sarif.json` — SARIF 2.1.0, validé (18 results, 17 rules, aucun `ruleId` orphelin)
- `vulnerable-test-app_2026-07-29_053912.sbom.json` — CycloneDX 1.5, annoté du caveat « pas de lockfile, versions = borne basse des plages `^` »
- `vulnerable-test-app_2026-07-29_053912.md` — rapport détaillé avec remédiations et ordre de correction

Secrets rédigés dans les trois. Ordre de correction recommandé : rotation des secrets → authn/authz → requêtes paramétrées → `/api/fetch-url` → wrapper async.

Le `package.json` se décrit comme « intentionally vulnerable app for Sentinel E2E testing », alors que le `README` décrit un vrai service de commandes. Si c'est bien une cible de test, dis-le moi — ces 18 findings font alors un bon référentiel pour mesurer le recall du pipeline.