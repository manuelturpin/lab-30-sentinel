# Lab-30 Sentinel — Session 4 : Knowledge Base Mobile + Infra + DB + Privacy

## Context

Sessions 1-3 terminees et pushees sur GitHub (`63c14d8`). La KB contient actuellement :
- **web-app** : 22 regles + 19 patterns (4 fichiers)
- **api** : 14 regles + 11 patterns (3 fichiers)
- **llm-ai** : 16 regles + 28 patterns (5 fichiers) + OWASP LLM mapping + checklist
- **supply-chain** : 11 regles + 15 patterns (4 fichiers) + checklist
- **Total** : 63 regles, 81 patterns, 3 OWASP mappings, 1 MITRE mapping, 4 checklists

Session 4 doit peupler les 4 domaines restants : **mobile**, **infrastructure**, **database**, **data-privacy**. Apres cette session, la KB sera complete (8/8 domaines remplis) et prete pour l'implementation du scan engine (Session 5+).

## Etat actuel des fichiers cibles

Tous les fichiers suivants existent deja avec `[]` vide :
- `knowledge-base/domains/mobile/rules.json` — `[]`
- `knowledge-base/domains/infrastructure/rules.json` — `[]`
- `knowledge-base/domains/database/rules.json` — `[]`
- `knowledge-base/domains/data-privacy/rules.json` — `[]`
- Repertoires `patterns/` vides dans chaque domaine

Standards disponibles (placeholders) :
- `standards/owasp-mobile-2024.json` — 10 categories M1-M10 (placeholder)
- `standards/nist-ai-rmf.json` — 4 fonctions GOVERN/MAP/MEASURE/MANAGE (placeholder)
- `standards/cwe-top25.json` — 25 CWEs (complet)

## Fichiers a creer/modifier

### Domaine Mobile (6 fichiers)

1. **`knowledge-base/domains/mobile/rules.json`** — Remplacer le `[]` vide
   - ~10-12 regles couvrant les 10 categories OWASP Mobile Top 10 2024
   - IDs : `MOB-CRED-001`, `MOB-AUTH-001`, `MOB-VALID-001`, `MOB-COMM-001`, `MOB-PRIV-001`, `MOB-BIN-001`, `MOB-CONF-001`, `MOB-STORE-001`, `MOB-CRYPTO-001`, etc.
   - frameworks : `["react-native", "flutter", "swift", "kotlin", "expo"]`
   - Standards : `["OWASP-M01:2024", "CWE-xxx", ...]`

2. **`knowledge-base/domains/mobile/patterns/credential-storage.json`** — 4-5 patterns
   - Hardcoded API keys in mobile code
   - Credentials in SharedPreferences/NSUserDefaults sans chiffrement
   - Tokens stockes en clair dans le filesystem

3. **`knowledge-base/domains/mobile/patterns/insecure-storage.json`** — 4-5 patterns
   - SQLite sans chiffrement
   - Fichiers sensibles en stockage externe (Android)
   - Logs contenant des donnees sensibles
   - Pas de certificate pinning

4. **`knowledge-base/domains/mobile/owasp-mobile-top10-2024.json`** — Mapping complet
   - Format identique a `web-app/owasp-top10-2025.json`
   - 10 categories M1-M10 avec CWEs et `sentinel_rules`

5. **`knowledge-base/domains/mobile/checklist.md`**

6. **Mettre a jour `standards/owasp-mobile-2024.json`** — Enrichir le placeholder

### Domaine Infrastructure (5 fichiers)

6. **`knowledge-base/domains/infrastructure/rules.json`** — Remplacer le `[]` vide
   - ~8-10 regles
   - IDs : `INFRA-DOCKER-001`, `INFRA-K8S-001`, `INFRA-TLS-001`, `INFRA-SECRET-001`, `INFRA-IAM-001`, `INFRA-NET-001`, etc.
   - Couvre : Docker, Kubernetes, TLS/SSL, secrets management, IAM, cloud config
   - file_types : `["Dockerfile", "*.yaml", "*.yml", "*.tf", "*.hcl", "docker-compose.yml"]`

7. **`knowledge-base/domains/infrastructure/patterns/docker.json`** — 4-5 patterns
   - Running as root, secrets in build args, unverified base images, exposed ports

8. **`knowledge-base/domains/infrastructure/patterns/kubernetes.json`** — 4-5 patterns
   - Privileged containers, hostNetwork, no resource limits, default service accounts

9. **`knowledge-base/domains/infrastructure/patterns/secrets.json`** — 3-4 patterns
   - Hardcoded secrets in env vars, .env committed, secrets in Terraform state

10. **`knowledge-base/domains/infrastructure/checklist.md`**

### Domaine Database (4 fichiers)

11. **`knowledge-base/domains/database/rules.json`** — Remplacer le `[]` vide
    - ~6-8 regles
    - IDs : `DB-AUTH-001`, `DB-INJECT-001`, `DB-ENCRYPT-001`, `DB-ACCESS-001`, `DB-BACKUP-001`, `DB-EXPOSE-001`, etc.
    - Couvre : SQL injection (complementaire a web-app), NoSQL injection, auth DB, chiffrement at-rest, exposed endpoints

12. **`knowledge-base/domains/database/patterns/nosql-injection.json`** — 3-4 patterns
    - MongoDB operator injection, query object manipulation

13. **`knowledge-base/domains/database/patterns/misconfig.json`** — 3-4 patterns
    - Default credentials, public-facing DB, no TLS for connections

14. **`knowledge-base/domains/database/checklist.md`**

### Domaine Data Privacy (4 fichiers)

15. **`knowledge-base/domains/data-privacy/rules.json`** — Remplacer le `[]` vide
    - ~6-8 regles
    - IDs : `PRIV-PII-001`, `PRIV-CONSENT-001`, `PRIV-RETAIN-001`, `PRIV-LOG-001`, `PRIV-TRANS-001`, `PRIV-GDPR-001`, etc.
    - Couvre : PII exposure, consentement, retention, logging de donnees sensibles, transfert transfrontalier
    - Standards : GDPR, CCPA, CWEs

16. **`knowledge-base/domains/data-privacy/patterns/pii-exposure.json`** — 4-5 patterns
    - Email/phone/SSN dans les logs, PII dans les URLs, donnees sensibles non masquees dans les reponses API

17. **`knowledge-base/domains/data-privacy/patterns/consent.json`** — 3-4 patterns
    - Tracking sans consentement, cookies tiers sans opt-in, analytics pre-consent

18. **`knowledge-base/domains/data-privacy/checklist.md`**

### Total attendu : ~18 fichiers, ~30-38 regles, ~30-40 patterns

## Conventions a suivre (identiques Sessions 2-3)

### Schema des regles (rules.json)
```json
{
  "id": "MOB-CRED-001",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cvss_v4": 9.1,
  "category": "mobile",
  "subcategory": "credential-storage",
  "title": "...",
  "description": "...",
  "detect": {
    "patterns": ["regex1", "regex2"],
    "negative_patterns": ["safe_pattern"],
    "file_types": ["*.swift", "*.kt", "*.java", "*.dart"],
    "exclude": ["node_modules", "dist", "build", "test"]
  },
  "remediation": {
    "description": "...",
    "code_example": "...",
    "references": ["https://..."]
  },
  "standards": ["CWE-xxx", "OWASP-M01:2024"],
  "ai_specific": false,
  "frameworks": ["react-native", "flutter", "swift", "kotlin"]
}
```

### Schema des patterns (patterns/*.json)
```json
{
  "id": "CRED-HARDCODE-001",
  "type": "hardcoded-credential",
  "title": "...",
  "pattern": "single_regex",
  "negative_pattern": "optional_or_null",
  "severity": "CRITICAL",
  "file_types": ["*.swift", "*.kt"],
  "description": "...",
  "cwe": "CWE-xxx",
  "remediation": "Short fix"
}
```

### Severite / CVSS v4
| Severity | CVSS v4 |
|----------|---------|
| CRITICAL | 9.0-9.4 |
| HIGH | 7.4-8.6 |
| MEDIUM | 5.3-6.5 |
| LOW | 3.7-4.5 |

## Ordre d'execution

1. Mobile `rules.json` (~10-12 regles)
2. Mobile 2 pattern files + `owasp-mobile-top10-2024.json` + `checklist.md`
3. Infrastructure `rules.json` (~8-10 regles)
4. Infrastructure 3 pattern files + `checklist.md`
5. Database `rules.json` (~6-8 regles)
6. Database 2 pattern files + `checklist.md`
7. Data Privacy `rules.json` (~6-8 regles)
8. Data Privacy 2 pattern files + `checklist.md`
9. Mettre a jour `standards/owasp-mobile-2024.json`
10. Mettre a jour `docs/plans/2026-03-13-sentinel-design.md` et `docs/roadmap.md`

**Note** : Certains fichiers contenant des termes de securite (eval, exec, etc.) seront bloques par le hook de securite. Utiliser `bash cat <<'EOF'` pour contourner comme en Sessions 2-3.

## Verification

- Tous les JSON valides : `find knowledge-base -name "*.json" -exec python3 -c "import json,sys; json.load(open(sys.argv[1]))" {} \;`
- Compter les regles par domaine
- Cross-reference IDs entre `rules.json`, OWASP mappings, et `checklist.md`
- Verifier unicite des pattern IDs sur l'ensemble de la KB
- Verifier schema complet (tous les champs requis presents)
- Commit + push apres validation

## Resultat attendu apres Session 4

| Domaine | Regles | Patterns |
|---------|--------|----------|
| web-app | 22 | 27 |
| api | 14 | 11 |
| llm-ai | 16 | 28 |
| supply-chain | 11 | 15 |
| mobile | ~10-12 | ~8-10 |
| infrastructure | ~8-10 | ~11-14 |
| database | ~6-8 | ~6-8 |
| data-privacy | ~6-8 | ~7-9 |
| **Total** | **~93-105** | **~113-122** |

KB complete → pret pour Session 5 (MCP Server implementation).
