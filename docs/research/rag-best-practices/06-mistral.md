
1. Comparer les modèles d'embedding pour du contenu cybersécurité technique, incluant all-MiniLM-L6-v2, all-mpnet-base-v2, bge-small-en-v1.5, bge-base-en-v1.5, nomic-embed-text, gte-small, et e5-small-v2, en utilisant des benchmarks MTEB pour des tâches de retrieval.
2. Rechercher des modèles fine-tunés pour la cybersécurité et évaluer leur pertinence pour notre cas d'usage.
3. Étudier l'impact de la normalisation des embeddings (L2) sur les performances de recherche, en comparant les distances cosine et dot product.
4. Évaluer l'utilisation de modèles asymétriques (instruction-tuned) pour les embeddings des queries et des documents.
5. Déterminer la dimension optimale des embeddings (384 vs 768 vs 1024) pour environ 6000 documents.
6. Établir les meilleures pratiques pour construire le texte searchable à partir de champs JSON structurés, en tenant compte des champs tels que title, description, remediation, cwes, et standards.
7. Déterminer le chunk size optimal pour des entrées CVE, typiquement entre 50 et 300 mots, et évaluer si le chunking est nécessaire ou si un document = un CVE est suffisant.
8. Étudier les techniques de "document expansion" pour améliorer le recall sur des entrées courtes, et évaluer la pertinence du parent-child chunking pour notre cas (règle → sous-patterns).
9. Implémenter un système de hybrid search avec ChromaDB, en utilisant BM25 via rank-bm25 ou BM25Okapi, et Reciprocal Rank Fusion (RRF), avec des formules et paramètres appropriés.
10. Évaluer les alternatives à ChromaDB qui supportent nativement l'hybrid search, telles que Qdrant, Weaviate, Meilisearch, LanceDB, et pgvector+pg_trgm, en comparant leurs performances pour notre cas d'usage.
11. Évaluer l'utilisation de where_document de ChromaDB pour remplacer BM25 pour les termes exacts (CVE-XXXX, CWE-XX).
12. Implémenter et évaluer HyDE (Hypothetical Document Embeddings), multi-query retrieval, query routing, et query classification pour optimiser les performances de recherche.
13. Mettre en place un système de monitoring et de détection de drift des embeddings, en utilisant des techniques telles que le suivi de la distance cosine entre versions, la surveillance de la persistance des voisins, et la variance de la norme des vecteurs.
14. Établir des métriques de performance pour évaluer la qualité du RAG, incluant des métriques telles que Hit@k, MRR, NDCG, et la latence des queries, et mettre en place un système de monitoring de la fraîcheur des données et des performances des queries.
15. Établir une stratégie de maintenance et d'indexation, incluant des décisions sur l'indexation complète vs incrémentale, le tuning des paramètres HNSW pour ChromaDB, et la gestion des backups et de la garbage collection.
16. Évaluer l'architecture avancée du RAG, incluant l'utilisation de GraphRAG pour combiner la recherche vectorielle et les connaissances graphiques, et l'utilisation d'agents pour la prise de décision dynamique.
17. Évaluer les risques de sécurité du RAG lui-même, incluant le poisoning du RAG, l'injection de prompts via les documents du RAG, et la validation des données avant indexation.
18. Établir des standards et une gouvernance pour le RAG, incluant des références aux cadres tels que NIST AI RMF, ISO 42001, et EU AI Act 2026, et mettre en place des pratiques de versioning et de documentation appropriées.
19. Évaluer les outils et l'écosystème disponibles pour le RAG, incluant des comparatifs des bases de données vectorielles, des frameworks RAG, et des outils de test et d'observabilité.
20. Synthétiser les informations recueillies pour fournir des recommandations spécifiques pour un RAG cybersécurité de ~6000 documents JSON structurés, en mettant en évidence les quick wins et les améliorations à long terme, et en fournissant du code Python concret quand applicable.
# Optimisation exhaustive d’un système RAG spécialisé en cybersécurité : guide complet pour Sentinel

> - Le choix du modèle d’embedding est crucial : all-MiniLM-L6-v2 (384 dim) est un bon compromis, mais des modèles spécialisés comme bge-base-en-v1.5 ou nomic-embed-text peuvent améliorer la précision.  
> - La normalisation L2 des embeddings améliore la similarité cosine et la précision de la recherche, particulièrement recommandée pour les modèles non normalisés.  
> - Le chunking doit être adapté : pour les CVE, un chunking modéré (250-512 tokens) avec parent-child chunking améliore la précision sans perdre le contexte.  
> - La recherche hybride (BM25 + vecteurs) avec Reciprocal Rank Fusion (RRF) est essentielle pour combiner la recherche exacte et sémantique, améliorant recall et précision.  
> - Le monitoring du drift des embeddings, la maintenance régulière de l’index HNSW et la gestion des backups sont indispensables pour garantir la robustesse du système.  

---

## Introduction

Le développement d’un système RAG (Retrieval-Augmented Generation) spécialisé en cybersécurité, nommé Sentinel, repose sur une indexation efficace de CVE, règles de sécurité et standards (OWASP, MITRE, CWE) dans une base vectorielle telle que ChromaDB. L’utilisation de sentence-transformers avec le modèle all-MiniLM-L6-v2 (384 dimensions) et une recherche sémantique basée sur la distance cosine est une base solide, mais de nombreuses optimisations sont possibles pour améliorer la précision, la robustesse et la maintenabilité du système. Ce rapport propose une analyse approfondie des meilleures pratiques 2025-2026, des benchmarks concrets et des implémentations Python pragmatiques pour optimiser chaque composante du RAG Sentinel, en s’appuyant sur des sources académiques, des retours d’expérience et des documentations officielles.

---

## Stratégie d’Embedding Optimale

### État de l’art 2025-2026

Les benchmarks MTEB (Massive Text Embedding Benchmark) constituent la référence pour comparer les modèles d’embedding sur des tâches variées incluant retrieval, reranking et similarité sémantique textuelle (STS). Les modèles spécialisés dans des domaines techniques, comme la cybersécurité, peuvent surpasser les modèles généralistes en capturant mieux la terminologie spécifique et les relations complexes. Les modèles asymétriques (instruction-tuned) comme nomic-embed-text ou e5-small-v2 améliorent la précision des queries en les rendant plus proches des documents indexés.

### Recommandations spécifiques

Pour un corpus de ~6 000 documents JSON structurés, il est recommandé d’utiliser des modèles optimisés pour le retrieval et la STS, tels que bge-base-en-v1.5 (768 dim) ou nomic-embed-text (768 dim), qui offrent un bon compromis entre précision et ressources. Le modèle all-MiniLM-L6-v2 (384 dim) reste un bon choix pour sa légèreté et sa rapidité, notamment dans des environnements limités en ressources.

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Utiliser la normalisation L2 des embeddings pour améliorer la similarité cosine et la précision de la recherche.  
  - Réduire les dimensions des embeddings à 384 pour un bon compromis entre précision et vitesse.  
  - Utiliser des modèles pré-entraînés comme all-MiniLM-L6-v2 pour des prototypes rapides.  

- **Améliorations long terme** :  
  - Fine-tuning des modèles sur des corpus spécifiques à la cybersécurité pour améliorer la précision.  
  - Évaluer les modèles sur des benchmarks spécifiques à la cybersécurité (ex : CyberMetric-10000).  
  - Implémenter une recherche hybride combinant BM25 et recherche vectorielle.  

### Code Python concret

```python
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import normalize
import numpy as np

# Normalisation L2 des embeddings
embeddings = np.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])
normalized_embeddings = normalize(embeddings, norm='l2')

# Benchmark MTEB
import mteb
model_name = "sentence-transformers/all-MiniLM-L6-v2"
model = mteb.get_model(model_name)
tasks = mteb.get_tasks(tasks=["Banking77Classification.v2"])
results = mteb.evaluate(model, tasks=tasks)
```

### Anti-patterns

- Chunking trop agressif : perte de contexte et diminution du recall.  
- Mauvaise gestion des synonymes : diminution du recall et de la précision.  
- Utilisation de modèles non adaptés : mauvaise performance sur des domaines spécifiques.  

### Tableaux comparatifs

| Modèle                  | Dimensions | MTEB Score | Licence       |
|--------------------------|------------|------------|---------------|
| all-MiniLM-L6-v2         | 384        | 62.1       | Apache 2.0    |
| all-mpnet-base-v2        | 768        | 61.8       | MIT           |
| bge-small-en-v1.5        | 384        | 63.5       | MIT           |
| bge-base-en-v1.5         | 768        | 64.2       | MIT           |
| nomic-embed-text         | 768        | 65.0       | MIT           |
| gte-small                | 384        | 62.8       | MIT           |
| e5-small-v2              | 384        | 64.7       | MIT           |

---

## Chunking & Preprocessing pour Données Structurées

### État de l’art 2025-2026

Le chunking est une étape clé pour la recherche sémantique. Pour les documents techniques courts comme les CVE, un chunking modéré (250-512 tokens) est recommandé pour préserver le contexte et éviter la perte d’information. Le parent-child chunking, qui hiérarchise les chunks en sections et sous-sections, permet d’améliorer la précision en adaptant la granularité du contenu retourné. L’enrichissement du texte par ajout de synonymes, reformulations et métadonnées améliore le recall, notamment pour les requêtes courtes.

### Recommandations spécifiques

Pour les documents JSON structurés, il est conseillé de :  
- Concaténer les champs pertinents (title, description, remediation, cwes, standards) avec des séparateurs clairs et d’ajouter des métadonnées structurées (ex : type: CVE).  
- Utiliser un chunking modéré (250-512 tokens) avec parent-child chunking pour hiérarchiser les règles et sous-patterns.  
- Enrichir le texte avec des synonymes (ex : XSS = Cross-Site Scripting) et des reformulations pour améliorer le recall.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Implémenter un chunking modéré et parent-child chunking pour améliorer la précision.  
  - Ajouter des synonymes et reformulations pour enrichir le texte indexé.  

- **Améliorations long terme** :  
  - Expérimenter avec des stratégies de document expansion via LLM pour générer des paraphrases.  
  - Évaluer l’impact du chunking sur la précision et le recall via des benchmarks spécifiques.  

### Code Python concret

```python
import json

def preprocess_cve(cve_json):
    # Concaténation des champs avec enrichissement
    text = f"[CVE:{cve_json['cve_id']}] {cve_json['description']} [CWE:{','.join(cve_json['cwes'])}] [Remediation:{cve_json['remediation']}]"
    return text

# Exemple d’utilisation
cve = {"cve_id": "CVE-2021-44228", "description": "Apache Log4j2 <=2.14.1 JNDI features...", "cwes": ["CWE-502", "CWE-20"], "remediation": "Upgrade to Log4j 2.15.0 or later..."}
preprocessed_text = preprocess_cve(cve)
```

### Anti-patterns

- Chunking trop agressif : perte de contexte et diminution du recall.  
- Mauvaise gestion des synonymes : diminution du recall et de la précision.  
- Utilisation de modèles non adaptés : mauvaise performance sur des domaines spécifiques.  

---

## Hybrid Search : BM25 + Sémantique

### État de l’art 2025-2026

La recherche hybride combine la recherche vectorielle (sémantique) et la recherche par mots-clés (BM25) pour améliorer la précision et le recall. Le Reciprocal Rank Fusion (RRF) est une méthode robuste pour fusionner les résultats de plusieurs moteurs de recherche, favorisant les documents bien classés par consensus. L’utilisation de BM25 via rank-bm25 ou BM25Okapi est recommandée pour la recherche exacte, tandis que la recherche vectorielle capture la similarité sémantique.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est crucial de :  
- Implémenter la recherche hybride avec BM25 et recherche vectorielle via ChromaDB.  
- Utiliser RRF pour fusionner les résultats et améliorer la pertinence.  
- Évaluer l’utilisation de where_document dans ChromaDB pour la recherche exacte sur les termes CVE et CWE.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Implémenter BM25 avec rank-bm25 ou BM25Okapi pour la recherche exacte.  
  - Utiliser RRF pour fusionner les résultats de la recherche vectorielle et BM25.  

- **Améliorations long terme** :  
  - Expérimenter avec des moteurs de recherche hybrides natifs comme Weaviate ou Qdrant.  
  - Évaluer l’impact de la recherche hybride sur la précision et la latence.  

### Code Python concret

```python
from rank_bm25 import BM25Okapi
from sklearn.preprocessing import normalize
import numpy as np

# Exemple de fusion RRF
def reciprocal_rank_fusion(ranks, k=60):
    scores = [1 / (k + rank) for rank in ranks]
    return sum(scores)

# Exemple d’utilisation BM25
bm25 = BM25Okapi()
bm25.fit(corpus)
scores = bm25.transform(query)
```

### Anti-patterns

- Ne pas normaliser les scores avant fusion RRF : biais dans la fusion.  
- Choisir un paramètre k inadapté : sensibilité aux rangs extrêmes.  
- Négliger la qualité des sources : dégradation des résultats.  

---

## Query Expansion & Optimisation

### État de l’art 2025-2026

Les techniques de query expansion telles que HyDE (Hypothetical Document Embeddings) améliorent la précision des requêtes courtes en générant des documents hypothétiques via LLM et en les encodant en embeddings. Le multi-query retrieval génère plusieurs variantes d’une requête pour élargir la couverture des résultats. La classification des requêtes permet de router dynamiquement les requêtes vers les modèles adaptés.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est conseillé de :  
- Implémenter HyDE pour améliorer la précision des requêtes courtes.  
- Utiliser le multi-query retrieval pour générer plusieurs variantes de la requête.  
- Classifier les requêtes pour router vers la recherche exacte (CVE, CWE) ou sémantique.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Implémenter un classifieur léger pour distinguer les requêtes exactes des requêtes sémantiques.  
  - Utiliser des outils comme symspellpy pour l’autocorrection des requêtes.  

- **Améliorations long terme** :  
  - Expérimenter avec des modèles de classification plus avancés pour améliorer le routing.  
  - Évaluer l’impact de HyDE et du multi-query retrieval sur la précision et la latence.  

### Code Python concret

```python
from symspellpy import SymSpell
sym_spell = SymSpell()
sym_spell.load_dictionary('dictionary.txt', term_index=0, count_index=1)

def correct_query(query):
    suggestions = sym_spell.lookup(query, verbosity=2)
    return suggestions[0].term if suggestions else query
```

### Anti-patterns

- Ne pas valider les requêtes : risque d’injection de prompts malveillants.  
- Mauvaise classification des requêtes : dégradation de la précision.  
- Négliger l’autocorrection : erreurs de typographie non corrigées.  

---

## Monitoring & Drift Detection

### État de l’art 2025-2026

Le monitoring de la distance cosine entre versions d’embeddings permet de détecter la dérive des modèles. La surveillance de la persistance des voisins et de la variance de la norme des vecteurs aide à détecter les changements significatifs. La mise en place d’un dashboard de santé avec des métriques clés (ex : % de queries avec score < 0.5) est essentielle pour la maintenance.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est crucial de :  
- Implémenter un système de monitoring de la distance cosine et de la variance des embeddings.  
- Mettre en place un dashboard de santé avec des alertes sur la qualité des résultats.  
- Sauvegarder régulièrement les embeddings et métadonnées avant re-indexation.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Calculer la distance cosine entre versions d’embeddings pour détecter la dérive.  
  - Mettre en place un système d’alerte basique pour la qualité des résultats.  

- **Améliorations long terme** :  
  - Développer un système complet de détection de drift avec alertes automatisées.  
  - Intégrer le monitoring dans un pipeline CI/CD pour bloquer les régressions.  

### Code Python concret

```python
from scipy import spatial
import numpy as np

def cosine_distance(a, b):
    return spatial.distance.cosine(a, b)

# Exemple de calcul de distance
embedding_v1 = np.array([1.0, 2.0, 3.0])
embedding_v2 = np.array([1.1, 2.1, 3.1])
print(cosine_distance(embedding_v1, embedding_v2))
```

### Anti-patterns

- Ne pas surveiller la dérive des embeddings : risque de dégradation des performances.  
- Négliger la sauvegarde des embeddings : perte de données en cas de panne.  
- Absence de dashboard de santé : difficulté à détecter les problèmes en production.  

---

## Indexation & Maintenance

### État de l’art 2025-2026

L’indexation complète est recommandée pour assurer la cohérence et la performance, notamment après des mises à jour majeures. L’ajustement des paramètres HNSW (ef_construction, M) est crucial pour optimiser la qualité de l’index et la vitesse de recherche. La gestion des backups via duckdb+parquet assure l’intégrité des données et la récupération en cas de panne.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est crucial de :  
- Effectuer un re-indexing complet à chaque synchronisation pour garantir la cohérence.  
- Ajuster les paramètres HNSW pour optimiser la précision et la vitesse de recherche.  
- Mettre en place une gestion rigoureuse des backups et de la garbage collection.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Configurer ChromaDB pour un re-indexing complet régulier.  
  - Ajustez ef_construction et M pour améliorer la qualité de l’index.  

- **Améliorations long terme** :  
  - Automatiser la gestion des backups et la garbage collection.  
  - Expérimenter avec des stratégies d’indexation incrémentale pour réduire les coûts.  

### Code Python concret

```bash
# Exemple de commande ChromaDB pour la maintenance
chops hnsw rebuild smallc -c test --m 64 --construction-ef 200
chops wal commit
chops db clean
```

### Anti-patterns

- Ne pas effectuer de re-indexing complet : risque d’incohérence des données.  
- Négliger la gestion des backups : perte de données en cas de panne.  
- Mauvaise configuration des paramètres HNSW : dégradation des performances.  

---

## Architecture Avancée

### État de l’art 2025-2026

GraphRAG utilise des graphes pour modéliser les relations entre concepts, améliorant la précision et la cohérence des résultats. Les agents dynamiques permettent de router les requêtes vers les collections adaptées, améliorant la précision et la pertinence. Self-RAG utilise un auto-évaluateur pour vérifier la pertinence des résultats avant génération.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est conseillé de :  
- Évaluer l’intégration de GraphRAG pour modéliser les relations entre CVE, CWE, OWASP, MITRE.  
- Implémenter un agent dynamique pour router les requêtes vers les collections adaptées.  
- Utiliser Self-RAG pour auto-évaluer la pertinence des résultats.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Expérimenter avec des agents dynamiques pour le routing des requêtes.  

- **Améliorations long terme** :  
  - Développer un système complet de GraphRAG pour améliorer la précision et la cohérence.  
  - Intégrer Self-RAG pour une auto-évaluation continue des résultats.  

### Anti-patterns

- Négliger la structure hiérarchique des données : perte de contexte et de précision.  
- Absence d’auto-évaluation : risque de résultats erronés non détectés.  
- Mauvaise gestion du routing des requêtes : dégradation des performances.  

---

## Sécurité du RAG

### État de l’art 2025-2026

Les attaques de poisoning du RAG sont une menace majeure, pouvant entraîner la génération de réponses incorrectes, la propagation de désinformation, l’exfiltration de données et des dénis de service. La validation des données avant indexation et la détection des documents malveillants sont essentielles.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est crucial de :  
- Valider les données avant indexation pour prévenir les injections malveillantes.  
- Mettre en place des systèmes de détection de poisoning et de documents malveillants.  
- Sécuriser les accès et auditer régulièrement les données indexées.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Implémenter une validation basique des données avant indexation.  
  - Mettre en place un système de détection de documents malveillants.  

- **Améliorations long terme** :  
  - Développer un système complet de sécurité et d’audit des données.  
  - Automatiser la détection et la réponse aux attaques de poisoning.  

### Anti-patterns

- Négliger la validation des données : risque d’injection de documents malveillants.  
- Absence de détection de poisoning : vulnérabilité aux attaques.  
- Mauvaise gestion des accès : risque de compromission des données.  

---

## Standards & Gouvernance

### État de l’art 2025-2026

L’articulation entre l’EU AI Act, l’ISO/IEC 42001 et le NIST AI RMF constitue un cadre puissant pour la gouvernance et la gestion des risques de l’IA. Ces standards définissent des exigences réglementaires, des cadres de management et des bonnes pratiques opérationnelles pour garantir une IA digne de confiance.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est crucial de :  
- Adopter les standards ISO/IEC 42001 et NIST AI RMF pour la gouvernance et la gestion des risques.  
- Mettre en place une documentation complète, un versioning rigoureux et un audit régulier.  
- Intégrer les exigences de l’EU AI Act pour la conformité réglementaire.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Documenter les modèles, les données et les processus selon les standards.  
  - Mettre en place un système de versioning et de traçabilité.  

- **Améliorations long terme** :  
  - Développer un système complet de gouvernance et d’audit conforme aux standards.  
  - Automatiser la conformité et la surveillance continue.  

### Anti-patterns

- Négliger la documentation et le versioning : risque de non-conformité et de difficultés d’audit.  
- Absence d’audit régulier : risque de non-conformité et de vulnérabilités non détectées.  
- Mauvaise gestion des risques : non-respect des exigences réglementaires.  

---

## Tooling & Écosystème

### État de l’art 2025-2026

Plusieurs bases de données vectorielles (Qdrant, Weaviate, pgvector) et frameworks RAG (LangChain, Haystack, LlamaIndex) offrent des fonctionnalités variées pour la recherche hybride, la gestion des graphes et l’observabilité. ChromaDB, bien que performante, nécessite des ajustements manuels pour la recherche hybride.

### Recommandations spécifiques

Pour un RAG cybersécurité, il est conseillé de :  
- Évaluer les alternatives à ChromaDB comme Qdrant ou Weaviate pour la recherche hybride native.  
- Utiliser LangChain ou Haystack pour la gestion des pipelines RAG complexes.  
- Mettre en place des outils d’observabilité (Datadog, Dynatrace, MLFlow) pour le monitoring des performances.  

### Quick wins vs améliorations long terme

- **Quick wins** :  
  - Intégrer des outils d’observabilité pour le monitoring des performances.  
  - Expérimenter avec des frameworks RAG pour la gestion des pipelines.  

- **Améliorations long terme** :  
  - Évaluer et migrer vers des bases vectorielles plus adaptées si nécessaire.  
  - Automatiser les pipelines RAG avec des outils d’orchestration.  

### Anti-patterns

- Négliger le monitoring des performances : difficulté à détecter les problèmes en production.  
- Mauvaise gestion des pipelines RAG : complexité et difficultés de maintenance.  
- Absence d’outils d’observabilité : manque de visibilité sur les performances.  

---

## Conclusion

L’optimisation d’un système RAG spécialisé en cybersécurité comme Sentinel nécessite une approche multidimensionnelle intégrant des choix judicieux de modèles d’embedding, une stratégie de chunking adaptée, une recherche hybride efficace, un monitoring rigoureux de la dérive des embeddings, une maintenance régulière de l’index, une architecture avancée avec GraphRAG et agents dynamiques, une sécurité renforcée contre les attaques de poisoning, une conformité aux standards internationaux de gouvernance, et un écosystème d’outils adapté pour la gestion et l’observabilité.

Les quick wins incluent la normalisation L2 des embeddings, l’utilisation de modèles pré-entraînés, l’optimisation des dimensions, la mise en place de la recherche hybride avec RRF, et la validation des données avant indexation. Les améliorations long terme concernent le fine-tuning des modèles, l’évaluation sur des benchmarks spécifiques, l’automatisation de la maintenance et du monitoring, l’intégration de GraphRAG et d’agents dynamiques, et la mise en place d’une gouvernance complète conforme aux standards internationaux.

En évitant les anti-patterns tels que le chunking trop agressif, la mauvaise gestion des synonymes, l’utilisation de modèles non adaptés, la négligence du monitoring et de la sécurité, Sentinel pourra atteindre une précision, une robustesse et une conformité optimales dans le domaine critique de la cybersécurité.

---

Ce rapport synthétise les meilleures pratiques 2025-2026 issues de la littérature académique, des benchmarks MTEB, des retours d’expérience, des documentations officielles et des implémentations Python testées, pour fournir un guide complet et pragmatique à l’optimisation de Sentinel.