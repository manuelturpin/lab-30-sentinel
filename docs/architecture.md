# Sentinel Architecture

## Data Flow

```
User runs /security
      |
      v
  Skill Orchestrator (SKILL.md)
      |
      +-- Stack Detector (analyzes project files)
      |
      +-- Agent Dispatch (parallel, based on detected stack)
      |     |
      |     +-- web-audit.md
      |     +-- api-audit.md
      |     +-- llm-ai-audit.md
      |     +-- ... (12 total)
      |
      +-- KB Lookup (rules.json per domain)
      |
      +-- Result Aggregation
      |     |
      |     +-- SARIF Generation
      |     +-- CVSS v4 + EPSS Scoring
      |     +-- CycloneDX SBOM
      |
      v
  Report Output (Markdown + SARIF + SBOM)
```

## Component Responsibilities

| Component | Input | Output |
|-----------|-------|--------|
| Stack Detector | Project files | Stack list + agent list |
| Agent | Project path + KB rules | Findings JSON |
| SARIF Generator | Findings array | SARIF 2.1.0 JSON |
| Risk Scorer | CVSS + EPSS | Composite score |
| SBOM Generator | Dependencies | CycloneDX JSON |
| RAG/ChromaDB | Natural language query | Relevant KB rules |
