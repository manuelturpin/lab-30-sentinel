# LLM/AI Security Checklist — Sentinel

Based on OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS.

## LLM01 — Prompt Injection

- [ ] **LLM-PROMPT-001** | CRITICAL | No direct string concatenation of user input into prompts — use structured message roles
- [ ] **LLM-PROMPT-002** | CRITICAL | RAG-retrieved content is sanitized before insertion into LLM context

## LLM02 — Sensitive Information Disclosure

- [ ] **LLM-INFO-001** | HIGH | No API keys, PII, or credentials in system prompts or few-shot examples — use PII redaction

## LLM03 — Supply Chain Vulnerabilities

- [ ] **LLM-SUPPLY-001** | HIGH | Pre-trained models pinned to revision hashes with trust_remote_code=False
- [ ] **LLM-MCP-001** | CRITICAL | MCP servers verified and audited before connection — tool descriptions reviewed
- [ ] **LLM-MCP-002** | HIGH | CLAUDE.md/SKILL.md files audited for hidden override instructions in dependencies

## LLM04 — Data and Model Poisoning

- [ ] **LLM-POISON-001** | HIGH | Training and fine-tuning data validated with checksums and provenance checks

## LLM05 — Improper Output Handling

- [ ] **LLM-OUTPUT-001** | HIGH | LLM output sanitized before rendering in HTML or executing as code
- [ ] **LLM-OUTPUT-002** | HIGH | LLM-generated code executed only in sandboxed environments with human review

## LLM06 — Excessive Agency

- [ ] **LLM-AGENCY-001** | CRITICAL | AI agents use allowlisted tools only — no unrestricted shell or filesystem access
- [ ] **LLM-AGENCY-002** | HIGH | Agent network access restricted to allowlisted domains — egress filtering enabled

## LLM07 — System Prompt Leakage

- [ ] **LLM-LEAK-001** | HIGH | System prompts include instruction defense against extraction attempts

## LLM08 — Vector and Embedding Weaknesses

- [ ] **LLM-EMBED-001** | MEDIUM | Vector databases use authentication and tenant isolation (namespaces or metadata filters)
- [ ] **LLM-EMBED-002** | MEDIUM | Embedding endpoints protected with authentication and rate limiting

## LLM09 — Misinformation

- [ ] **LLM-MISINFO-001** | MEDIUM | High-stakes LLM outputs require human review and fact verification

## LLM10 — Unbounded Consumption

- [ ] **LLM-CONSUME-001** | MEDIUM | All LLM API calls have max_tokens, rate limits, and cost budgets configured
