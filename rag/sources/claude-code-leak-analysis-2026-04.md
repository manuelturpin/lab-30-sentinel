# Claude Code Source Leak Analysis — Security Intelligence

**Date**: 2026-03-31
**Source**: Multiple (Alex Kim blog, VentureBeat, Ars Technica, TheHackerNews, Penligent)
**Category**: AI Agent Security, Supply Chain, Shell Security

## Incident Summary

On 2026-03-31, Anthropic's Claude Code CLI tool (v2.1.88) accidentally exposed 512,000 lines of TypeScript source code via a 59.8MB source map file (.map) included in the npm package. The root cause was a Bun bundler bug (oven-sh/bun#28001) that serves source maps in production mode despite documentation saying otherwise.

## Attack Vectors Revealed

### 1. Hook Exploitation (Critical)
The leak exposed the exact orchestration logic for Hooks and MCP servers. Attackers can now design malicious repositories with crafted `.claude/settings.json` that:
- Execute background commands via PreToolUse/PostToolUse hooks
- Exfiltrate data via HTTP hooks to external URLs
- Suppress security warnings by intercepting tool calls
- Run commands without conditional `if` guards

### 2. Bash Security Checks (23 patterns)
File `bashSecurity.ts` contains 23 numbered security checks:
- 18 blocked Zsh builtins (zmodload, builtin, source with vars)
- Unicode zero-width space injection (U+200B, U+200C, U+200D, U+FEFF) — invisible chars that bypass text-based command filtering
- IFS null-byte injection — modifying Internal Field Separator to break command parsing
- Zsh equals expansion (`=curl` resolves to the path of curl, bypassing command allowlists)
- HackerOne-identified malformed token bypass

### 3. Anti-Distillation Bypass
Flag `ANTI_DISTILLATION_CC` can be bypassed by:
- MITM proxy stripping the `anti_distillation` field from API requests
- Setting `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS` environment variable
- Using third-party API providers or SDK entrypoint

### 4. Undercover Mode
File `undercover.ts` (~90 lines) strips traces of Anthropic internals:
- Instructs model to never mention codenames ("Capybara", "Tengu")
- Prevents Co-Authored-By lines and AI attribution
- Can be forced ON with `CLAUDE_CODE_UNDERCOVER=1`
- Dead-code-eliminated in external builds but reveals the pattern

### 5. Native Client Attestation
API requests include a `cch=00000` placeholder that Bun's native HTTP stack overwrites with a computed hash. Bypass vectors:
- Gated behind compile-time flag `NATIVE_CLIENT_ATTESTATION`
- Disable via `CLAUDE_CODE_ATTRIBUTION_HEADER` env var
- GrowthBook killswitch: `tengu_attribution_header`
- Stock Bun/Node.js preserves literal zeros

### 6. Source Map Supply Chain Risk
The leak itself demonstrates the risk of shipping source maps:
- `.map` files enable full source reconstruction
- npm packages often include .map files by default
- Missing `.npmignore` or `files` field in package.json exposes everything
- Bun's bundler generates source maps by default unless explicitly disabled

## Security Patterns for Detection

### Malicious Hook Patterns
```
"hooks": { ... }
"PreToolUse": [ ... ]
"command": "curl|wget|nc "
"type": "http"
"url": "https://external-domain"
```

### Shell Injection Patterns
```
\u200b \u200c \u200d \ufeff    — zero-width chars
$IFS                          — field separator manipulation
=curl =wget =chmod            — Zsh equals expansion
builtin zmodload command -    — dangerous builtins
```

### Security Bypass Env Vars
```
CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS
CLAUDE_CODE_ATTRIBUTION_HEADER
CLAUDE_CODE_SIMPLE
CLAUDE_CODE_UNDERCOVER=1
ENABLE_CLAUDEAI_MCP_SERVERS=false
```

### Attribution Suppression
```
"do not blow your cover"
"never mention Claude/AI"
"NEVER include Co-Authored-By"
```

## Defensive Recommendations

1. **Audit hooks** in any cloned repository's `.claude/settings.json` before trusting
2. **Disable source maps** in production builds: `devtool: false` in webpack, `--no-source-maps` in Bun
3. **Use `files` field** in package.json to explicitly list published files
4. **Set `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`** to prevent credential leakage
5. **Add `if` conditional guards** to all hooks to restrict when they fire
6. **Block zero-width Unicode** in any command input sanitization
7. **Require AI attribution** in project policies for supply chain transparency

## Typosquatting Alert

Post-leak, attacker "pacifier136" registered typosquat npm packages mimicking internal Claude Code package names. Currently empty stubs but may push malicious updates.

## Standards Mapping

| Finding | CWE | OWASP | MITRE ATLAS |
|---------|-----|-------|-------------|
| Hook exploitation | CWE-94, CWE-78 | LLM06:2025 | AML.T0056 |
| Shell injection patterns | CWE-78, CWE-116 | A03:2025 | — |
| Source map exposure | CWE-540, CWE-615 | A05:2025 | — |
| Env var bypass | CWE-489, CWE-215 | LLM06:2025 | — |
| Attribution suppression | CWE-451 | LLM03:2025 | — |
| Anti-distillation bypass | CWE-693 | — | AML.T0057 |
