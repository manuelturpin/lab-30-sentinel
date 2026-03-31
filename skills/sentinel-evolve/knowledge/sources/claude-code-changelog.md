# Claude Code Changelog — Feature Intelligence

Auto-generated from GitHub releases for RAG indexing.


## v2.1.88 (2026-03-30)


### Features

- Added CLAUDE_CODE_NO_FLICKER=1 environment variable to opt into flicker-free alt-screen rendering with virtualized scrollback
- Added PermissionDenied hook that fires after auto mode classifier denials — return {retry: true} to tell the model it can retry
- Added named subagents to @ mention typeahead suggestions
- Fixed Shift+Enter submitting instead of inserting a newline on Windows Terminal Preview 1.25

### Deprecations

- Fixed prompt history entries containing CJK or emoji being silently dropped when they fall on a 4KB boundary in ~/.claude/history.jsonl

## v2.1.86 (2026-03-27)


### Features

- Added X-Claude-Code-Session-Id header to API requests so proxies can aggregate requests by session without parsing the body
- Added .jj and .sl to VCS directory exclusion lists so Grep and file autocomplete don't descend into Jujutsu or Sapling metadata
- Fixed scroll not following new messages after wheel scroll or click-to-select at the bottom of a long conversation

## v2.1.84 (2026-03-26)


### Features

- Added PowerShell tool for Windows as an opt-in preview. Learn more at https://code.claude.com/docs/en/tools-reference#powershell-tool
- Added ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL_SUPPORTS env vars to override effort/thinking capability detection for pinned default models for 3p (Bedrock, Vertex, Foundry), and _MODEL_NAME/_DESCR
- Added CLAUDE_STREAM_IDLE_TIMEOUT_MS env var to configure the streaming idle watchdog threshold (default 90s)
- Added TaskCreated hook that fires when a task is created via TaskCreate
- Added WorktreeCreate hook support for type: "http" — return the created worktree path via hookSpecificOutput.worktreePath in the response JSON
- Added allowedChannelPlugins managed setting for team/enterprise admins to define a channel plugin allowlist
- Added x-client-request-id header to API requests for debugging timeouts
- Added idle-return prompt that nudges users returning after 75+ minutes to /clear, reducing unnecessary token re-caching on stale sessions
- Deep links (claude-cli://) now open in your preferred terminal instead of whichever terminal happens to be first in the detection list
- Rules and skills paths: frontmatter now accepts a YAML list of globs
- MCP tool descriptions and server instructions are now capped at 2KB to prevent OpenAPI-generated servers from bloating context
- MCP servers configured both locally and via claude.ai connectors are now deduplicated — the local config wins
- Background bash tasks that appear stuck on an interactive prompt now surface a notification after ~45 seconds
- Token counts ≥1M now display as "1.5m" instead of "1512.6k"
- Global system-prompt caching now works when ToolSearch is enabled, including for users with MCP tools configured
- [VSCode] Added rate limit warning banner with usage percentage and reset time
- Stats screenshot (Ctrl+S in /stats) now works in all builds and is 16× faster

## v2.1.85 (2026-03-26)


### Features

- Added CLAUDE_CODE_MCP_SERVER_NAME and CLAUDE_CODE_MCP_SERVER_URL environment variables to MCP headersHelper scripts, allowing one helper to serve multiple servers
- Added conditional if field for hooks using permission rule syntax (e.g., Bash(git *)) to filter when they run, reducing process spawning overhead
- Added timestamp markers in transcripts when scheduled tasks (/loop, CronCreate) fire
- Added trailing space after [Image #N] placeholder when pasting images
- Deep link queries (claude-cli://open?q=…) now support up to 5,000 characters, with a "scroll to review" warning for long pre-filled prompts
- MCP OAuth now follows RFC 9728 Protected Resource Metadata discovery to find the authorization server
- Plugins blocked by organization policy (managed-settings.json) can no longer be installed or enabled, and are hidden from marketplace views
- PreToolUse hooks can now satisfy AskUserQuestion by returning updatedInput alongside permissionDecision: "allow", enabling headless integrations that collect answers via their own UI
- tool_parameters in OpenTelemetry tool_result events are now gated behind OTEL_LOG_TOOL_DETAILS=1
- Fixed shift+enter and meta+enter being intercepted by typeahead suggestions instead of inserting newlines
- Fixed terminal left in enhanced keyboard mode after exit in Ghostty, Kitty, WezTerm, and other terminals supporting the Kitty keyboard protocol — Ctrl+C and Ctrl+D now work correctly after quitting
- Improved @-mention file autocomplete performance on large repositories
- Improved PowerShell dangerous command detection
- Improved scroll performance with large transcripts by replacing WASM yoga-layout with a pure TypeScript implementation
- Reduced UI stutter when compaction triggers on large sessions

### Deprecations

- Fixed Python Agent SDK: type:'sdk' MCP servers passed via --mcp-config are no longer dropped during startup

## v2.1.83 (2026-03-25)


### Features

- Added managed-settings.d/ drop-in directory alongside managed-settings.json, letting separate teams deploy independent policy fragments that merge alphabetically
- Added CwdChanged and FileChanged hook events for reactive environment management (e.g., direnv)
- Added sandbox.failIfUnavailable setting to exit with an error when sandbox is enabled but cannot start, instead of running unsandboxed
- Added disableDeepLinkRegistration setting to prevent claude-cli:// protocol handler registration
- Added CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 to strip Anthropic and cloud provider credentials from subprocess environments (Bash tool, hooks, MCP stdio servers)
- Added transcript search — press / in transcript mode (Ctrl+O) to search, n/N to step through matches
- Added Ctrl+X Ctrl+E as an alias for opening the external editor (readline-native binding; Ctrl+G still works)
- Pasted images now insert an [Image #N] chip at the cursor so you can reference them positionally in your prompt
- Agents can now declare initialPrompt in frontmatter to auto-submit a first turn
- chat:killAgents and chat:fastMode are now rebindable via ~/.claude/keybindings.json

### Deprecations

- Deprecated TaskOutput tool in favor of using Read on the background task's output file path
- [VSCode] Spinner now turns red with "Not responding" when the backend hasn't responded for 60 seconds

## v2.1.81 (2026-03-20)


### Features

- Added --bare flag for scripted -p calls — skips hooks, LSP, plugin sync, and skill directory walks; requires ANTHROPIC_API_KEY or an apiKeyHelper via --settings (OAuth and keychain auth disabled); aut
- Added --channels permission relay — channel servers that declare the permission capability can forward tool approval prompts to your phone

## v2.1.80 (2026-03-19)


### Features

- Added rate_limits field to statusline scripts for displaying Claude.ai rate limit usage (5-hour and 7-day windows with used_percentage and resets_at)
- Added source: 'settings' plugin marketplace source — declare plugin entries inline in settings.json
- Added CLI tool usage detection to plugin tips, in addition to file pattern matching
- Added effort frontmatter support for skills and slash commands to override the model effort level when invoked
- Added --channels (research preview) — allow MCP servers to push messages into your session

## v2.1.79 (2026-03-18)


### Features

- Added --console flag to claude auth login for Anthropic Console (API billing) authentication
- Added "Show turn duration" toggle to the /config menu
- [VSCode] Added /remote-control — bridge your session to claude.ai/code to continue from a browser or phone
- [VSCode] Session tabs now get AI-generated titles based on your first message

## v2.1.78 (2026-03-17)


### Features

- Added StopFailure hook event that fires when the turn ends due to an API error (rate limit, auth failure, etc.)
- Added ${CLAUDE_PLUGIN_DATA} variable for plugin persistent state that survives plugin updates; /plugin uninstall prompts before deleting it
- Added effort, maxTurns, and disallowedTools frontmatter support for plugin-shipped agents
- Terminal notifications (iTerm2/Kitty/Ghostty popups, progress bar) now reach the outer terminal when running inside tmux with set -g allow-passthrough on
- Response text now streams line-by-line as it's generated
- Added ANTHROPIC_CUSTOM_MODEL_OPTION env var to add a custom entry to the /model picker, with optional _NAME and _DESCRIPTION suffixed vars for display
- Fixed queued prompts being concatenated without a newline separator
- Improved memory usage and startup time when resuming large sessions

## v2.1.77 (2026-03-17)


### Features

- Increased default maximum output token limits for Claude Opus 4.6 to 64k tokens, and the upper bound for Opus 4.6 and Sonnet 4.6 models to 128k tokens
- Added allowRead sandbox filesystem setting to re-allow read access within denyRead regions
- /copy now accepts an optional index: /copy N copies the Nth-latest assistant response

## v2.1.76 (2026-03-14)


### Features

- Added MCP elicitation support — MCP servers can now request structured input mid-task via an interactive dialog (form fields or browser URL)
- Added new Elicitation and ElicitationResult hooks to intercept and override responses before they're sent back
- Added -n / --name <name> CLI flag to set a display name for the session at startup
- Added worktree.sparsePaths setting for claude --worktree in large monorepos to check out only the directories you need via git sparse-checkout
- Added PostCompact hook that fires after compaction completes
- Added /effort slash command to set model effort level
- Added session quality survey — enterprise admins can configure the sample rate via the feedbackSurveyRate setting
- Fixed transcript not auto-scrolling to new messages after selecting text

## v2.1.74 (2026-03-12)


### Features

- Added actionable suggestions to /context command — identifies context-heavy tools, memory bloat, and capacity warnings with specific optimization tips
- Added autoMemoryDirectory setting to configure a custom directory for auto-memory storage

## v2.1.73 (2026-03-11)


### Features

- Added modelOverrides setting to map model picker entries to custom provider model IDs (e.g. Bedrock inference profile ARNs)
- Added actionable guidance when OAuth login or connectivity checks fail due to SSL certificate errors (corporate proxies, NODE_EXTRA_CA_CERTS)
- Fixed voice mode session corruption when a slow connection overlaps a new recording

### Deprecations

- Deprecated /output-style command — use /config instead. Output style is now fixed at session start for better prompt caching

## v2.1.72 (2026-03-10)


### Features

- Added w key in /copy to write the focused selection directly to a file, bypassing the clipboard (useful over SSH)
- Added optional description argument to /plan (e.g., /plan fix the auth bug) that enters plan mode and immediately starts
- Added claude plugins as an alias for claude plugin
- Added ExitWorktree tool to leave an EnterWorktree session
- Added CLAUDE_CODE_DISABLE_CRON environment variable to immediately stop scheduled cron jobs mid-session
- Added lsof, pgrep, tput, ss, fd, and fdfind to the bash auto-approval allowlist, reducing permission prompts for common read-only operations
- Added support for marketplace git URLs without .git suffix (Azure DevOps, AWS CodeCommit)
- Restored the model parameter on the Agent tool for per-invocation model overrides
- Fixed backgrounded Ctrl+B queries losing their transcript or corrupting the new conversation after /clear
- Fixed several permission rule matching issues: wildcard rules not matching commands with heredocs, embedded newlines, or no arguments; sandbox.excludedCommands failing with env var prefixes; "always a
- Fixed multi-line session titles when forking from a conversation whose first message contained newlines
- VSCode: Fixed Shift+Enter submitting input instead of inserting a newline for users with older keybindings
- VSCode: Added effort level indicator on the input border
- VSCode: Added vscode://anthropic.claude-code/open URI handler to open a new Claude Code tab programmatically, with optional prompt and session query parameters

### Deprecations

- Changed tool search to bypass the third-party proxy gate when the environment variable is set (replaces CLAUDE_CODE_PROXY_SUPPORTS_TOOL_REFERENCE, now removed)
- Simplified effort levels to low/medium/high (removed max) with new symbols (○ ◐ ●) and a brief notification instead of a persistent icon. Use /effort auto to reset to default
- Improved /config — Escape now cancels changes, Enter saves and closes, Space toggles settings
- Improved up-arrow history to show current session's messages first when running multiple concurrent sessions
- Improved voice input transcription accuracy for repo names and common dev terms (regex, OAuth, JSON)
- Improved marketplace clone failure messages to show diagnostic info even when git produces no stderr
- Improved claude plugin validate to explain that marketplace.json source paths are relative to the repo root when rejecting ../ paths
- Improved bash command parsing by switching to a native module — faster initialization and no memory leak

## v2.1.71 (2026-03-07)


### Features

- Added /loop command to run a prompt or slash command on a recurring interval (e.g. /loop 5m check the deploy)
- Added cron scheduling tools for recurring prompts within a session
- Added voice:pushToTalk keybinding to make the voice activation key rebindable in keybindings.json (default: space) — modifier+letter combos like meta+k have zero typing interference
- Added fmt, comm, cmp, numfmt, expr, test, printf, getconf, seq, tsort, and pr to the bash auto-approval allowlist
- Fixed duplicate entries in /permissions Workspace tab when the same directory is added with and without a trailing slash

### Deprecations

- Removed startup notification noise for unauthenticated org-registered claude.ai connectors

### Breaking Changes

- Fixed the Read tool putting oversized images into context when image processing failed, breaking subsequent turns in long image-heavy sessions

## v2.1.70 (2026-03-06)


### Features

- Fixed Enter inserting a newline instead of submitting when typing over a slow SSH connection
- Fixed feature flags read during early startup never refreshing their disk cache, causing stale values to persist across sessions
- [VSCode] Added spark icon in VS Code activity bar that lists all Claude Code sessions, with sessions opening as full editors
- [VSCode] Added full markdown document view for plans in VS Code, with support for adding comments to provide feedback
- [VSCode] Added native MCP server management dialog — use /mcp in the chat panel to enable/disable servers, reconnect, and manage OAuth authentication without switching to the terminal

## v2.1.69 (2026-03-05)


### Features

- Added the /claude-api skill for building applications with the Claude API and Anthropic SDK
- Added Ctrl+U on an empty bash prompt (!) to exit bash mode, matching escape and backspace
- Added numeric keypad support for selecting options in Claude's interview questions (previously only the number row above QWERTY worked)
- Added optional name argument to /remote-control and claude remote-control (/remote-control My Project or --name "My Project") to set a custom session title visible in claude.ai/code
- Added Voice STT support for 10 new languages (20 total) — Russian, Polish, Turkish, Dutch, Ukrainian, Greek, Czech, Danish, Swedish, Norwegian
- Added effort level display (e.g., "with low effort") to the logo and spinner, making it easier to see which effort setting is active
- Added agent name display in terminal title when using claude --agent
- Added sandbox.enableWeakerNetworkIsolation setting (macOS only) to allow Go programs like gh, gcloud, and terraform to verify TLS certificates when using a custom MITM proxy with httpProxyPort
- Added includeGitInstructions setting (and CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS env var) to remove built-in commit and PR workflow instructions from Claude's system prompt
- Added /reload-plugins command to activate pending plugin changes without restarting
- Added a one-time startup prompt suggesting Claude Code Desktop on macOS and Windows (max 3 showings, dismissible)
- Added ${CLAUDE_SKILL_DIR} variable for skills to reference their own directory in SKILL.md content
- Added InstructionsLoaded hook event that fires when CLAUDE.md or .claude/rules/*.md files are loaded into context
- Added agent_id (for subagents) and agent_type (for subagents and --agent) to hook events
- Added worktree field to status line hook commands with name, path, branch, and original repo directory when running in a --worktree session
- Added pluginTrustMessage in managed settings to append organization-specific context to the plugin trust warning shown before installation
- Added policy limit fetching (e.g., remote control restrictions) for Team plan OAuth users, not just Enterprise
- Added pathPattern to strictKnownMarketplaces for regex-matching file/directory marketplace sources alongside hostPattern restrictions
- Added plugin source type git-subdir to point to a subdirectory within a git repo
- Added oauth.authServerMetadataUrl config option for MCP servers to specify a custom OAuth metadata discovery URL when standard discovery fails
- Fixed Shift+Enter printing [27;2;13~ instead of inserting a newline in Ghostty over SSH
- Fixed plan mode feedback input not supporting multi-line text entry (backslash+Enter and Shift+Enter now insert newlines)
- Fixed symlink bypass where writing new files through a symlinked parent directory could escape the working directory in acceptEdits mode
- [VSCode] Added compaction display as a collapsible "Compacted chat" card with the summary inside
- [VSCode] The permission mode picker now respects permissions.disableBypassPermissionsMode from your effective Claude Code settings (including managed/policy settings) — when set to disable, bypass per

### Deprecations

- Fixed --model claude-opus-4-0 and --model claude-opus-4-1 resolving to deprecated Opus versions instead of current
- Fixed plugin hooks being silently dropped when two plugins use the same ${CLAUDE_PLUGIN_ROOT}/... command template

## v2.1.68 (2026-03-04)


### Features

- Opus 4.6 now defaults to medium effort for Max and Team subscribers. Medium effort works well for most tasks — it's the sweet spot between speed and thoroughness. You can change this anytime with /mod
- Re-introduced the "ultrathink" keyword to enable high effort for the next turn

### Deprecations

- Removed Opus 4 and 4.1 from Claude Code on the first-party API — users with these models pinned are automatically moved to Opus 4.6

## v2.1.63 (2026-02-28)


### Features

- Added /simplify and /batch bundled slash commands
- Added ENABLE_CLAUDEAI_MCP_SERVERS=false env var to opt out from making claude.ai MCP servers available
- Improved /model command to show the currently active model in the slash command menu
- Added HTTP hooks, which can POST JSON to a URL and receive JSON instead of running a shell command
- Added manual URL paste fallback during MCP OAuth authentication. If the automatic localhost redirect doesn't work, you can paste the callback URL to complete authentication.
- Fixed a race condition in the REPL bridge where new messages could arrive at the server interleaved with historical messages during the initial connection flush, causing message ordering issues.
- Added "Always copy full response" option to the /copy picker. When selected, future /copy commands will skip the code block picker and copy the full response directly.
- VSCode: Added session rename and remove actions to the sessions list
- Fixed /clear not resetting cached skills, which could cause stale skill content to persist in the new conversation

## v2.1.59 (2026-02-26)


### Features

- Claude automatically saves useful context to auto-memory. Manage with /memory
- Added /copy command to show an interactive picker when code blocks are present, allowing selection of individual code blocks or the full response.

## v2.1.58 (2026-02-25)


### Features

- Expand Remote Control to more users

## v2.1.51 (2026-02-24)


### Features

- Added claude remote-control subcommand for external builds, enabling local environment serving for all users.
- Updated plugin marketplace default git timeout from 30s to 120s and added CLAUDE_CODE_PLUGIN_GIT_TIMEOUT_MS to configure.
- Added support for custom npm registries and specific version pinning when installing plugins from npm sources
- BashTool now skips login shell (-l flag) by default when a shell snapshot is available, improving command execution performance. Previously this required setting CLAUDE_BASH_NO_LOGIN=true.
- Added CLAUDE_CODE_ACCOUNT_UUID, CLAUDE_CODE_USER_EMAIL, and CLAUDE_CODE_ORGANIZATION_UUID environment variables for SDK callers to provide account info synchronously, eliminating a race condition wher
- The /model picker now shows human-readable labels (e.g., "Sonnet 4.5") instead of raw model IDs for pinned model versions, with an upgrade hint when a newer version is available.

## v2.1.50 (2026-02-20)


### Features

- Added support for startupTimeout configuration for LSP servers
- Added WorktreeCreate and WorktreeRemove hook events, enabling custom VCS setup and teardown when agent worktree isolation creates or removes worktrees.
- Added support for isolation: worktree in agent definitions, allowing agents to declaratively run in isolated git worktrees.
- CLAUDE_CODE_SIMPLE mode now also disables MCP tools, attachments, hooks, and CLAUDE.md file loading for a fully minimal experience.
- Added claude agents CLI command to list all configured agents
- Improved memory usage during long sessions by clearing large tool results after they have been processed
- Added CLAUDE_CODE_DISABLE_1M_CONTEXT environment variable to disable 1M context window support
- Opus 4.6 (fast mode) now includes the full 1M context window
- VSCode: Added /extra-usage command support in VS Code sessions

### Deprecations

- Fixed memory leak where completed task state objects were never removed from AppState

## v2.1.49 (2026-02-19)


### Features

- Added ConfigChange hook event that fires when configuration files change during a session, enabling enterprise security auditing and optional blocking of settings changes.
- Improved startup performance by caching MCP auth failures to avoid redundant connection attempts
- Improved startup performance by reducing HTTP calls for analytics token counting
- Improved startup performance by batching MCP tool token counting into a single API call

### Deprecations

- Sonnet 4.5 with 1M context is being removed from the Max plan in favor of our frontier Sonnet 4.6 model, which now has 1M context. Please switch in /model.

## v2.1.47 (2026-02-18)


### Features

- Added last_assistant_message field to Stop and SubagentStop hook inputs, providing the final assistant response text so hooks can access it without parsing transcript files.
- Added chat:newline keybinding action for configurable multi-line input (anthropics/claude-code#26075)
- Added added_dirs to the statusline JSON workspace section, exposing directories added via /add-dir to external scripts (anthropics/claude-code#26096)

### Breaking Changes

- Fixed an issue where bash commands with backslash-newline continuation lines (e.g., long commands split across multiple lines with \) would produce spurious empty arguments, potentially breaking comma

## v2.1.45 (2026-02-17)


### Features

- Added support for Claude Sonnet 4.6
- Added support for reading enabledPlugins and extraKnownMarketplaces from --add-dir directories
- Added spinnerTipsOverride setting to customize spinner tips — configure tips with an array of custom tip strings, and optionally set excludeDefault: true to show only your custom tips instead of the b
- Added SDKRateLimitInfo and SDKRateLimitEvent types to the SDK, enabling consumers to receive rate limit status updates including utilization, reset times, and overage information

## v2.1.41 (2026-02-13)


### Features

- Added claude auth login, claude auth status, and claude auth logout CLI subcommands
- Added Windows ARM64 (win32-arm64) native binary support
- Improved /rename to auto-generate session name from conversation context when called without arguments
- Improved narrow terminal layout for prompt footer

### Deprecations

- Fixed markdown link display text being dropped for raw URL

## v2.1.39 (2026-02-10)


### Features

- Improved terminal rendering performance

## v2.1.36 (2026-02-07)


### Features

- Fast mode is now available for Opus 4.6. Learn more at https://code.claude.com/docs/en/fast-mode

## v2.1.33 (2026-02-06)


### Features

- Added TeammateIdle and TaskCompleted hook events for multi-agent workflows
- Added support for restricting which sub-agents can be spawned via Task(agent_type) syntax in agent "tools" frontmatter
- Added memory frontmatter field support for agents, enabling persistent memory with user, project, or local scope
- Added plugin name to skill descriptions and /skills menu for better discoverability
- Fixed an issue where submitting a new message while the model was in extended thinking would interrupt the thinking phase
- VSCode: Added support for remote sessions, allowing OAuth users to browse and resume sessions from claude.ai
- VSCode: Added git branch and message count to the session picker, with support for searching by branch name

## v2.1.32 (2026-02-05)


### Features

- Claude Opus 4.6 is now available!
- Added research preview agent teams feature for multi-agent collaboration (token-intensive feature, requires setting CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1)
- Claude now automatically records and recalls memories as it works
- Added "Summarize from here" to the message selector, allowing partial conversation summarization.
- Skills defined in .claude/skills/ within additional directories (--add-dir) are now loaded automatically.
- VSCode: Added spinner when loading past conversations list

## v2.1.31 (2026-02-04)


### Features

- Added session resume hint on exit, showing how to continue your conversation later
- Added support for full-width (zenkaku) space input from Japanese IME in checkbox selection
- Fixed PDF too large errors permanently locking up sessions, requiring users to start a new conversation

### Deprecations

- Removed misleading Anthropic API pricing from model selector for third-party provider (Bedrock, Vertex, Foundry) users

## v2.1.30 (2026-02-03)


### Features

- Added pages parameter to the Read tool for PDFs, allowing specific page ranges to be read (e.g., pages: "1-5"). Large PDFs (>10 pages) now return a lightweight reference when @ mentioned instead of be
- Added pre-configured OAuth client credentials for MCP servers that don't support Dynamic Client Registration (e.g., Slack). Use --client-id and --client-secret with claude mcp add.
- Added /debug for Claude to help troubleshoot the current session
- Added support for additional git log and git show flags in read-only mode (e.g., --topo-order, --cherry-pick, --format, --raw)
- Added token count, tool uses, and duration metrics to Task tool results
- Added reduced motion mode to the config
- [VSCode] Added multiline input support to the "Other" text input in question dialogs (use Shift+Enter for new lines)
- [VSCode] Fixed duplicate sessions appearing in the session list when starting a new conversation

## v2.1.27 (2026-01-30)


### Features

- Added tool call failures and denials to debug logs
- Added --from-pr flag to resume sessions linked to a specific GitHub PR number or URL
- Sessions are now automatically linked to PRs when created via gh pr create

## v2.1.23 (2026-01-29)


### Features

- Added customizable spinner verbs setting (spinnerVerbs)

## v2.1.21 (2026-01-28)


### Features

- Added support for full-width (zenkaku) number input from Japanese IME in option selection prompts
- [VSCode] Added automatic Python virtual environment activation, ensuring python and pip commands use the correct interpreter (configurable via claudeCode.usePythonEnvironment setting)

## v2.1.20 (2026-01-27)


### Features

- Added arrow key history navigation in vim normal mode when cursor cannot move further
- Added external editor shortcut (Ctrl+G) to the help menu for better discoverability
- Added PR review status indicator to the prompt footer, showing the current branch's PR state (approved, changes requested, pending, or draft) as a colored dot with a clickable link
- Added support for loading CLAUDE.md files from additional directories specified via --add-dir flag (requires setting CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD=1)
- Added ability to delete tasks via the TaskUpdate tool

## v2.1.19 (2026-01-23)


### Features

- Added env var CLAUDE_CODE_ENABLE_TASKS, set to false to keep the old system temporarily
- Added shorthand $0, $1, etc. for accessing individual arguments in custom commands
- [SDK] Added replay of queued_command attachment messages as SDKUserMessageReplay events when replayUserMessages is enabled
- [VSCode] Enabled session forking and rewind functionality for all users

## v2.1.16 (2026-01-22)


### Features

- Added new task management system, including new capabilities like dependency tracking
- [VSCode] Added native plugin management support
- [VSCode] Added ability for OAuth users to browse and resume remote Claude sessions from the Sessions dialog

## v2.1.15 (2026-01-21)


### Deprecations

- Added deprecation notification for npm installations - run claude install or see https://docs.anthropic.com/en/docs/claude-code/getting-started for more options
- Improved UI rendering performance with React Compiler

## v2.1.14 (2026-01-20)


### Features

- Added history-based autocomplete in bash mode (!) - type a partial command and press Tab to complete from your bash command history
- Added search to installed plugins list - type to filter by name or description
- Added support for pinning plugins to specific git commit SHAs, allowing marketplace entries to install exact versions
- [VSCode] Added /usage command to display current plan usage

## v2.1.9 (2026-01-16)


### Features

- Added auto:N syntax for configuring the MCP tool search auto-enable threshold, where N is the context window percentage (0-100)
- Added plansDirectory setting to customize where plan files are stored
- Added external editor support (Ctrl+G) in AskUserQuestion "Other" input field
- Added session URL attribution to commits and PRs created from web sessions
- Added support for PreToolUse hooks to return additionalContext to the model
- Added ${CLAUDE_SESSION_ID} string substitution for skills to access the current session ID

## v2.1.7 (2026-01-14)


### Features

- Added showTurnDuration setting to hide turn duration messages (e.g., "Cooked for 1m 6s")
- Added ability to provide feedback when accepting permission prompts
- Added inline display of agent's final response in task notifications, making it easier to see results without reading the full transcript file

## v2.1.6 (2026-01-13)


### Features

- Added search functionality to /config command for quickly filtering settings
- Added Updates section to /doctor showing auto-update channel and available npm versions (stable/latest)
- Added date range filtering to /stats command - press r to cycle between Last 7 days, Last 30 days, and All time
- Added automatic discovery of skills from nested .claude/skills directories when working with files in subdirectories
- Added context_window.used_percentage and context_window.remaining_percentage fields to status line input for easier context window display
- Added an error display when the editor fails during Ctrl+G
- Fixed Option+Return not inserting newlines in Kitty keyboard protocol terminals

### Deprecations

- Removed ability to @-mention MCP servers to enable/disable - use /mcp enable <name> instead

## v2.1.5 (2026-01-12)


### Features

- Added CLAUDE_CODE_TMPDIR environment variable to override the temp directory used for internal temp files, useful for environments with custom temp directory requirements

## v2.1.4 (2026-01-11)


### Features

- Added CLAUDE_CODE_DISABLE_BACKGROUND_TASKS environment variable to disable all background task functionality including auto-backgrounding and the Ctrl+B shortcut

## v2.1.3 (2026-01-09)


### Features

- Merged slash commands and skills, simplifying the mental model with no change in behavior
- Added release channel (stable or latest) toggle to /config
- Added detection and warnings for unreachable permission rules, with warnings in /doctor and after saving rules that include the source of each rule and actionable fix guidance
- Fixed trust dialog acceptance when running from the home directory not enabling trust-requiring features like hooks during the session
- Improved terminal rendering stability by preventing uncontrolled writes from corrupting cursor state
- Improved slash command suggestion readability by truncating long descriptions to 2 lines
- Changed tool hook execution timeout from 60 seconds to 10 minutes
- [VSCode] Added clickable destination selector for permission requests, allowing you to choose where settings are saved (this project, all projects, shared with team, or session only)

## v2.1.2 (2026-01-09)


### Features

- Added source path metadata to images dragged onto the terminal, helping Claude understand where images originated
- Added clickable hyperlinks for file paths in tool output in terminals that support OSC 8 (like iTerm)
- Added support for Windows Package Manager (winget) installations with automatic detection and update instructions
- Added Shift+Tab keyboard shortcut in plan mode to quickly select "auto-accept edits" option
- Added FORCE_AUTOUPDATE_PLUGINS environment variable to allow plugin autoupdate even when the main auto-updater is disabled
- Added agent_type to SessionStart hook input, populated if --agent is specified

### Deprecations

- Deprecated Windows managed settings path C:\ProgramData\ClaudeCode\managed-settings.json - administrators should migrate to C:\Program Files\ClaudeCode\managed-settings.json
- [SDK] Changed minimum zod peer dependency to ^4.0.0
