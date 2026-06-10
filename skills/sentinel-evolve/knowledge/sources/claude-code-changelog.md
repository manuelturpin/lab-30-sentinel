# Claude Code Changelog — Feature Intelligence

Auto-generated from GitHub releases for RAG indexing.


## v2.1.170 (2026-06-09)


### Features

- Introducing Claude Fable 5: a Mythos-class model that we’ve made safe for general use. Fable’s capabilities exceed those of any model we’ve ever made generally available. Update to version 2.1.170 for

## v2.1.169 (2026-06-08)


### Features

- Added --safe-mode flag (and CLAUDE_CODE_SAFE_MODE) to start Claude Code with all customizations (CLAUDE.md, plugins, skills, hooks, MCP servers) disabled for troubleshooting
- Added a disableBundledSkills setting and CLAUDE_CODE_DISABLE_BUNDLED_SKILLS environment variable to hide bundled skills, workflows, and built-in slash commands from the model
- Fixed claude agents --json omitting blocked and just-dispatched background sessions; added --all to include completed sessions, plus new id and state fields
- Added a tip suggesting claude agents when running multiple concurrent sessions

### Breaking Changes

- Added /cd command to move a session to a new working directory without breaking the prompt cache mid-session

## v2.1.168 (2026-06-06)


### Features

- Bug fixes and reliability improvements

## v2.1.167 (2026-06-06)


### Features

- Bug fixes and reliability improvements

## v2.1.166 (2026-06-06)


### Features

- Added fallbackModel setting to configure up to three fallback models tried in order when the primary model is overloaded or unavailable; --fallback-model now also applies to interactive sessions
- Added glob pattern support in deny rule tool-name position ("*" denies all tools); allow rules reject non-MCP globs, and unknown tool names in deny rules warn at startup
- Hardened cross-session messaging: messages relayed via SendMessage from other Claude sessions no longer carry user authority — receivers refuse relayed permission requests, and auto mode blocks them
- MAX_THINKING_TOKENS=0, --thinking disabled, and the per-model thinking toggle now disable thinking on models that think by default via the Claude API (3P providers unchanged)
- Claude Code now retries a turn once on the fallback model when the API rejects an unexpected non-retryable error; auth, rate-limit, request-size, and transport errors still surface immediately
- claude update now announces the target version before downloading instead of going silent
- claude agents: typing a URL into the list now filters to the session whose first prompt contained it

### Deprecations

- Fixed Shift+non-ASCII characters (e.g. Shift+ä → Ä) being dropped in terminals using the Kitty keyboard protocol (WezTerm, Ghostty, kitty)

## v2.1.165 (2026-06-05)


### Features

- Bug fixes and reliability improvements

## v2.1.163 (2026-06-04)


### Features

- Added requiredMinimumVersion and requiredMaximumVersion managed settings — Claude Code refuses to start if its version is outside the allowed range and directs the user to an approved version
- Added /plugin list command to list installed plugins, with --enabled/--disabled filters
- Added a "c to copy" shortcut to /btw that copies the raw markdown answer to the clipboard, preserving formatting when pasted elsewhere
- Hooks: Stop and SubagentStop hooks can now return hookSpecificOutput.additionalContext to give Claude feedback and keep the turn going without being labeled a hook error
- Skills: added \$ escape syntax to include a literal $ before a digit in command bodies
- stdio MCP servers now receive the same CLAUDE_CODE_SESSION_ID as hooks/Bash on --resume
- Background agent sessions now update to a new Claude Code version in the background, so opening a session after an update no longer waits on a cold restart
- Clearer descriptions for built-in commands and skills in the / menu
- The subscription-switch suggestion now shows in the startup announcement slot instead of a toast

### Deprecations

- Fixed keyboard input becoming permanently unresponsive after a paste operation whose end marker is dropped by the terminal

## v2.1.162 (2026-06-03)


### Features

- claude agents --json now includes waitingFor showing what a waiting session is blocked on (e.g. permission prompt)
- --tools: explicitly listing Grep/Glob now provides the dedicated search tools on native builds with embedded search (previously these names were silently ignored)
- /effort now confirms when your chosen level will persist as the default for new sessions
- Clicking a slash command in the autocomplete menu now fills it into your prompt instead of running it immediately; press Enter to run
- Remote Control now shows as a persistent footer pill (with a link to the session) instead of a startup message
- Renamed Windsurf to Devin Desktop in the /ide menu, /terminal-setup, and /scroll-speed, following the editor's rebrand
- Improved background service startup and claude update verification to wait out endpoint-security scanning of new binaries instead of failing after 5 seconds

### Deprecations

- Fixed an interrupt (Esc) sent at the very start of a turn being silently dropped in stream-json/SDK sessions, leaving the turn running with no "Interrupted" feedback
- Removed the "Claude in Chrome enabled" and "marketplace installed" startup messages; model auto-updates and the team-onboarding tip now show as quiet notices under the logo

### Breaking Changes

- Fixed cross-session messaging (SendMessage) silently breaking when CLAUDE_CODE_TMPDIR or $TMPDIR points at a deep directory

## v2.1.161 (2026-06-02)


### Features

- OTEL_RESOURCE_ATTRIBUTES values are now included as labels on metric datapoints, so you can slice usage metrics by custom dimensions like team or repo
- claude agents rows now show done/total before the detail when work is fanned out; peek shows the longest-running item
- /mcp now collapses claude.ai connectors you've never signed in to behind a "Show unused connectors" row
- Parallel tool calls: a failed Bash command no longer cancels other calls in the same batch — each tool returns its own result independently
- Fullscreen mode: clipboard now uses wl-copy/xclip/xsel on Linux when available, copies to both the clipboard and PRIMARY selection for middle-click paste, and the "hold {key} for native selection" hin
- [VSCode] Added a tip suggesting disabling terminal GPU acceleration (or running /terminal-setup) to fix garbled glyphs

### Deprecations

- Fixed OpenTelemetry log events (user_prompt, api_request, tool_result, tool_decision) being silently dropped when emitted before telemetry initialization completed

## v2.1.160 (2026-06-02)


### Features

- Added a prompt before writing to shell startup files (.zshenv, .zlogin, .bash_login) and ~/.config/git/, which could otherwise lead to unintended command execution
- acceptEdits mode now prompts before writing build-tool config files that grant code execution (.npmrc, .yarnrc*, bunfig.toml, .bazelrc, .pre-commit-config.yaml, .devcontainer/, etc.)
- Edit no longer requires a separate Read after viewing a file with grep: single-file grep/egrep/fgrep commands now satisfy the read-before-edit check

### Deprecations

- Removed CLAUDE_CODE_OPUS_4_6_FAST_MODE_OVERRIDE; the environment variable is now a no-op
- Removed the JetBrains plugin install suggestion from startup
- Renamed the dynamic-workflow trigger keyword from workflow to ultracode. The word "workflow" no longer triggers a run; asking for one in your own words still works. The trigger keyword is highlighted 

## v2.1.159 (2026-05-31)


### Features

- Internal infrastructure improvements (no user-facing changes)

## v2.1.158 (2026-05-30)


### Features

- Auto mode is now available on Bedrock, Vertex, and Foundry for Opus 4.7 and Opus 4.8. Opt in by setting CLAUDE_CODE_ENABLE_AUTO_MODE=1

## v2.1.157 (2026-05-29)


### Features

- Plugins in .claude/skills directories are now automatically loaded, no marketplace required
- Added claude plugin init <name> to scaffold a new plugin in .claude/skills
- Added autocomplete for /plugin arguments: subcommands, installed plugin names, and plugins from known marketplaces
- Fixed the /model picker showing an incorrect "Newer version available" hint when the selected model is already the newest in its family; the pinned-model row now shows the model's description instead 
- WSL: fixed image paste (alt+v keybinding), screenshot paste on Windows 11, and added support for dragging images from Windows Explorer
- Improved performance of long and resumed conversations by eliminating redundant message-rendering recomputations
- /terminal-setup now disables GPU acceleration in VS Code/Cursor/Windsurf integrated terminals to prevent garbled-text rendering
- The Feature of the Week credit-claim status now appears as a notification in the status area instead of a line above the prompt
- Added a "Workflow keyword trigger" setting in /config to stop the word "workflow" in a prompt from triggering a dynamic workflow

### Deprecations

- Removed the "bash commands will be sandboxed" startup banner — sandbox status still shows in /status and when a command is blocked
- Removed the "/ide for …" startup hint toast

## v2.1.154 (2026-05-28)


### Features

- Opus 4.8 is here! Now defaults to high effort · /effort xhigh for your hardest tasks
- Introducing dynamic workflows: ask Claude to create a workflow and it orchestrates work across tens to hundreds of agents in the background, so you can take on larger, more complex tasks. Run /workflo
- Fast mode on Opus 4.8 is now available at a fraction of its previous cost: 2x the standard rate for 2.5x the speed
- The lean system prompt is now the default for all models except Haiku, Sonnet, and Opus 4.7 and earlier
- Claude now reserves the multiple-choice question prompt for decisions it genuinely cannot make itself, instead of asking when it already has enough context to proceed
- Streaming tool execution is now always enabled, including when telemetry is disabled or on Bedrock/Vertex/Foundry (previously behind a feature flag)
- Stdio MCP server subprocesses now receive CLAUDE_CODE_SESSION_ID and CLAUDECODE=1 in their environment
- claude mcp list/get now show unapproved .mcp.json servers as ⏸ Pending approval instead of auto-approving and connecting when output is piped
- /remote-control autocomplete now shows "Disconnect Remote Control" when Remote Control is already active
- [VSCode] Auto mode no longer requires the bypass-permissions setting to appear in the mode picker, and a dismissable notice on the new-session screen explains auto mode the first time it's active

### Deprecations

- Deprecated CLAUDE_CODE_OPUS_4_6_FAST_MODE_OVERRIDE (will be removed on 06/01). To use fast mode on Opus 4.6, switch with /model claude-opus-4-6[1m] and then /fast on
- Improved the auto-mode classifier's detection of data exfiltration, particularly bulk transfers of repository contents
- Fixed a single invalid allowedMcpServers/deniedMcpServers entry in managed settings discarding all managed-settings policy; the bad entry is now dropped with a claude doctor warning
- Removed the stale "& for background" hint from the shortcuts help panel

### Breaking Changes

- Added Claude Opus 4.8 support and 4.7 → 4.8 migration guidance to the /claude-api skill

## v2.1.153 (2026-05-28)


### Features

- Added skipLfs option to github/git plugin marketplace sources to skip Git LFS downloads during clone and update
- /model now saves your selection as the default for new sessions (matching the IDE). Press s in the picker to switch models for the current session only.
- If you customized the modelPicker:setAsDefault keybinding, rename it to modelPicker:thisSessionOnly in keybindings.json (the d action was replaced by s)

## v2.1.152 (2026-05-27)


### Features

- Added /reload-skills command to re-scan skill directories without restarting the session
- SessionStart hooks can now return reloadSkills: true to re-scan skill directories, making skills installed by the hook available in the same session
- SessionStart hooks can now set the session title via hookSpecificOutput.sessionTitle on startup and resume
- Added a MessageDisplay hook event that lets hooks transform or hide assistant message text as it is displayed
- Added pluginSuggestionMarketplaces managed setting: admins can allowlist org marketplaces whose plugins may be suggested via context-aware tips
- claude plugin marketplace remove now accepts --scope user|project|local for symmetry with marketplace add, install, and uninstall
- Claude Code now switches to your configured --fallback-model for the rest of the session when the primary model is not found, instead of failing every request
- Auto mode no longer requires opt-in consent
- Vim mode: / in NORMAL mode now opens reverse history search (like Ctrl+R), matching bash/zsh vi-mode
- The /usage breakdown now includes large session files; files are scanned with a streaming read so memory usage stays flat
- Thinking summaries in the collapsed group now stay readable for at least 3 seconds, render as markdown, and cap at 10 lines (Ctrl+O shows the full thinking)
- In fullscreen mode, the "Thinking for Ns" indicator now counts up live while the model is thinking, and keeps its value if you interrupt mid-thought
- Simplified the Workflow tool's inline progress display — live agent counts now show only in the persistent workflow status row below the prompt
- The post-response timer now shows "Waiting for N background agents/workflows to finish" when backgrounded agents or workflows are still running, and reports the cumulative time once their results are 
- Added the session entrypoint as an OpenTelemetry metric attribute (app.entrypoint, opt-in via OTEL_METRICS_INCLUDE_ENTRYPOINT=true)

### Deprecations

- Fixed /doctor reporting "marketplace not found" or "plugin not found" for stale enabledPlugins entries referencing removed marketplaces or dropped plugins

## v2.1.150 (2026-05-23)


### Features

- Internal infrastructure improvements (no user-facing changes)

## v2.1.149 (2026-05-22)


### Features

- /usage now shows a per-category breakdown of what's driving your limits usage — skills, subagents, plugins, and per-MCP-server cost
- /diff detail view can now be scrolled with the keyboard (arrows, j/k, PgUp/PgDn, Space, Home/End)
- Markdown output now renders GFM task list checkboxes (- [ ] todo / - [x] done) instead of plain bullets
- Enterprise: added the allowAllClaudeAiMcps managed setting to load claude.ai cloud MCP connectors alongside managed-mcp.json
- Fixed Ctrl+O transcript view freezing at the moment it was opened instead of tailing new messages

## v2.1.147 (2026-05-21)


### Features

- Pinned background sessions (Ctrl+T in claude agents) now stay alive when idle, are restarted in place to apply Claude Code updates, and are shed under memory pressure only after non-pinned sessions
- Fixed /theme "New custom theme" and color editor dialogs not responding to Esc
- Fixed slash commands followed by a tab or newline being treated as an unknown command

### Deprecations

- Renamed /simplify to /code-review. It now reports correctness bugs at a chosen effort level (e.g., /code-review high); pass --comment to post findings as inline GitHub PR comments. The old cleanup-and
- Improved auto-updater: retries transient network failures, reports specific error categories and OS error codes on failure, and shows the current version when an update fails
- Improved diff rendering performance for large file edits
- Prompt history no longer records consecutive duplicate entries — recalling a prompt with arrow-up and submitting it again won't add another copy

## v2.1.146 (2026-05-21)


### Features

- Renamed /simplify to /code-review with an optional effort level (e.g. /code-review high)
- Auto mode no longer suppresses AskUserQuestion when the user or a skill explicitly relies on it
- Fixed /theme color editor and "New custom theme" dialogs not responding to Esc

## v2.1.145 (2026-05-19)


### Features

- Added claude agents --json to list live Claude sessions as JSON for scripting (tmux-resurrect, status bars, session pickers)
- Added agent_id and parent_agent_id attributes to claude_code.tool OTEL spans, and fixed trace parenting so background subagent spans nest under the dispatching Agent tool span
- Status line JSON input now includes GitHub repo and PR information when detected
- /plugin Discover and Browse screens now show a plugin's commands, agents, skills, hooks, and MCP/LSP servers before installation
- claude agents terminal tab title now shows the awaiting-input count so an alt-tabbed window tells you when an agent needs attention
- Slash command and @-mention suggestion list now supports mouse hover and click in fullscreen mode
- Stop and SubagentStop hook input now includes background_tasks and session_crons fields

### Deprecations

- Fixed /review using a deprecated projectCards GraphQL query that errored on repos with Classic Projects

## v2.1.144 (2026-05-19)


### Features

- Added /resume support for background sessions — sessions started via claude --bg or agent view now appear alongside interactive ones, marked with bg
- Added elapsed duration to background subagent completion notifications (e.g. "Agent completed · 3h 2m 5s")
- The /plugin browse and discover panes now show when a plugin was last updated
- /model now changes the model for the current session only; press d in the model picker to set a default for new sessions
- Renamed "extra usage" to "usage credits" across CLI copy; /extra-usage is now /usage-credits (old name still works)
- /bg and ←-detach now preserve directories added via /add-dir

### Breaking Changes

- Fixed MCP images with unsupported MIME types (e.g. SVG) breaking the conversation — now saved to disk and referenced in the tool result

## v2.1.143 (2026-05-15)


### Features

- Added plugin dependency enforcement: claude plugin disable now refuses when another enabled plugin depends on the target (with a copy-pasteable disable-chain hint), and claude plugin enable force-enab
- Added projected context cost (per-turn and per-invocation token estimates) to the /plugin marketplace browse pane
- Added worktree.bgIsolation: "none" setting to let background sessions edit the working copy directly without EnterWorktree, for repos where worktrees are impractical
- PowerShell tool now passes -ExecutionPolicy Bypass. Opt out with CLAUDE_CODE_POWERSHELL_RESPECT_EXECUTION_POLICY=1
- Background sessions now preserve the model and effort level you set after waking from idle
- Shift+Tab in attached agent sessions now includes auto mode in the cycle

## v2.1.142 (2026-05-14)


### Features

- Added new claude agents flags: --add-dir, --settings, --mcp-config, --plugin-dir, --permission-mode, --model, --effort, and --dangerously-skip-permissions to configure dispatched background sessions
- Fast mode now uses Opus 4.7 by default (previously Opus 4.6). Set CLAUDE_CODE_OPUS_4_6_FAST_MODE_OVERRIDE=1 to pin fast mode to Opus 4.6
- Plugins with a root-level SKILL.md and no skills/ subdirectory are now surfaced as a skill
- The /plugin details pane and claude plugin details now show LSP servers a plugin provides
- /web-setup warns before replacing an existing GitHub App connection
- Fixed /plugin browse pane showing "0 installs" for newly published plugins

### Deprecations

- Removed stale /model claude-sonnet-4-20250514 suggestion from Usage Policy refusal messages

## v2.1.141 (2026-05-13)


### Features

- Added terminalSequence field to hook JSON output so hooks can emit desktop notifications, window titles, and bells without a controlling terminal
- Added CLAUDE_CODE_PLUGIN_PREFER_HTTPS to clone GitHub plugin sources over HTTPS instead of SSH, for environments without a GitHub SSH key
- Added ANTHROPIC_WORKSPACE_ID environment variable for workload identity federation — scopes the minted token to a specific workspace when the federation rule covers more than one
- Added claude agents --cwd <path> to scope the session list to a directory
- /feedback can now include recent sessions (last 24 hours or 7 days) for issues spanning more than the current session
- Rewind menu: added "Summarize up to here" to compress earlier context while keeping recent turns intact
- Auto mode permission dialog now explains when a permissions.ask rule caused the prompt
- Restored the "view diff in your IDE" option on file-edit permission prompts when an IDE is connected
- Background agents launched via /bg or ←← now preserve the current permission mode instead of reverting to default
- claude agents: agents that finish work but leave a background shell running now move to Completed instead of staying under Working
- Improved spinner feedback during long thinking periods — the spinner now warms to amber after 10 seconds to signal Claude is still working
- Improved plugin menu navigation: →/Tab switch tabs, ↑ moves to the tab strip, and tab headers and search box are clickable in fullscreen mode
- Fixed switching permission mode while a tool-permission prompt is open not auto-dismissing the prompt when the new setting permits the tool
- Fixed alternative chat:submit keybindings (e.g. meta+enter, ctrl+enter) not working when enter is rebound to chat:newline

### Deprecations

- Fixed cancelled prompts being removed from Up-arrow history when auto-restored into the input box, avoiding duplicate entries
- Fixed prompts cancelled with Ctrl+C/Esc before any response being dropped from Up-arrow history
- Fixed early analytics events being silently dropped when fired before logger initialization
- Fixed a race where early OTel spans could be silently dropped in SDK/headless mode with beta tracing enabled

## v2.1.140 (2026-05-12)


### Features

- Improved Agent tool subagent_type matching to accept case- and separator-insensitive values (e.g. "Code Reviewer" resolves to code-reviewer)
- Updated agent color palette
- Fixed Read tool calls failing validation when offset is passed as a whitespace-padded or +-prefixed string

### Deprecations

- Fixed claude --bg failing with "connection dropped mid-request" when the background service was about to idle-exit

## v2.1.139 (2026-05-11)


### Features

- Added agent view (Research Preview): a single list of every Claude Code session — running, blocked on you, or done. Run claude agents to get started. See https://code.claude.com/docs/en/agent-view
- Added /goal command: set a completion condition and Claude keeps working across turns until it's met. Works in interactive, -p, and Remote Control. Shows live elapsed/turns/tokens as an overlay panel
- Added /scroll-speed command to tune mouse wheel scroll speed with a live preview
- Added claude plugin details <name> to show a plugin's component inventory and projected per-session token cost
- Added transcript view navigation: ? for keyboard shortcuts, {/} to jump between user prompts, v to toggle shortcut panel
- Added hook args: string[] field (exec form) that spawns the command directly without a shell, so path placeholders never need quoting
- Added hook continueOnBlock config option for PostToolUse — set to true to feed the hook's rejection reason back to Claude and continue the turn
- MCP stdio servers now receive CLAUDE_PROJECT_DIR in their environment, matching hooks. Plugin configs can reference ${CLAUDE_PROJECT_DIR} in commands
- Compaction prompt now asks the model to preserve sensitive user instructions
- /mcp Reconnect now picks up .mcp.json edits without a restart, and shows the HTTP status and URL when reconnecting fails
- /context all per-skill token estimates now account for the model's tokenizer and show rounded values
- claude plugin install <name>@<marketplace> now auto-refreshes the marketplace and retries before reporting a plugin as not found
- /plugin installed-plugin details now show hook event names and MCP server names cleanly
- /context now shows the providing plugin's name for plugin-sourced skills
- Remote MCP server reconnect retry on transient failures is now enabled for all users
- API requests from subagents now carry x-claude-code-agent-id / x-claude-code-parent-agent-id headers, and claude_code.llm_request OTEL spans include agent_id / parent_agent_id attributes
- Remote Control, /schedule, claude.ai MCP connectors, and notification preferences are now disabled when ANTHROPIC_API_KEY / apiKeyHelper / ANTHROPIC_AUTH_TOKEN is set, even if a Claude.ai login also e

### Breaking Changes

- Fixed skill argument names containing regex metacharacters breaking argument substitution

## v2.1.136 (2026-05-08)


### Features

- Added CLAUDE_CODE_ENABLE_FEEDBACK_SURVEY_FOR_OTEL to re-enable the session quality survey for enterprises capturing responses through OpenTelemetry
- Added settings.autoMode.hard_deny for auto mode classifier rules that block unconditionally regardless of user intent or allow exceptions

### Deprecations

- Fixed pasted text being silently dropped when a long prompt with a pasted-text placeholder was auto-truncated

## v2.1.133 (2026-05-07)


### Features

- Added worktree.baseRef setting (fresh | head) to choose whether --worktree, EnterWorktree, and agent-isolation worktrees branch from origin/<default> or local HEAD. Note: the default fresh changes Ent
- Added sandbox.bwrapPath and sandbox.socatPath managed settings (Linux/WSL) to specify custom bubblewrap and socat binary locations
- Added parentSettingsBehavior admin-tier key ('first-wins' | 'merge') to let admins opt SDK managedSettings (parent tier) into the policy merge
- Hooks now receive the active effort level via the effort.level JSON input field and the $CLAUDE_EFFORT environment variable, and Bash tool commands can read $CLAUDE_EFFORT
- Improved focus mode behavior
- Improved memory usage by releasing warm-spare background workers under memory pressure

### Deprecations

- Fixed /effort in one session unexpectedly changing the effort level of other concurrent sessions, and a related issue where an IDE effort change could be silently dropped

## v2.1.132 (2026-05-06)


### Features

- Added CLAUDE_CODE_SESSION_ID environment variable to the Bash tool subprocess environment, matching the session_id passed to hooks
- Added CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN=1 env var to opt out of the fullscreen alternate-screen renderer and keep the conversation in the terminal's native scrollback
- Added a "Pasting…" footer hint while a Ctrl+V image paste is being read from the clipboard

## v2.1.129 (2026-05-06)


### Features

- Added --plugin-url <url> flag to fetch a plugin .zip archive from a URL for the current session
- Added CLAUDE_CODE_FORCE_SYNC_OUTPUT=1 env var to force-enable synchronized output on terminals that auto-detection misses (e.g. Emacs eat)
- Added CLAUDE_CODE_PACKAGE_MANAGER_AUTO_UPDATE: when set on Homebrew or WinGet installations, Claude Code runs the upgrade command in the background and prompts to restart
- Plugin manifests: themes and monitors should now be declared under "experimental": { ... }. Top-level declarations still work but claude plugin validate will warn
- Gateway /v1/models discovery for the /model picker is now opt-in via CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1 (was automatic in 2.1.126–2.1.128)
- Ctrl+R history picker now defaults to searching all prompts across all projects, matching pre-2.1.124 behavior. Press Ctrl+S to narrow to the current project or session
- Third-party deployments (Bedrock, Vertex, Foundry, or ANTHROPIC_BASE_URL gateway) no longer see spinner tips pointing at first-party Anthropic surfaces
- skillOverrides setting now works: off hides from model and /, user-invocable-only hides from model only, name-only collapses description
- The claude_code.pull_request.count OTel metric now counts PRs/MRs created via MCP tools, not just shell commands
- Fixed /branch success message not including the new branch's session id for /resume

## v2.1.128 (2026-05-04)


### Features

- Bare /color (no args) now picks a random session color
- /mcp now shows the tool count for connected servers and flags servers that connected with 0 tools
- --plugin-dir now accepts .zip plugin archives in addition to directories
- --channels now works with console (API key) authentication — console orgs with managed settings must set channelsEnabled: true to enable
- Updated /model picker: collapsed duplicate Opus 4.7 entries, and current Opus now shows as "Opus" instead of "Opus 4.7"
- Subprocesses (Bash, hooks, MCP, LSP) no longer inherit OTEL_* environment variables, so OTEL-instrumented apps run via the Bash tool no longer pick up the CLI's own OTLP endpoint
- MCP: workspace is now a reserved server name — existing servers with that name will be skipped with a warning
- Fixed focus mode briefly dimming the previous response when submitting a new prompt
- Fixed /plugin update never detecting new versions of npm-sourced plugins

### Deprecations

- EnterWorktree now creates the new branch from local HEAD as documented, instead of origin/<default-branch> — unpushed commits are no longer dropped

## v2.1.126 (2026-05-01)


### Features

- The /model picker now lists models from your gateway's /v1/models endpoint when ANTHROPIC_BASE_URL points at an Anthropic-compatible gateway
- - Added claude project purge [path] to delete all Claude Code state for a project (transcripts, tasks, file history, config entry) — supports --dry-run, -y/--yes, -i/--interactive, and --all
- --dangerously-skip-permissions now bypasses prompts for writes to .claude/, .git/, .vscode/, shell config files, and other previously-protected paths (catastrophic removal commands still prompt as a s
- claude auth login now accepts the OAuth code pasted into the terminal when the browser callback can't reach localhost (WSL2, SSH, containers)
- claude_code.skill_activated OpenTelemetry event now fires for user-typed slash commands and carries a new invocation_trigger attribute ("user-slash", "claude-proactive", or "nested-skill")
- Auto mode: the spinner now turns red when a permission check stalls, instead of looking like the tool is running
- Host-managed deployments (CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST) no longer auto-disable analytics on Bedrock/Vertex/Foundry
- Windows: PowerShell 7 installed via the Microsoft Store, MSI without PATH, or .NET global tool is now detected
- Windows: when the PowerShell tool is enabled, Claude now treats PowerShell as the primary shell instead of defaulting to Bash

### Deprecations

- Read tool: removed the per-file malware-assessment reminder that could cause spurious refusals and "this is not malware" commentary on legacy models
- Fixed pasting an image larger than 2000px breaking the session — images are now downscaled on paste, and oversized images in history are automatically removed and the request retried

## v2.1.122 (2026-04-28)


### Features

- Added ANTHROPIC_BEDROCK_SERVICE_TIER environment variable to select a Bedrock service tier (default, flex, or priority), sent as the X-Amzn-Bedrock-Service-Tier header
- Pasting a PR URL into the /resume search box now finds the session that created that PR (GitHub, GitHub Enterprise, GitLab, and Bitbucket)
- /mcp now shows claude.ai connectors hidden by a manually-added server with the same URL, with a hint to remove the duplicate
- Clarified the /mcp message shown when an MCP server is still unauthorized after the browser sign-in flow
- OpenTelemetry: numeric attributes on api_request/api_error log events are now emitted as numbers, not strings
- OpenTelemetry: added claude_code.at_mention log event for @-mention resolution
- Fixed images sent to newer models being resized to 2576px per side instead of the correct 2000px maximum

## v2.1.121 (2026-04-28)


### Features

- Added alwaysLoad option to MCP server config — when true, all tools from that server skip tool-search deferral and are always available
- Added claude plugin prune to remove orphaned auto-installed plugin dependencies; plugin uninstall --prune cascades
- Added a type-to-filter search box to /skills so you can find a skill in long lists without scrolling
- PostToolUse hooks can now replace tool output for all tools via hookSpecificOutput.updatedToolOutput (previously MCP-only)
- Fullscreen mode: typing into the prompt no longer jumps scroll back to the bottom after you've scrolled up to read earlier output
- Dialogs that overflow the terminal are now scrollable with arrow keys, PgUp/PgDn, home/end, and mouse wheel in both fullscreen and non-fullscreen modes
- Clicking any line of a long URL that wraps across rows in fullscreen mode now opens the full URL
- SDK and claude -p: CLAUDE_CODE_FORK_SUBAGENT=1 now works in non-interactive sessions
- --dangerously-skip-permissions no longer prompts for writes to .claude/skills/, .claude/agents/, and .claude/commands/
- /terminal-setup now enables iTerm2's "Applications in terminal may access clipboard" setting so /copy works, including from tmux
- MCP servers that hit a transient error during startup now auto-retry up to 3 times instead of staying disconnected
- The terminal tab session title is now generated in your configured language setting
- Claude.ai connectors with the same upstream URL are now deduplicated instead of appearing as duplicates
- Vertex AI: support X.509 certificate-based Workload Identity Federation (mTLS ADC)
- OpenTelemetry: added stop_reason, gen_ai.response.finish_reasons, and user_system_prompt (gated behind OTEL_LOG_USER_PROMPTS) to LLM request spans
- [VSCode] Voice dictation now respects the accessibility.voice.speechLanguage setting when no Claude Code language is configured
- [VSCode] /context now opens a native token usage dialog

### Deprecations

- Faster startup after upgrading: removed the Recent Activity panel from the release-notes splash
- LSP diagnostic summaries now expand on click/ctrl+o and show the expand hint
- SDK: mcp_authenticate now supports redirectUri for custom scheme completion and claude.ai connectors

## v2.1.118 (2026-04-23)


### Features

- Added vim visual mode (v) and visual-line mode (V) with selection, operators, and visual feedback
- Merged /cost and /stats into /usage — both remain as typing shortcuts that open the relevant tab
- Create and switch between named custom themes from /theme, or hand-edit JSON files in ~/.claude/themes/; plugins can also ship themes via a themes/ directory
- Hooks can now invoke MCP tools directly via type: "mcp_tool"
- Added DISABLE_UPDATES env var to completely block all update paths including manual claude update — stricter than DISABLE_AUTOUPDATER
- WSL on Windows can now inherit Windows-side managed settings via the wslInheritsWindowsSettings policy key
- Auto mode: include "$defaults" in autoMode.allow, autoMode.soft_deny, or autoMode.environment to add custom rules alongside the built-in list instead of replacing it
- Added a "Don't ask again" option to the auto mode opt-in prompt
- Added claude plugin tag to create release git tags for plugins with version validation
- --continue/--resume now find sessions that added the current directory via /add-dir
- /color now syncs the session accent color to claude.ai/code when Remote Control is connected
- The /model picker now honors ANTHROPIC_DEFAULT_*_MODEL_NAME/_DESCRIPTION overrides when using a custom ANTHROPIC_BASE_URL gateway
- When auto-update skips a plugin due to another plugin's version constraint, the skip now appears in /doctor and the /plugin Errors tab
- Fixed unreadable text in the "new messages" scroll pill and /plugin badges

## v2.1.119 (2026-04-23)


### Features

- /config settings (theme, editor mode, verbose, etc.) now persist to ~/.claude/settings.json and participate in project/local/policy override precedence
- Added prUrlTemplate setting to point the footer PR badge at a custom code-review URL instead of github.com
- Added CLAUDE_CODE_HIDE_CWD environment variable to hide the working directory in the startup logo
- --from-pr now accepts GitLab merge-request, Bitbucket pull-request, and GitHub Enterprise PR URLs
- --print mode now honors the agent's tools: and disallowedTools: frontmatter, matching interactive-mode behavior
- --agent <name> now honors the agent definition's permissionMode for built-in agents
- PowerShell tool commands can now be auto-approved in permission mode, matching Bash behavior
- Hooks: PostToolUse and PostToolUseFailure hook inputs now include duration_ms (tool execution time, excluding permission prompts and PreToolUse hooks)
- Subagent and SDK MCP server reconfiguration now connects servers in parallel instead of serially
- Plugins pinned by another plugin's version constraint now auto-update to the highest satisfying git tag
- Vim mode: Esc in INSERT no longer pulls a queued message back into the input; press Esc again to interrupt
- Slash command suggestions now highlight the characters that matched your query
- Slash command picker now wraps long descriptions onto a second line instead of truncating
- owner/repo#N shorthand links in output now use your git remote's host instead of always pointing at github.com
- Security: blockedMarketplaces now correctly enforces hostPattern and pathPattern entries
- OpenTelemetry: tool_result and tool_decision events now include tool_use_id; tool_result also includes tool_input_size_bytes
- Status line: stdin JSON now includes effort.level and thinking.enabled
- Fixed multi-line paste losing newlines in terminals using kitty keyboard protocol sequences inside bracketed paste

### Deprecations

- Windows: removed false-positive "Windows requires 'cmd /c' wrapper" MCP config warning

## v2.1.117 (2026-04-22)


### Features

- Forked subagents can now be enabled on external builds by setting CLAUDE_CODE_FORK_SUBAGENT=1
- Agent frontmatter mcpServers are now loaded for main-thread agent sessions via --agent
- Improved /model: selections now persist across restarts even when the project pins a different model, and the startup header shows when the active model comes from a project or managed-settings pin
- The /resume command now offers to summarize stale, large sessions before re-reading them, matching the existing --resume behavior
- Faster startup when both local and claude.ai MCP servers are configured (concurrent connect now default)
- plugin install on an already-installed plugin now installs any missing dependencies instead of stopping at "already installed"
- Plugin dependency errors now say "not installed" with an install hint, and claude plugin marketplace add now auto-resolves missing dependencies from configured marketplaces
- Managed-settings blockedMarketplaces and strictKnownMarketplaces are now enforced on plugin install, update, refresh, and autoupdate
- Advisor Tool (experimental): dialog now carries an "experimental" label, learn-more link, and startup notification when enabled; sessions no longer get stuck with "Advisor tool result content could no
- The cleanupPeriodDays retention sweep now also covers ~/.claude/tasks/, ~/.claude/shell-snapshots/, and ~/.claude/backups/
- OpenTelemetry: user_prompt events now include command_name and command_source for slash commands; cost.usage, token.usage, api_request, and api_error now include an effort attribute when the model sup
- Native builds on macOS and Linux: the Glob and Grep tools are replaced by embedded bfs and ugrep available through the Bash tool — faster searches without a separate tool round-trip (Windows and npm-i
- Windows: cached where.exe executable lookups per process for faster subprocess launches
- Default effort for Pro/Max subscribers on Opus 4.6 and Sonnet 4.6 is now high (was medium)

### Breaking Changes

- [VSCode] Fixed "Manage Plugins" panel breaking when multiple large marketplaces are configured

## v2.1.116 (2026-04-20)


### Features

- /resume on large sessions is significantly faster (up to 67% on 40MB+ sessions) and handles sessions with many dead-fork entries more efficiently
- Faster MCP startup when multiple stdio servers are configured; resources/templates/list is now deferred to first @-mention
- Smoother fullscreen scrolling in VS Code, Cursor, and Windsurf terminals — /terminal-setup now configures the editor's scroll sensitivity
- Thinking spinner now shows progress inline ("still thinking", "thinking more", "almost done thinking"), replacing the separate hint row
- /config search now matches option values (e.g. searching "vim" finds the Editor mode setting)
- /doctor can now be opened while Claude is responding, without waiting for the current turn to finish
- /reload-plugins and background plugin auto-update now auto-install missing plugin dependencies from marketplaces you've already added
- Bash tool now surfaces a hint when gh commands hit GitHub's API rate limit, so agents can back off instead of retrying
- The Usage tab in Settings now shows your 5-hour and weekly usage immediately and no longer fails when the usage endpoint is rate-limited
- Agent frontmatter hooks: now fire when running as a main-thread agent via --agent
- Slash command menu now shows "No commands match" when your filter has zero results, instead of disappearing
- Security: sandbox auto-allow no longer bypasses the dangerous-path safety check for rm/rmdir targeting /, $HOME, or other critical system directories

## v2.1.113 (2026-04-17)


### Features

- Changed the CLI to spawn a native Claude Code binary (via a per-platform optional dependency) instead of bundled JavaScript
- Added sandbox.network.deniedDomains setting to block specific domains even when a broader allowedDomains wildcard would otherwise permit them
- Fullscreen mode: Shift+↑/↓ now scrolls the viewport when extending a selection past the visible edge
- Ctrl+A and Ctrl+E now move to the start/end of the current logical line in multiline input, matching readline behavior
- Windows: Ctrl+Backspace now deletes the previous word
- Long URLs in responses and bash output stay clickable when they wrap across lines (in terminals with OSC 8 hyperlinks)
- Improved /loop: pressing Esc now cancels pending wakeups, and wakeups display as "Claude resuming /loop wakeup" for clarity
- /extra-usage now works from Remote Control (mobile/web) clients
- Remote Control clients can now query @-file autocomplete suggestions
- Improved /ultrareview: faster launch with parallelized checks, diffstat in the launch dialog, and animated launching state
- Subagents that stall mid-stream now fail with a clear error after 10 minutes instead of hanging silently
- Bash tool: multi-line commands whose first line is a comment now show the full command in the transcript, closing a UI-spoofing vector
- Running cd <current-directory> && git … no longer triggers a permission prompt when the cd is a no-op
- Security: on macOS, /private/{etc,var,tmp,home} paths are now treated as dangerous removal targets under Bash(rm:*) allow rules
- Security: Bash deny rules now match commands wrapped in env/sudo/watch/ionice/setsid and similar exec wrappers
- Security: Bash(find:*) allow rules no longer auto-approve find -exec/-delete

### Breaking Changes

- Fixed markdown tables breaking when a cell contains an inline code span with a pipe character

## v2.1.111 (2026-04-16)


### Features

- Claude Opus 4.7 xhigh is now available! Use /effort to tune speed vs. intelligence
- Auto mode is now available for Max subscribers when using Opus 4.7
- Added xhigh effort level for Opus 4.7, sitting between high and max. Available via /effort, --effort, and the model picker; other models fall back to high
- /effort now opens an interactive slider when called without arguments, with arrow-key navigation between levels and Enter to confirm
- Added "Auto (match terminal)" theme option that matches your terminal's dark/light mode — select it from /theme
- Added /less-permission-prompts skill — scans transcripts for common read-only Bash and MCP tool calls and proposes a prioritized allowlist for .claude/settings.json
- Added /ultrareview for running comprehensive code review in the cloud using parallel multi-agent analysis and critique — invoke with no arguments to review your current branch, or /ultrareview <PR#> t
- Auto mode no longer requires --enable-auto-mode
- Windows: PowerShell tool is progressively rolling out. Opt in or out with CLAUDE_CODE_USE_POWERSHELL_TOOL. On Linux and macOS, enable with CLAUDE_CODE_USE_POWERSHELL_TOOL=1 (requires pwsh on PATH)
- Read-only bash commands with glob patterns (e.g. ls *.ts) and commands starting with cd <project-dir> && no longer trigger a permission prompt
- Suggest the closest matching subcommand when claude <word> is invoked with a near-miss typo (e.g. claude udpate → "Did you mean claude update?")
- Added OTEL_LOG_RAW_API_BODIES environment variable to emit full API request and response bodies as OpenTelemetry log events for debugging
- Suppressed spurious decompression, network, and transient error messages that could appear in the TUI during normal operation
- Reverted the v2.1.110 cap on non-streaming fallback retries — it traded long waits for more outright failures during API overload

## v2.1.110 (2026-04-15)


### Features

- Added /tui command and tui setting — run /tui fullscreen to switch to flicker-free rendering in the same conversation
- Changed Ctrl+O to toggle between normal and verbose transcript only; focus view is now toggled separately with the new /focus command
- Added push notification tool — Claude can send mobile push notifications when Remote Control and "Push when Claude decides" config are enabled
- Added autoScrollEnabled config to disable conversation auto-scroll in fullscreen mode
- Added option to show Claude's last response as commented context in the Ctrl+G external editor (enable via /config)
- Improved /plugin Installed tab — items needing attention and favorites appear at the top, disabled items are hidden behind a fold, and f favorites the selected item
- Improved /doctor to warn when an MCP server is defined in multiple config scopes with different endpoints
- --resume/--continue now resurrects unexpired scheduled tasks
- /autocompact, /context, /exit, and /reload-plugins now work from Remote Control (mobile/web) clients
- Write tool now informs the model when you edit the proposed content in the IDE diff before accepting
- Bash tool now enforces the documented maximum timeout instead of accepting arbitrarily large values
- SDK/headless sessions now read TRACEPARENT/TRACESTATE from the environment for distributed trace linking
- Session recap is now enabled for users with telemetry disabled (Bedrock, Vertex, Foundry, DISABLE_TELEMETRY). Opt out via /config or CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0.

### Deprecations

- Fixed dropped keystrokes after the CLI relaunches (e.g. /tui, provider setup wizards)
- Fixed PreToolUse hook additionalContext being dropped when the tool call fails

## v2.1.109 (2026-04-15)


### Features

- Improved the extended-thinking indicator with a rotating progress hint

## v2.1.108 (2026-04-14)


### Features

- Added recap feature to provide context when returning to a session, configurable in /config and manually invocable with /recap; force with CLAUDE_CODE_ENABLE_AWAY_SUMMARY if telemetry disabled.
- The model can now discover and invoke built-in slash commands like /init, /review, and /security-review via the Skill tool
- /undo is now an alias for /rewind
- Improved /model to warn before switching models mid-conversation, since the next response re-reads the full history uncached
- Improved /resume picker to default to sessions from the current directory; press Ctrl+A to show all projects
- Improved error messages: server rate limits are now distinguished from plan usage limits; 5xx/529 errors show a link to status.claude.com; unknown slash commands suggest the closest match
- Reduced memory footprint for file reads, edits, and syntax highlighting by loading language grammars on demand
- Added "verbose" indicator when viewing the detailed transcript (Ctrl+O)
- Added a warning at startup when prompt caching is disabled via DISABLE_PROMPT_CACHING* environment variables

### Deprecations

- Added ENABLE_PROMPT_CACHING_1H env var to opt into 1-hour prompt cache TTL on API key, Bedrock, Vertex, and Foundry (ENABLE_PROMPT_CACHING_1H_BEDROCK is deprecated but still honored), and FORCE_PROMPT
- Fixed transcript write failures (e.g., disk full) being silently dropped instead of being logged
- Fixed diacritical marks (accents, umlauts, cedillas) being dropped from responses when the language setting is configured

## v2.1.107 (2026-04-14)


### Features

- Show thinking hints sooner during long operations

## v2.1.105 (2026-04-13)


### Features

- Added path parameter to the EnterWorktree tool to switch into an existing worktree of the current repository
- Added PreCompact hook support: hooks can now block compaction by exiting with code 2 or returning {"decision":"block"}
- Added background monitor support for plugins via a top-level monitors manifest key that auto-arms at session start or on skill invoke
- /proactive is now an alias for /loop
- Improved stalled API stream handling: streams now abort after 5 minutes of no data and retry non-streaming instead of hanging indefinitely
- Improved network error messages: connection errors now show a retry message immediately instead of a silent spinner
- Improved file write display: long single-line writes (e.g. minified JSON) are now truncated in the UI instead of paginating across many screens
- Improved skill description handling: raised the listing cap from 250 to 1,536 characters and added a startup warning when descriptions are truncated
- Improved WebFetch to strip <style> and <script> contents from fetched pages so CSS-heavy pages no longer exhaust the content budget before reaching actual text
- Improved stale agent worktree cleanup to remove worktrees whose PR was squash-merged instead of keeping them indefinitely
- Improved MCP large-output truncation prompt to give format-specific recipes (e.g. jq for JSON, computed Read chunk sizes for text)
- Fixed alt+enter not inserting a newline in terminals using ESC-prefix alt encoding, and Ctrl+J not inserting a newline (regression in 2.1.100)

### Deprecations

- Fixed images attached to queued messages (sent while Claude is working) being dropped
- Fixed inbound channel notifications being silently dropped after the first message for Team/Enterprise users

### Breaking Changes

- Fixed leading whitespace being trimmed from assistant messages, breaking ASCII art and indented diagrams

## v2.1.96 (2026-04-08)


### Features

- Fixed Bedrock auth 403 'Authorization header is missing' regression from 2.1.94 when using AWS_BEARER_TOKEN_BEDROCK or CLAUDE_CODE_SKIP_BEDROCK_AUTH

## v2.1.94 (2026-04-07)


### Features

- Added Amazon Bedrock support via Mantle — set CLAUDE_CODE_USE_MANTLE=1 to enable
- Default effort level increased from medium to high for API-key, Bedrock/Vertex/Foundry, Team, and Enterprise users
- Plugin skill invocation names now use frontmatter name field for stability across install methods
- Added keep-coding-instructions frontmatter field for plugin output styles
- Added hookSpecificOutput.sessionTitle to UserPromptSubmit hooks for customizing session titles
- Slack MCP compact channel headers
- Write tool diff computation 60% faster
- Fixed 429 rate-limit handling that caused agents to appear stuck with long Retry-After headers
- Fixed Console login on macOS silently failing with locked keychains
- Fixed YAML frontmatter skill hooks being silently ignored
- Fixed Shift+Space inserting literal 'space' instead of space character
- Fixed hyperlinks opening two tabs in tmux/xterm.js terminals
- Fixed alt-screen rendering bugs with content height changes
- Fixed FORCE_HYPERLINK environment variable being ignored
- Fixed CJK and multibyte text corruption in stream-json processing
- Improved ${CLAUDE_PLUGIN_ROOT} resolution for local-marketplace plugins
- Reduced cold-open subprocess work in VSCode integration

### Deprecations

- Removed /tag command
- Removed /vim command — toggle vim mode via /config → Editor mode

### Breaking Changes

- Default effort level changed from medium to high for API-key, Bedrock/Vertex/Foundry, Team, and Enterprise users — use /effort to adjust

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
