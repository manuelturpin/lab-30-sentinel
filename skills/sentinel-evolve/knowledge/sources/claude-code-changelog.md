# Claude Code Changelog — Feature Intelligence

Auto-generated from GitHub releases for RAG indexing.


## v2.1.220 (2026-07-25)


### Features

- Bug fixes and reliability improvements

## v2.1.219 (2026-07-24)


### Features

- Added Claude Opus 5 (claude-opus-5), now the default Opus model — 1M context, fast mode at $10/$50 per Mtok
- Added sandbox.network.strictAllowlist setting to deny non-allowlisted hosts for sandboxed commands without prompting
- Added DirectoryAdded hook that fires after /add-dir or the SDK register_repo_root control request registers a new working directory mid-session
- Added mcp_server_errors to the headless stream-json init event, listing --mcp-config entries skipped by config validation; terminal runs print a startup warning
- Added the workflowSizeGuideline settings key so the advisory Dynamic workflow size guideline can be set from any settings file; the /config row is hidden while one does
- Added nested subagent forwarding in stream-json: subagents spawned at depth-2+ now appear when --forward-subagent-text is set, keyed by their spawning Agent tool_use id
- Added HTTP status and error text to claude mcp list and /mcp when a server fails to connect, and a warning for MCP config values with hidden leading or trailing whitespace
- Added structured failure categories to self-hosted runner spawn and session failures, so hook errors, runner crashes and config errors can be told apart
- Changed the /model picker to highlight only the newest model's name, so the highlight marks the new release rather than an arbitrary subset of the list
- Added the current default workflow size to the running-workflow status line, with a pointer to /config for changing it

### Deprecations

- Fixed a permission you approved while a self-hosted runner was restarting being dropped when the session resumed, so the approved action now runs
- Removed Opus 4.7 from fast mode; /fast now applies to Opus 5 and Opus 4.8

### Breaking Changes

- Updated the claude-api skill to default to Claude Opus 5, with a migration path from Opus 4.8
- Subagents can now spawn nested subagents up to depth 3 by default (was 1); set CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH=1 to disable nesting

## v2.1.218 (2026-07-22)


### Features

- Changed /code-review to run as a background subagent, so review work no longer fills your conversation and keeps stacked slash commands as its review target
- Added screen-reader announcements of deleted text for word and line deletions (Option+Delete, Ctrl+W, Cmd+Backspace, Ctrl+U, Ctrl+K) in --ax-screen-reader mode
- Added HTTP status and error text to claude mcp list and /mcp when a server fails to connect, and a warning for MCP config values with hidden leading or trailing whitespace
- Fixed multi-line paste collapsing into one line with j in place of newlines in terminals that encode pasted newlines as Ctrl+J
- Fixed VoiceOver reading "new line" instead of echoing the typed space at the end of the input in --ax-screen-reader mode
- Added an announcement when fast mode changes as a result of switching models via /config model=<x> or Remote Control
- Changed server-managed settings so benign feature and cost toggles no longer trigger the settings-approval prompt
- Changed agent markdown files to reject agent names containing :, which is reserved for plugin namespacing
- Changed skills with context: fork to run in the background by default; opt out per skill with background: false
- Added yes/no/on/off/1/0 (case-insensitive) as accepted values for skill and plugin frontmatter booleans, alongside true/false

### Deprecations

- Fixed mojibake when a long IDE selection was truncated mid-emoji, and a case where a tool executor error could be silently dropped
- Fixed prompt history entries being dropped or duplicated when history writes raced or failed

## v2.1.217 (2026-07-21)


### Features

- Added emoji shortcode autocomplete in the prompt input: type :heart: to insert ❤️, or :hea for suggestions — disable with the emojiCompletionEnabled setting
- Added warnings when transcript writes are failing (e.g. disk full) or when session saving is off due to an inherited environment variable, instead of losing transcripts silently
- Added a cap on concurrently-running subagents (default 20, override with CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS) so one message can't fan out unbounded background agents
- Changed subagents to no longer spawn nested subagents by default; set CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH to allow deeper nesting
- Fixed --max-budget-usd not stopping background subagents: once the cap is reached, new spawns are denied and running background agents are halted

## v2.1.216 (2026-07-20)


### Features

- Added sandbox.filesystem.disabled setting to skip filesystem isolation while keeping network egress control
- Fixed MCP re-authenticate revoking working credentials before the new sign-in succeeds, and the reconnect needs-auth message in background sessions pointing at an unusable command
- Improved the /fork confirmation to one line with the new session's name, claude attach id, and a note when the copy shares your checkout
- Improved validation of git and gh command arguments in the PowerShell tool
- Improved the /ultrareview diff-too-large error to show configured limits, measured diff size, and largest contributing files
- Improved /code-review ultra empty-diff message to name the exact base ref and suggest passing an explicit base
- Improved the spend limit adjustment prompt to show the server's reason when a spend limit change is rejected
- /context now shows an explicit warning when the conversation exceeds the context window, and a failed /compact displays as an error
- /rewind no longer restores or deletes files through symlinks or hard links at tracked paths and reports how many paths it skipped
- Background sessions: /mcp and /install-github-app now park a "needs input" request in the agent view when no client is attached

## v2.1.215 (2026-07-19)


### Features

- Claude no longer runs the /verify and /code-review skills on its own; invoke them with /verify or /code-review when you want them

## v2.1.214 (2026-07-18)


### Features

- Added the EndConversation tool: Claude can end sessions with highly abusive users or jailbreak attempts, as on claude.ai since 2025 — see https://www.anthropic.com/research/end-subset-conversations
- Added a periodic progress heartbeat for long-running tool calls that previously went silent
- Added an ISO modified timestamp to memory file frontmatter
- Added message.uuid, client_request_id, and tool_source attributes to OpenTelemetry log events for message-level correlation and tool provenance
- Added CLAUDE_CODE_OTEL_CONTENT_MAX_LENGTH to configure the 60 KB truncation limit on OpenTelemetry content attributes
- Added reasoning effort to the subagentStatusLine payload, so custom agent rows can render model and effort
- Added permission prompts for docker commands (including the Podman docker shim) carrying daemon-redirect flags (--url, --connection, --identity, and Podman's remote mode) that previously ran without o
- Fixed a crash when a GrowthBook feature evaluates to null, and a bug where a malformed flag payload could wipe the cached feature flags
- Fixed feature flags going stale in long-running sessions after the OAuth token rotates

## v2.1.212 (2026-07-17)


### Features

- /fork now copies your conversation into a new background session (its own row in claude agents) while you keep working; the in-session subagent it used to launch is now /subtask
- Added claude auto-mode reset to restore the default auto-mode configuration, with a confirmation prompt (pass --yes to skip)
- Added a session-wide limit on WebSearch tool calls (default 200, tunable via CLAUDE_CODE_MAX_WEB_SEARCHES_PER_SESSION) to stop runaway search loops
- Added a per-session cap on subagent spawns (default 200, override with CLAUDE_CODE_MAX_SUBAGENTS_PER_SESSION) to stop runaway delegation loops; /clear resets the budget
- MCP tool calls running longer than 2 minutes now move to the background automatically so the session stays usable; configure the threshold or disable with CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS
- Typing /resume in the agent view now opens a picker of past sessions — including sessions deleted from the list — and resumes your pick as a background session
- Fixed Ctrl+J not inserting a newline in the agent view dispatch input on terminals with extended key reporting, and surfaced the newline shortcut in the ? help overlay
- Fixed /ultrareview skipping the billing confirmation in a new conversation after /clear
- Changed headless/SDK sessions to apply a set_model control request mid-turn; the next model round-trip uses the new model instead of waiting for the next turn
- Changed agent view / claude agents --json: sessions waiting on a sandbox, MCP-input, or managed-settings prompt now show as "Needs input" instead of "Working"
- Updated the auth status panel title from "Cloud authentication" to "Authentication"
- Corrected an earlier release note (2.1.200): tmux through the 3.6 series lacks synchronized output; newer tmux with support is detected automatically

### Deprecations

- Fixed a continue:false hook's halt being dropped when the tool fails or completes mid-stream, and hook infrastructure errors being misreported as user rejections
- Deprecated the Task tool's mode parameter (now ignored); subagents inherit the parent session's permission mode by default
- Changed Enterprise forceLoginMethod to be enforced for VS Code extension, SDK, setup-token, and install-github-app logins, not just the terminal
- Changed session transcripts to record the reasoning effort level on each assistant message

## v2.1.211 (2026-07-15)


### Features

- Added --forward-subagent-text flag and CLAUDE_CODE_FORWARD_SUBAGENT_TEXT environment variable to include subagent text and thinking in stream-json output

## v2.1.210 (2026-07-14)


### Features

- Added a live elapsed-time counter to the collapsed tool summary line so long-running tool calls visibly tick instead of looking stuck
- Added a startup warning for Write(path), NotebookEdit(path), and Glob(path) permission rules — use Edit(path) or Read(path) instead

### Deprecations

- Fixed claude agents --effort ultracode not reaching dispatched sessions; the value was silently dropped

## v2.1.208 (2026-07-14)


### Features

- Added screen reader mode: opt-in plain-text rendering for screen reader users. Run claude --ax-screen-reader, set CLAUDE_AX_SCREEN_READER=1, or add "axScreenReader": true to settings.
- Added vimInsertModeRemaps setting: map two-key insert-mode sequences like jj to Escape in vim mode
- Added CLAUDE_CODE_PROCESS_WRAPPER: agent view and the background service now honor a corporate launcher by running every Claude Code self-spawn through a required wrapper executable
- Added mouse-click support for multi-select menus and "Other" input rows in fullscreen mode
- Background sessions: an older daemon no longer silently restarts workers spawned by a newer version onto the older binary
- Agent view: Ctrl+X now deletes renamed-branch worktrees, never destroys unpushed commits, keeps the session row when a worktree is kept, and reused worktree names reset to the current base
- Catastrophic removals (e.g. rm -rf ~) in commands containing $(…)/backticks/<(…) now prompt in --dangerously-skip-permissions and auto mode, matching the plain form
- /install-github-app and the /mcp settings menu no longer open in background sessions
- MCP servers configured with an empty URL now show as "not configured" in /mcp instead of a config error
- /usage now shows your last-known usage bars with an "as of" note when the usage endpoint is rate-limited, instead of an error screen

## v2.1.207 (2026-07-11)


### Features

- Auto mode is now available without CLAUDE_CODE_ENABLE_AUTO_MODE opt-in on Bedrock, Vertex AI, and Foundry; disable via disableAutoMode in settings

### Deprecations

- Fixed extensions.worktreeConfig being left in the repo's .git/config (breaking go-git tools like tea) after the last worktree.sparsePaths worktree was removed

### Breaking Changes

- Fixed malformed bracket patterns in rules globs, skill paths, .ignore, and .worktreeinclude breaking file reads, file suggestions, and worktree creation

## v2.1.206 (2026-07-10)


### Features

- Added directory path suggestions to /cd, matching /add-dir behavior
- Added a /doctor check that proposes trimming checked-in CLAUDE.md files by cutting content Claude could derive from the codebase
- /commit-push-pr now auto-allows git push to the repo's configured push remote (remote.pushDefault, or the sole remote when only one is configured) in addition to origin
- Gateway: /login now supports Anthropic-operated public gateway endpoints
- EnterWorktree now asks for confirmation before entering a git worktree outside the project's .claude/worktrees/ directory
- Background agents now upgrade to a new version in the background right after a Claude Code update, instead of paying a slow stale-session upgrade when you attach

### Deprecations

- Fixed claude rm leaving the removed job in the daemon roster, causing the row to reappear in claude agents

## v2.1.205 (2026-07-08)


### Features

- Added an auto mode rule that blocks tampering with session transcript files

## v2.1.203 (2026-07-07)


### Features

- Added a warning when your login is about to expire, so you can re-authenticate before background sessions are interrupted
- Added a grey ⏸ badge to the footer when in manual permission mode, making the active mode always visible
- Added the session's additional working directories to MCP roots/list, with notifications/roots/list_changed sent when the set changes
- [VSCode] Added a Settings toggle for "Enable Remote Control for all sessions"

### Deprecations

- Removed the startup "claude command missing or broken" warnings — they now appear in /doctor and /status instead
- Removed a redundant navigation hint from the claude agents footer

## v2.1.202 (2026-07-06)


### Features

- Added a "Dynamic workflow size" setting in /config for controlling how large Claude generally makes dynamic workflows (small/medium/large agent counts) — an advisory guideline, not an enforced cap
- Added workflow.run_id and workflow.name OpenTelemetry attributes to telemetry emitted by workflow-spawned agents, so a workflow run's activity can be reconstructed from OTel data
- Fixed /rename on background sessions being reverted when the job restarts, which broke addressing the session by its new name

### Deprecations

- Fixed images and files sent from the Remote Control mobile or web app without a caption being silently dropped

## v2.1.201 (2026-07-03)


### Features

- Claude Sonnet 5 sessions no longer use the mid-conversation system role for harness reminders

## v2.1.200 (2026-07-03)


### Features

- Changed AskUserQuestion dialogs to no longer auto-continue by default; opt into an idle timeout via /config
- Changed the "default" permission mode to "Manual" across the CLI, --help, VS Code, and JetBrains; --permission-mode manual and "defaultMode": "manual" are accepted alongside default
- Fixed background-agent roster issues: transient corruption permanently disabling orphan cleanup, older binaries not preserving fields written by newer versions, and socket auth tokens being stripped d

## v2.1.199 (2026-07-02)


### Features

- Stacked slash-skill invocations like /skill-a /skill-b do XYZ now load all leading skills (up to 5), not just the first
- Fixed opening or resuming a session with no new messages needlessly growing the transcript file

## v2.1.198 (2026-07-01)


### Features

- Subagents now run in the background by default, so Claude keeps working while they run and is notified when they finish (previously a gradual rollout)
- Claude in Chrome is now generally available
- Added background agent notifications in claude agents — sessions that need input or finish now fire the Notification hook (agent_needs_input / agent_completed)
- Added /dataviz skill for chart and dashboard design guidance with a runnable color-palette validator
- Gateway: added Claude Platform on AWS (anthropicAws) as an upstream provider; model-not-found responses now advance the failover chain
- Background agents launched from claude agents now commit, push, and open a draft PR when they finish code work in a worktree, instead of stopping to ask
- The built-in Explore agent now inherits the main session's model (capped at opus) instead of running on haiku
- Subagents and context compaction now inherit the session's extended thinking configuration, improving output quality on delegated tasks

### Deprecations

- Removed the /agents wizard; ask Claude to create or manage subagents, or edit .claude/agents/ directly

## v2.1.197 (2026-06-30)


### Features

- Introducing Claude Sonnet 5: now the default model in Claude Code, with a native 1M-token context window and promotional pricing of $2/$10 per Mtok through August 31. Update to version 2.1.197 for acc

## v2.1.196 (2026-06-29)


### Features

- Added support for organization default models — admins set it in the org console; it shows as "Org default" (or "Role default") in /model when you haven't picked one yourself
- Added readable default names for sessions at start, making them easier to identify and message
- Added clickable file attachments in chat — Cmd/Ctrl-click reveals the file in Finder/Explorer
- Security: claude mcp list/get no longer spawn .mcp.json servers that a repo self-approved via a committed .claude/settings.json; untrusted workspaces show ⏸ Pending approval
- Fixed plugin dependency version pins not being honored when the marketplace was added as a local folder path backed by a git repo

## v2.1.195 (2026-06-26)


### Features

- Added CLAUDE_CODE_DISABLE_MOUSE_CLICKS to disable mouse click/drag/hover in fullscreen mode while keeping wheel scroll
- Fixed background jobs disappearing from claude agents or losing data when written by a newer Claude Code version

## v2.1.193 (2026-06-25)


### Features

- Added autoMode.classifyAllShell setting to route all Bash/PowerShell commands through the auto-mode classifier instead of only arbitrary-code-execution patterns
- Added auto-mode denial reasons to the transcript, the denial toast, and /permissions recent denials
- Added claude_code.assistant_response OpenTelemetry log event containing the model's response text. Redacted unless OTEL_LOG_ASSISTANT_RESPONSES=1; when that var is unset it follows OTEL_LOG_USER_PROMP
- Added live file path autocomplete to bash mode (!)
- Added a startup notice when MCP servers need authentication, pointing at /mcp
- Added automatic memory-pressure reaping for idle background shell commands (disable with CLAUDE_CODE_DISABLE_BG_SHELL_PRESSURE_REAP=1)
- Fixed backgrounding (←←) spuriously cancelling with "N background tasks would be abandoned" when all running tasks carry over to the new session
- Improved plugin auto-rename: marketplace renames maps are now followed automatically, updating your settings to the new name
- Improved /add-dir message when the directory is already a working directory

## v2.1.191 (2026-06-24)


### Features

- Added /rewind support for resuming a conversation from before /clear was run

## v2.1.190 (2026-06-24)


### Features

- Bug fixes and reliability improvements

## v2.1.187 (2026-06-23)


### Features

- Added sandbox.credentials setting to block sandboxed commands from reading credential files and secret environment variables
- Added org-configured model restrictions to the model picker, --model, /model, and ANTHROPIC_MODEL, with a "restricted by your organization's settings" message when a restricted model is selected
- Added mouse click support to select menus (permission prompts, /model, /config, etc.) in fullscreen mode
- Fixed Claude Code Remote sessions taking ~2.7s longer to start after the agent proxy CA system-trust install was added

## v2.1.186 (2026-06-22)


### Features

- Added claude mcp login <name> and claude mcp logout <name> to authenticate MCP servers from the CLI without opening the interactive /mcp menu, with --no-browser stdin redirect support for completing o
- Added status filtering (press f) to the /workflows agent detail view
- Added a "Skills" section to the /plugin Installed tab
- Added teammateMode: "iterm2" setting with a warning when auto mode cannot find the it2 CLI
- Added "Claude Platform on AWS - refresh credentials" option to /login when awsAuthRefresh is configured
- ! bash commands now trigger Claude to respond to the output automatically; set "respondToBashCommands": false in settings.json to keep the previous context-only behavior
- Fixed --tools allowing feature-gated tools to slip through before flags loaded on a cold first launch

## v2.1.185 (2026-06-20)


### Features

- The stream-stall hint now reads "Waiting for API response · will retry in …" instead of "No response from API · Retrying in …", and triggers after 20s of silence instead of 10s

## v2.1.183 (2026-06-19)


### Features

- Improved auto mode safety: destructive git commands (git reset --hard, git checkout -- ., git clean -fd, git stash drop) are now blocked when you didn't ask to discard local work, git commit --amend i
- Added attribution.sessionUrl setting to omit the claude.ai session link from commits and PRs in web and Remote Control sessions
- Added /config --help to list all available shorthand keys for /config key=value
- Changed /config toggle behavior: Enter and Space both change the selected setting, and Esc now saves and closes instead of reverting
- Fixed tmux teammate panes failing to launch when the shell has slow rc-file initialization, and keystrokes typed during agent spawn leaking into the new tmux pane instead of the leader prompt

### Deprecations

- Added a warning when the requested model is deprecated or automatically updated to a newer model, shown on stderr in print mode (-p) and now also covering models set in agent frontmatter
- Removed the startup "setup issues" line under the logo — run /doctor to see configuration issues or use --debug

## v2.1.181 (2026-06-17)


### Features

- Added /config key=value syntax to set any setting from the prompt (e.g. /config thinking=false) — works in interactive, -p, and Remote Control
- Added sandbox.allowAppleEvents opt-in setting that lets sandboxed commands send Apple Events on macOS
- Added CLAUDE_CLIENT_PRESENCE_FILE environment variable: point it at a marker file to suppress mobile push notifications while you're at the machine
- Upgraded the bundled Bun runtime to 1.4
- Improved streaming of long paragraphs: text now appears line-by-line instead of waiting for the first line break
- Improved auto-retry: API connection drops mid-thinking now automatically retry instead of showing "Connection closed while thinking"
- Improved the subagent panel: idle subagents auto-hide after 30s, the list caps at 5 rows with scroll hints, and keyboard hints now show in the footer
- Improved the MCP OAuth browser page to match Claude Code's visual style and auto-close on success
- Changed fullscreen mode URL opening to require Cmd+click (macOS) / Ctrl+click, matching native terminal behavior
- Changed the Improved N memories line to no longer list individual files outside verbose mode

## v2.1.178 (2026-06-15)


### Features

- Added Tool(param:value) syntax for permission rules to match a tool's input parameters (with * wildcard), e.g. Agent(model:opus) to block Opus subagents
- Skills in nested .claude/skills directories now load when working on files there; on a name clash, the nested skill appears as <dir>:<name> so both stay available
- Nested .claude/ directories: the agent, workflow, and output-style closest to the working directory now wins when names collide; project-scope workflow saves now target the closest existing .claude/wo
- Improved auto mode: subagent spawns are now evaluated by the classifier before launch, closing a gap where a subagent could request a blocked action without review
- Improved /doctor with consistent flat tree layout across all sections, clearer section status icons, and highlighted command names
- Improved the skill listing truncation warning to show how many skill descriptions are affected
- Changed the workflow prompt keyword to use a purple shimmer highlight and trigger only on explicit phrases like "run a workflow" or "workflow:", not on any mention of the word
- Improved Remote Control error messages: connection failures now show a persistent red "/rc failed" indicator in the footer, and the "not yet enabled" error now explains whether it's a gate, a check fa

### Deprecations

- Fixed several subagent issues: viewing a subagent's transcript now shows tool results and live progress, messages sent while it finishes its turn are no longer dropped, and backgrounding a running sub

## v2.1.176 (2026-06-12)


### Features

- Session titles are now generated in the language of your conversation (set the language setting to pin a specific language)
- Added footerLinksRegexes setting for regex-matched link badges in the footer row, configurable via user or managed settings

## v2.1.175 (2026-06-12)


### Features

- Added enforceAvailableModels managed setting — when enabled, the availableModels allowlist also constrains the Default model (a Default that would resolve to a disallowed model now falls back to the f

## v2.1.174 (2026-06-12)


### Features

- Added wheelScrollAccelerationEnabled setting to disable mouse-wheel scroll acceleration in fullscreen mode
- [VSCode] Added usage attribution to the Account & usage dialog (/usage) showing cache misses, long context, subagents, and per-skill/agent/plugin/MCP breakdowns over the last 24h or 7d

## v2.1.172 (2026-06-10)


### Features

- Sub-agents can now spawn their own sub-agents (up to 5 levels deep)
- Amazon Bedrock now reads the AWS region from ~/.aws config files when AWS_REGION isn't set, matching AWS SDK precedence; /status shows where the region came from
- Added a search bar when browsing a marketplace's plugins in /plugin
- Added model attribute to the claude_code.lines_of_code.count OTEL metric
- Improved the non-interactive Usage Policy refusal message to suggest starting a new session or changing your model
- /code-review now keeps the ultra option visible when you're not signed in to claude.ai, with an explanation that the cloud review requires a claude.ai account
- Shortened the Remote Control footer indicator to "/rc active" and hid it on narrow terminals
- Stopped promoting /loop in remote sessions, where pending loops don't keep the container alive

### Deprecations

- Fixed a repeating "an image in the conversation could not be processed and was removed" error when the conversation contained multiple images

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
