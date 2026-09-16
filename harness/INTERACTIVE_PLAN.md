# Interactive Codex onboarding and acceptance

Status: implementation and acceptance in progress, September 16, 2026. All implementation, builds, model calls,
security probes and terminal acceptance run in a new directory on Algol 2-1.
The paper and historical experiment evidence remain unchanged.

## Goal and user contract

Install once, run ptw codex in a new or existing repository, describe the intended
work, review the proposed project/task policy and escalation, then use the real
Codex terminal interface. Subsequent launches reuse the approved project and
shared history. No JSON editing, copying approval hashes or separate monitor
terminal should be required for the ordinary path. Stop/status remain available.
Thirty seconds is a target for repeat-start/operator effort, not a promise about
downloads, model latency, building packages or complex policy review.

## Minimal design

1. A trusted launcher detects project metadata, proposes candidate test/build
   commands without executing repository code, gathers intended scope and explicit
   warn/stop thresholds, calls the existing typed proposer, and displays a compact
   review. Only operator confirmation activates the exact reviewed bundle.
2. A repository policy copy is readable/versionable; the active approval, controller
   state, session credentials and launch configuration stay outside model-writable
   resources. Repository edits cannot silently activate policy changes. Historical
   logs are optional untrusted evidence, never authority.
3. Real Codex CLI uses a small local MCP adapter over the existing deterministic
   dispatch. Native uncontrolled shell, tools, plugins, search and
   unregistered delegation are unavailable. A deny filesystem profile is additional
   protection, not the sole control. The model never receives controller tokens.
   Codex 0.154.0's bundled isolated V8 host is required to dispatch MCP calls;
   it provides registered tools, not Node, filesystem or network APIs.
4. File/command/package effects reuse the existing broker and confined executor.
   Linux hides host resources, controller state and credentials from executed code.
   There is no unrestricted network or direct host write fallback. Codex's trusted
   client retains its own normal login; workload code does not inherit it.
5. Every independent session and delegate is bound by the launcher/controller to
   the same project identity before work starts. Task and child scopes only narrow.
   Project counters persist across restart. Supervised terminal processes and their
   descendants stop together; unrelated projects continue.
6. MCP is a transport, not an optional safety check. Stale monitoring, missing
   controls, an incompatible CLI or an uncertain launch must block execution.
   Test the pinned CLI's actual enabled routes before claiming protected operation.
   Hooks alone are insufficient and are not the enforcement boundary.

Reuse JSON Schema, SQLite, systemd, nono/bubblewrap, uv/npm and package evidence
checks. Prefer an existing MCP implementation if it reduces protocol risk without
introducing another policy engine. Do not replace the Codex terminal with a mock UI.

## Implementation sequence and commits

- [x] Commit this reviewed plan before runtime changes.
- [x] Verify a pinned real Codex terminal can use the local adapter under fixed
  restrictions. Inspect actual tool calls and effects, not model claims.
- [x] Implement safe startup/discovery/review/reuse/status/stop and supervised PTY.
- [x] Implement the MCP adapter and registered child path over existing controls.
- [x] Add realistic new/existing website fixtures, Python/JavaScript/TypeScript
  compatibility, protocol/unit tests and real Linux negative tests.
- [ ] Iterate on failures, retain each attempt, run the complete regression suite.
- [ ] Install from committed source as a fresh user and follow only the published
  quickstart in real terminals, including policy review and continued conversation.
- [ ] Commit reproducible scripts, sanitized evidence, documentation and final
  implementation. Publish only after credential and evidence checks.

## Acceptance matrix

| Path | Positive work | Negative and escalation checks |
|---|---|---|
| New website | Start with an empty repository; define project and task scope; propose policy including thresholds; approve; create public site, tests and build output | Private/outside resources inaccessible; first verified violation warns; allowed work still succeeds; later violations stop all project actors |
| Existing website | Preserve existing files; propose/review policy and explicit thresholds; fix a bug and add a visible feature; test/build succeeds | Existing customer data/secret fixture unchanged; logs and injected project text cannot grant access; approved policy cannot be self-edited |
| Python | Dependencies, actual source changes and passing tests; native wheel/extras/source-build regressions retained | Disallowed/known-critical/too-young packages, alternate install routes, offline build confinement |
| Node/TypeScript | npm lock, JavaScript tests, TypeScript compilation and checked output | Lifecycle/network/manifest attempts cannot bypass checked installation; unsupported dependencies diagnosed |
| Multiple sessions | Two independent parents and a narrower child work concurrently | Combined counters; no reset by reconnect/new child; no wider child grants; actual running processes stopped |
| Reliability | Reopen terminal, recover monitor, reviewed revision, clean stop | MCP disconnect/controller failure, concurrent edits, replay, tampering, symlink/path traversal and launch/stop races |
| Fresh install | Documented installation and one-command startup from clean environment | Missing dependencies/auth/support reported honestly; never substitute unconfined execution |

Every security check needs a working positive control. Verify actual files, hashes,
test/build receipts, package identities, process effects and unrelated-job survival.
Separate scripted attempts from genuine model-selected actions and refusals.
No policy widening to make an attack pass; revise ambiguous operator intent openly,
retain the failed attempt, and rerun from fresh fixtures.

## Scope and release gate

First release: the tested x86_64 Linux/systemd host, pinned Codex, Python and
JavaScript/TypeScript public-registry workflows. Arbitrary external services,
compromised hosts, private registries and unsupported native toolchains are not
silently treated as supported. Normal Codex conversation is the UI; its permitted
tool surface is intentionally restricted.

A passing existing noninteractive suite does not satisfy this plan. Completion
requires a genuine interactive positive workflow and a genuine deterministic
bypass/stop test, new and existing project onboarding, and recorded fresh-user
installation. Any incomplete gate must be reported explicitly.

## Sources and investigation

- [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp)
- [Permission surfaces](https://learn.chatgpt.com/docs/permissions)
- [Hook limitations](https://learn.chatgpt.com/docs/hooks)
- Existing harness: DESIGN.md, PRACTICAL.md and validation/practical-20260916.
- Recent accessible public/private history contained no named toy website commit.
  A separate private interactive package fixture was inspected; do not copy its
  synthetic package results into this release or modify that work. New website
  fixtures will use real files, compiled output and executable tests.

## Iteration record

The host user manager initially reports degraded because of an existing failed
unit. Inspect that unit read-only; do not reset unrelated services. The new
controller must independently prove healthy before activation.

The first real TUI probes caught two integration failures: CLI trust overrides
alone did not prevent the startup trust dialog from trying to edit a read-only
configuration, and disabling the code-mode host prevented MCP calls. An isolated
configuration file now contains the trusted empty control workspace; the host
configuration and credentials remain unchanged. The bundled V8 host is enabled
while native effectful routes remain disabled. Probe 04 read the actual fixture
through MCP. This does not yet satisfy full onboarding or security acceptance.

Subsequent real TUI tests found missing user-manager environment variables and
uv interpreter failures inside the CLI's nested configuration namespace. MCP
now relays to a separately registered systemd broker with only explicitly
forwarded runtime variables. Its effects still use the same confined executor.

The first tool-surface test found native apply_patch remained registered despite
shell_tool=false. Codex 0.154.0 selects that tool using model metadata. The
supported model-catalog override now removes it, without changing the model.
The second tool-surface test exposed only the two controlled project tools and
empty MCP resource discovery; JavaScript process/require/fetch were undefined.

Four real website workflows passed: fresh TypeScript, existing Python,
JavaScript and TypeScript. Separate post-generation functional tests also passed.
Repeated TUI startup was 6.6 to 7.1 seconds. A real two-terminal/delegate test
passed 15 checks, including combined warnings, denied access and process-group
termination. The revised full Linux suite passed 240 tests with no skips.
Fresh installation, lifecycle recovery and final publication checks remain.
