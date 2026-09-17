# Start once, then work in Codex

Use the [recoverable Linux installer](INSTALL.md), which runs doctor automatically,
then open a fresh terminal. If `ptw` is absent, follow the installer's printed
instructions for your shell. Authenticate with `ptw-codex login` using your own
account. Then, in your new or existing repository:

    ptw codex

The first time, supply the goal and select editable directories and exact root
files. Ordinary layouts are suggested from filenames and configuration. An empty
repository also asks whether you use Python, JavaScript or TypeScript. Defaults
warn after one violation and stop after three; no extra threshold questions are required.

The tool compiles a typed project policy and a narrower verification task without
a model call. Read the short review: files, directories, commands, package names
and warning/stopping thresholds. Enter `details` for exact commands and generated
configuration, or `customize` to change scope and thresholds, followed by a new
review. Type `yes` only if it matches your intent. Blank input, `reject`, `cancel`,
EOF and Ctrl-C never approve. Repository scripts execute during setup only when
local Python preparation is explicitly selected and approved as described below.

For example, a root-file Python project can use:

    ptw codex --goal "Maintain this application" --language python --editable '' --files app.py,README.md

For an existing static pure-Python package with `pyproject.toml`, a standard
registry backend, `src` and `tests`, current source adds reviewed editable setup:

    ptw codex --editable src,tests --files README.md --python-editable src --setup-only

The review identifies backend execution, assessed build dependencies and the
source snapshot. Type `yes` to prepare offline, then run `ptw codex`. Source edits
within `src` appear in subsequent protected imports without reinstalling. Build
configuration changes require another review. For a fixed wheel installation,
replace `--python-editable src` with `--python-wheel`; any source change then needs
reviewed re-preparation. The manager passed both terminal flows. Add
`--python-extras NAME` to select a declared optional dependency group; the manager
passed those fixtures. Dynamic metadata prompts first for confined discovery,
then for installation of the reviewed result; the manager passed the wheel flow.
Dynamic editable setup adds a separate editable-hook review after discovery.
The manager passed this flow, including dynamic optional dependencies.
`--python-native-wheels` requests native output for wheel or editable mode.
The manager passed compiled editable import/rebuild fixtures; compiled-input changes
need reviewed re-preparation with `--revise`. Live Python edits alongside static
declarative setuptools extensions now require an enforced build view excluding
those implementation files; the manager verified this in the local-Python suite.
Use `--python-full-build` for compilation that needs them, with reviewed rebuilding
after source changes. See
[local preparation limits and recovery](ONBOARDING.md#local-python-preparation).

For an existing backend/frontend layout, the current source also accepts:

    ptw codex --language mixed --python-root backend --node-root frontend --editable backend/src,backend/tests,frontend/src,frontend/dist --files ''

Select only paths needed by your project; nested parents must already exist.
Python's declared runtime requirement is preserved and the selected interpreter
is shown before approval. Current mixed support uses static Python declarations
and npm locks, including scoped workspace sources. See the precise format and
validation boundaries in [dependency status](DEPENDENCY_STATUS.md)
before treating this as complete ecosystem support.

Missing exact files may be created later through protected tools. No root-directory
write grant is needed. Metadata remains read only. New directories, generated
locks/configuration and the review copy are staged and published only after
approval. `--setup-only` commits setup without creating an agent session or
claiming terminal readiness. See [transaction and recovery details](ONBOARDING.md).

Codex then opens normally. For example:

> Build a public workshop page with a category filter. Add tests and run them.

Continue the conversation as usual. You do not need to call MCP tools or learn
the internal command API. Codex receives the approved tools and scope. Edits go
to your repository; builds and tests run in confined copies, and only permitted
changes are published back.

## Next time

Run `ptw codex` again in the same repository. It reuses the approved policy and
violation history. Multiple terminals share the same project. A narrower
verification session is `ptw codex --task verify`; delegates also inherit only
equal or narrower scope.

Quit Codex with `/quit`. This ends that session, not other agents on the project.
Use `ptw codex --stop` to stop the whole project. `ptw codex --status` shows the
shared state.

Do not use the bare `codex resume` command printed by Codex at exit. It is not a
protected entry point. Reopen through `ptw codex`; files and project history
persist, but the new conversation starts fresh.

## Policy changes are operator decisions

The `.ptw/policy.json` file is a review copy you can put in Git. Editing it cannot
change active permissions. The controller and approved policy are stored outside
the repository, under `~/.local/state/permission-to-work`.

Use `ptw codex --review` to inspect the active bundle. Use `ptw codex --revise` to
propose and approve a new version. This stops old sessions before switching and
retains their violation history. A stopped project never restarts merely because
another agent, delegate, or terminal joins it.

For selected existing-project history, add `--history /path/to/sanitized.jsonl`
during setup or revision. This does not trigger a model call or change authority.
The explicitly optional `--model-proposal` sends a bounded excerpt to your model
and adds model latency. Inspect the history first. The model may clarify
descriptions but cannot change selected scope, commands, packages or safety defaults.
Historical access is evidence, not permission.
The separate local `ptw audit` command is described in the [audit guide](README.md#existing-project).

## What is protected

- File operations, approved test/build commands, checked package installation,
  and registered delegation use the external controller.
- Multiple parents and descendants share project counters. Ordinary failed
  tests and stale edit conflicts are not malicious violations.
- The first verified scope violation warns. At the reviewed stop threshold,
  registered project processes stop and later actions are rejected.
- Skipping MCP does not provide an alternative execution path. Native shell,
  patching, plugins, apps and external search are disabled in this pinned adapter.
  The isolated JavaScript host can orchestrate registered tools, but has no
  Node, filesystem or network APIs. Codex's filesystem profile also denies access.

Codex's client and the operator remain trusted. This is not protection against a
compromised host or someone deliberately launching an unprotected agent.
Already completed effects and unmanaged external services cannot be undone.

## Supported first version

The tested platform is x86_64 Linux with an active systemd user manager,
Codex CLI 0.154.0, Python, and Node 22. The interactive model is GPT-5.6 Sol/low,
not a silently substituted model.

Python requirements and static pyproject dependencies are resolved to pins;
Python execution uses its reviewed compatible interpreter. npm uses a reviewed package lock.
Public registry packages are checked for release age and known vulnerabilities
before confined installation. Dependencies do not gain host credentials or
unrestricted network access. [Package details and advanced adapters](ECOSYSTEMS.md)
cover native wheels, explicit source builds and unsupported formats.

This one-command path supports ordinary repositories, not every package layout.
Configured private Python/npm origins and npm workspace sources use separate broker and
source bindings. For private Python, pass
`--python-registry-config /absolute/operator/python-routes.json` at setup and
review its bound hash in `details`. Credentials stay in an external operator
file; see the [registry contract and measured coverage](DEPENDENCY_STATUS.md#private-python-setup-and-verification).
Root `-e .`/`.` and additional project paths in requirements need matching
explicit local preparation flags. Static and dynamic uv locks retain original
versions/hashes; dynamic locks additionally require approved offline freshness
validation. Each source has separate build requirements and confinement, with
one compatible runtime installation. Dynamic sources request metadata and
editable-hook approval separately; `--python-build-requirements` requests hooks
for static sources. Rejection or a later build/validation failure publishes no
partial installation.

The manager's 300-test local suite passed the single/multiple-source native
terminal flows, protected imports, live edits, compiled rebuilding and static
and dynamic lock checks. See [source scope and review](ONBOARDING.md#local-python-preparation)
and [measured evidence](DEPENDENCY_STATUS.md#local-python-evidence).
Poetry, pnpm/Yarn and broader ecosystem integration remain required queued work.
Install scripts require explicit build policy. Metadata such as package
manifests is read only during agent work; dependency/scope changes need review.
For a dependency change, use the operator terminal, for example
`ptw deps update 'idna>=3.10,<4' --ecosystem pypi --source pyproject.toml`.
Review the proposed versions and files, expand `details` if needed, then type
`yes`, `reject` or `cancel`. Existing work is stopped only after approval and
must register again. See [the format matrix and revision examples](DEPENDENCY_STATUS.md).
This adapter covers editing, builds, tests, packages and registered delegation,
not every native Codex feature. Git administration, deployment and arbitrary
external services remain operator work.

Only verified controller violations increment the escalation count. A failing
test or an operating-system error inside a permitted command is not automatically
classified as an attack. That code is still confined, and commands have time limits.

## The 30-second target

Thirty seconds is the target from **first installer invocation through fresh
project review and protected readiness** on the declared supported profile.
That target is not yet certified. Record downloads, cache state, model latency,
human review and external login separately, and measure the first useful action.
The [first-setup driver](ONBOARDING.md#measurement-and-verification) includes the
installer clock and requires a live protected MCP connection as well as the TUI.
Reopening an installed, approved project is a separate warm measurement.
The [Algol acceptance record](validation/interactive-20260916/README.md) measured
6.18–7.03 seconds to reopen the four approved project fixtures.

## Reproduce the user tests on a disposable Linux VPS

For source regressions, first use the [isolated editable test environment](README.md#run-the-tests)
so detached services import the current checkout. Keep the installed tools on PATH:

    python harness/scripts/interactive_acceptance.py --out /absolute/new-website
    python harness/scripts/interactive_acceptance.py --existing --language python --out /absolute/existing-python
    python harness/scripts/interactive_acceptance.py --existing --language javascript --out /absolute/existing-js
    python harness/scripts/interactive_acceptance.py --existing --language typescript --out /absolute/existing-ts
    python harness/scripts/interactive_security.py --acceptance /absolute/new-website --out /absolute/website-security
    python harness/scripts/interactive_lifecycle.py --acceptance /absolute/existing-python --unrelated /absolute/existing-js --out /absolute/website-lifecycle
    python harness/scripts/validate.py --linux --out /absolute/linux-tests

Use fresh absolute output paths. These launch the real Codex TUI in pseudo
terminals, type the setup answers, check the synthetic policy before approval,
continue the conversation, and verify real files and independent test receipts.
They use your normal Codex login. No authentication files are copied.

Security checks distinguish real model calls from scripted adversarial requests.
The security test stops its approved synthetic project. Raw terminal recordings
and private session credentials stay in the output directory. Do not publish
that directory wholesale; publish only reviewed summaries.
