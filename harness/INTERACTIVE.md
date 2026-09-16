# Start once, then work in Codex

Install the [Linux prerequisites and pinned tools](README.md#install-on-a-linux-vps),
run `ptw doctor`, and authenticate Codex with your own account. Then, in your
new or existing repository:

    ptw codex

The first time, answer four short questions: what the project should do, which
directories it may change, when to warn, and when to stop. An empty repository
also asks whether you use Python, JavaScript or TypeScript.

The tool proposes a project policy and a narrower verification task. Read the
review: directories, commands, package names, and warning/stopping thresholds.
Type `yes` only if it matches your intent. Nothing is automatically approved.
For an existing project, this inventories metadata without executing its scripts.

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
during setup or revision. Inspect the file first: proposal generation sends a
bounded excerpt to your model. Historical access is evidence, not permission.
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
Python execution uses `/usr/bin/python3`. npm uses a reviewed package lock.
Public registry packages are checked for release age and known vulnerabilities
before confined installation. Dependencies do not gain host credentials or
unrestricted network access. [Package details and advanced adapters](ECOSYSTEMS.md)
cover native wheels, explicit source builds and unsupported formats.

This one-command path supports ordinary repositories, not every package layout.
Private registries, Git/local dependencies, npm workspaces, dynamic Python
metadata, and install-script builds require separate review or an adapter.
They fail explicitly, without an unconfined fallback. Metadata such as package
manifests is read only during agent work; dependency/scope changes need review.
This adapter covers editing, builds, tests, packages and registered delegation,
not every native Codex feature. Git administration, deployment and arbitrary
external services remain operator work.

Only verified controller violations increment the escalation count. A failing
test or an operating-system error inside a permitted command is not automatically
classified as an attack. That code is still confined, and commands have time limits.

## The 30-second target

Thirty seconds is the target for **reopening an installed, approved project**.
It is not a promise for a cold installation, login, downloads, model latency,
human review, or completing the coding task. Measure all of these separately.
The [Algol acceptance record](validation/interactive-20260916/README.md) measured
6.18–7.03 seconds to reopen the four approved project fixtures.

## Reproduce the user tests on a disposable Linux VPS

From the source repository with the installed tools on PATH:

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
