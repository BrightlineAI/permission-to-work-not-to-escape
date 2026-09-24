# Project safety harness

The [private candidate guide](RELEASE.md) contains exact local installation,
`ptw demo` and everyday-use commands. Build assets with
`python3 harness/scripts/prepare_product_release.py --out /absolute/new-candidate`
from the repository root. The packaged CLI passed native installation/demo
checks; full final-source acceptance remains pending. This does not publish a release.

The [three-demo quickstart](../docs/demos/TRY-VEGA.md) gives exact installed
commands for dependency, task-scope and swarm, plus verified Markdown summaries.
The [maintained specifications and status](../docs/demos/README.md) distinguish
accepted task20/21 native evidence from pending final-source candidate checks.
Those accepted milestones cover physical comparisons, useful work, child/resume
continuity and evidence rejection, including installed CLI interruption checks.
The [incident-inspired report demo](DEMO.md) retains its existing invocation,
paired confinement comparison and separately scripted shared escalation, with a
[measured historical sample](validation/demo-20260919/README.md). Task18 was
accepted; fresh release acceptance remains a separate gate. These deterministic
fixtures do not establish spontaneous model behavior or audience comprehension.

The [current safety contracts](SAFETY.md) distinguish original product acceptance
from the versioned extension. The [audit guide](AUDIT.md) and
[daily review guide](DAILY.md#bounded-project-sequence-review) document implemented
controls; the [acceptance guide](ACCEPTANCE.md) identifies pending final-source
verification. These are not publication or project-completion claims.

[Installed dependency reassessment](REASSESSMENT.md) checks freshness before reuse,
blocks uncertain evidence without misconduct counts, and quarantines confirmed
forbidden dependencies. Read its caching, running-work and recovery semantics.

A small working extension of the [paper](../paper/submission.pdf). Describe a project, review its proposed policy, and run agents through shared controls.

The usable prototype handles [repository editing and reviewed build/test commands](PRACTICAL.md) and [controlled Python and npm package installation](ECOSYSTEMS.md), including native Python libraries and JavaScript/TypeScript. It supports multiple independent agents, narrower tasks and delegates, shared escalation, automatic monitoring, and review of existing Codex logs. Project differences are JSON configuration, not custom code.

Typed setup preserves Python requirements, reviews a compatible installed
interpreter and supports mixed backend/frontend command roots.
`ptw deps add/remove/update` reviews dependency changes while preserving project
identity, unrelated scope and violation history. Local-source revisions rebuild
under explicit approval before work resumes. See the
[bounded format matrix](DEPENDENCY_STATUS.md) and the [Poetry](POETRY.md),
[pnpm](PNPM.md) and [Yarn Classic](YARN.md) tool guides.

Adapter milestones and both source and fresh-wheel journey matrices have passed
manager checks. Fresh-wheel journeys verify installed source hashes in foreground
and detached processes; final-source integration acceptance remains pending.
These deterministic tests do not establish complete product readiness, live
Codex behavior or the first-setup timing target.

For ordinary Python, JavaScript or TypeScript repositories, start with the
[interactive quickstart](INTERACTIVE.md): install once, run `ptw codex`, review
the policy, then work in the normal Codex terminal. The [automation workflow](PRACTICAL.md)
and exact-file workflow below remain supported.

Protected conversation continuation uses `ptw codex --resume ID` with fresh
session credentials and retained policy counts. Focused native resume checks passed;
see [daily workflow status and limits](DAILY.md).
The [daily guide](DAILY.md) also covers reviewed Python/Node previews, scoped Git
and exact operator checkpoint approval, with the composed native acceptance gate
clearly separated from offline checks.

## Install on a Linux VPS

For a compact installation without cloning the benchmark repository, use the
[recoverable release installer](INSTALL.md). Its built version-specific entry
command installs private tools, runs doctor automatically, and provides retry,
upgrade, rollback and conservative uninstall. The online release is unpublished.
The source installation below remains the legacy compatibility path.

Use an ordinary operator account, not root. The tested platform is x86_64 Linux with systemd, bubblewrap 0.12.0, Node 22 and Python 3.12. The installer downloads pinned, checksum verified nono and uv releases, an isolated Python environment, and Codex CLI 0.154.0. It does not modify global packages.

On a fresh Debian or Ubuntu host, an administrator may first need:

    sudo apt-get install git curl python3 bubblewrap nodejs npm

Get the source, then install:

    git clone https://github.com/BrightlineAI/permission-to-work-not-to-escape.git
    cd permission-to-work-not-to-escape

    PTW_INSTALL="$PWD/../ptw-install"
    bash harness/scripts/install-vps.sh "$PTW_INSTALL"
    export PATH="$PTW_INSTALL/venv/bin:$PTW_INSTALL/bin:$PTW_INSTALL/codex/node_modules/.bin:$PATH"
    ptw doctor

Use a new installation directory. Run from a normal login session with an active systemd user manager. Doctor checks an actual permitted read, blocked private read, running workload and confirmed stop. Do not proceed if it reports ready=false.

For model calls, authenticate your own Codex installation:

    codex login
    codex login status

The default model is GPT-5.6 Sol with low effort. No model is silently substituted. The file broker, package control and audit do not need an API key or a model. For those features alone, install with --no-codex; see the [package walkthrough](PACKAGES.md).

## New project

Start with a tiny example:

    PTW_PROJECT="$PWD/../ptw-example"
    ptw sample --out "$PTW_PROJECT"
    ptw propose --description "$PTW_PROJECT/project.md" \
      --inventory "$PTW_PROJECT/inventory.json" --out "$PTW_PROJECT/draft.json"
    ptw review --policy "$PTW_PROJECT/draft.json" --inventory "$PTW_PROJECT/inventory.json"

Read the review output. Check which resources each task can read or change, and the warning and stopping thresholds. Inventory means a resource exists, not that it is allowed. Edit the draft if needed, then review again.

Approve the exact review hash, not an earlier version:

    ptw approve --policy "$PTW_PROJECT/draft.json" --inventory "$PTW_PROJECT/inventory.json" \
      --sha256 PASTE_THE_REVIEW_HASH --reviewer "Your name" --out "$PTW_PROJECT/approved.json"
    ptw activate --bundle "$PTW_PROJECT/approved.json" --state "$PTW_PROJECT/controller"
    ptw run --state "$PTW_PROJECT/controller" --project website --task frontend \
      --assignment "$PTW_PROJECT/task.md" --out "$PTW_PROJECT/run.json"

The UI file should contain Hello followed by a newline. Customer records must remain unchanged. Inspect the files, not just the model's completion message.

To test without model calls, use the supplied policy.json in place of draft.json, skip propose, and use the manual request commands below. Do not call this a model generated policy.

For your project, replace project.md and inventory.json. Give every resource an ID and an existing relative file path under one canonical resource directory. The controller directory must be outside that directory. Both must be data directories outside system runtime trees such as /usr. Version 1 does not create/delete resources or grant arbitrary directory, credential or network access.

## Existing project

Write the intended project scope and inventory first. Select a relevant Codex rollout JSONL file; do not upload your entire history. Codex commonly stores these under its sessions directory.

    ptw propose --description "$PTW_PROJECT/project.md" \
      --inventory "$PTW_PROJECT/inventory.json" \
      --history "$PTW_PROJECT/history.jsonl" --out "$PTW_PROJECT/existing-draft.json"
    ptw review --policy "$PTW_PROJECT/existing-draft.json" --inventory "$PTW_PROJECT/inventory.json"

Review and approve this draft using the new review hash. Then compare the selected log with it:

    ptw approve --policy "$PTW_PROJECT/existing-draft.json" --inventory "$PTW_PROJECT/inventory.json" \
      --sha256 PASTE_THE_NEW_REVIEW_HASH --reviewer "Your name" --out "$PTW_PROJECT/existing-approved.json"

    ptw audit --bundle "$PTW_PROJECT/existing-approved.json" \
      --history "$PTW_PROJECT/history.jsonl" --task frontend --out "$PTW_PROJECT/audit.json"

For the sample log, expect one allowed request, one denied request and one unknown command. The audit does not execute commands, change permissions, or change live violation counts.

Past access does not grant permission. A denied request might reveal excessive access or an overly narrow draft. Resolve that against the operator's intent; do not automatically allow everything the logs contain. Unknown means the tool or command needs manual review, not that it was safe.

The proposer sends a bounded excerpt of your selected log to your configured model. Pattern redaction is only a convenience, not guaranteed secret removal. Inspect or sanitize real logs before using --history. The audit command itself stays local.

## Multiple agents, tasks and delegates

Register every agent with the same controller state and project ID. These are operator commands; do not give unconfined agents access to the controller, session files or these administration commands.

    ptw register --state "$PTW_PROJECT/controller" --project website --task frontend \
      --out "$PTW_PROJECT/parent.json"
    ptw register --state "$PTW_PROJECT/controller" --project website --task operations \
      --out "$PTW_PROJECT/second-parent.json"
    ptw register --state "$PTW_PROJECT/controller" --project website --task frontend \
      --parent "$PTW_PROJECT/parent.json" --out "$PTW_PROJECT/child.json"

Private session files hold credentials for trusted adapters. The model receives grants and tool results, not those credentials. Delegates can narrow further with --grants, but cannot exceed their parent or task. Their violations also count against ancestor tasks, so delegation cannot reset a stricter threshold.

For a manual permitted request:

    ptw request --state "$PTW_PROJECT/controller" --session "$PTW_PROJECT/parent.json" \
      --event ui-edit-1 --action write --resource ui --content "Hello"

For a forbidden request:

    ptw request --state "$PTW_PROJECT/controller" --session "$PTW_PROJECT/parent.json" \
      --event forbidden-1 --action read --resource customers

Use distinct event IDs for distinct attempts. A transport retry must reuse the same ID and body. With the sample policy, three denied requests across any parents or delegates stop the project. The first triggers a warning. New requests and launches are rejected; registered workloads are terminated. Warnings are returned to the acting adapter and visible through shared status.

    ptw status --state "$PTW_PROJECT/controller" --project website
    ptw events --state "$PTW_PROJECT/controller" --project website
    ptw stop --state "$PTW_PROJECT/controller" --project website

Version 4 activation starts automatic monitoring. For older file-only policies and long running local workloads, keep termination reconciliation active in another operator terminal:

    ptw watch --state "$PTW_PROJECT/controller"

The operator can launch a confined workload with ptw launch --state STATE --session SESSION -- COMMAND ARGUMENTS. It sees only its mounted resources under /resources/ID, scratch space and system runtimes. It cannot access the controller, other resource files, the host process namespace or the network. This is an operator API, not an unrestricted Codex shell tool.

## Run the tests

For source tests, create a new isolated environment on the VPS. Install the
hashed runtime dependencies and the same hashed build prerequisite used by the
release builder, then install this checkout without further resolution:

```sh
PTW_TEST_ENV=$(mktemp -d /tmp/ptw-source-tests.XXXXXXXX)
uv venv --no-python-downloads --python python3 "$PTW_TEST_ENV/venv"
uv pip sync --python "$PTW_TEST_ENV/venv/bin/python" --require-hashes --only-binary :all: harness/requirements.lock
python3 -c 'import sys; sys.path.insert(0,"harness/scripts"); from build_product_release import BUILD_PIN; print(BUILD_PIN,end="")' > "$PTW_TEST_ENV/build.lock"
uv pip install --python "$PTW_TEST_ENV/venv/bin/python" --require-hashes --only-binary :all: -r "$PTW_TEST_ENV/build.lock"
uv pip install --python "$PTW_TEST_ENV/venv/bin/python" --no-deps --no-build-isolation --editable ./harness
export PATH="$PTW_TEST_ENV/venv/bin:$PATH"
python -I -B -c 'import ptw; print(ptw.__file__)'
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -v
```

The import must point into this checkout. An ambient `PYTHONPATH=harness` alone
is insufficient because detached systemd services do not inherit it. Keep the
installed native tools on PATH and use a normal systemd user login for native
checks. Source tests with mocked integrations establish only their stated
behavior. For installed-user acceptance, use fresh wheel installations with
PYTHONPATH unset, prove installed hashes, and never reuse this editable environment.

The standalone Node import gate includes its cross-manager cases and selected
ecosystem, pnpm and Yarn regressions:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_node_import.py -v
```

Broad discovery runs those selected regressions through their owning modules
once. Partial discovery still includes selections whose owning modules are
excluded by the filename pattern. Named loading of the Node gate retains all
its selections. This uses the standard
[unittest load_tests protocol](https://docs.python.org/3.12/library/unittest.html#load-tests-protocol),
which supplies the discovery pattern; no global test-ID deduplication is used.
Structural cases in `test_product_reassessment.py` inspect actual suites without
running native fixtures, checking membership, multiplicity and visible load errors.

The task-scope observer fixture uses atomic file replacement for its intended
pre-exec, post-exec and changed-content states. A separate controlled transition
holds an empty intermediate file until sampled and requires the extra observation.
Bounded sample acknowledgements verify duplicate suppression, process identity and
exact content hashes through the real observer thread. These synthetic checks do
not establish native effects; installed demo tests still require actual child and
resume observations, useful recovery and unchanged unrelated work.

Native discovery that includes `test_product_reassessment.py` also retains a fresh
private `REGRESSION_TIMING_EVIDENCE` directory. It records source hashes and flushed
start/end records for each test, class setup, teardown and cleanup. The two Yarn
paths under timeout investigation additionally record controller, parser, tool
verification and native-install phases, including synthetic terminal children.
The Poetry legacy/PEP 735 group import and revision case additionally brackets
`poetry_tool.run`, payload verification, tool interpreter identification and the
native subprocess wait. Its pre-execution and post-execution integrity checks
remain separate nested spans. Hooks apply only to that selected case and restore
on failure or interruption; other subprocess callers remain untouched. Offline
hook tests exercise actual verification with synthetic tool bytes and a substituted
subprocess boundary, including tampering before/after execution, timeout and
interruption. Those tests do not establish native performance or confinement.
The single combined-editable rejection/cancellation/EOF case records nested
`onboarding.setup`, `python_runtime.identify`, policy compilation (including the
onboarding import) and `Store.locked` entry/exit spans. All five existing review
boundaries still run. Lock entry measures acquisition and connection setup; exit
measures release, excluding the caller's body. An exit can complete while
propagating a body exception, so interpret it with the enclosing setup/test
outcome. Repeated phase starts give call counts; these diagnostics do not cache
runtime identity or policy decisions, or change transaction durability. Hooks
apply only to that exact test ID and restore after failure or interruption.
Offline forwarding tests cover rejection, EOF, lock acquisition/body/release
errors, exception suppression and interruption without logging private values.
Native measurements are required before attributing accumulated regression time
to a runtime or environment cause; diagnostic coverage alone is not a speedup.
The existing runner, order, assertions, confinement and deadlines remain in force.
No arguments, payloads, output or exception messages enter these timing records.

The same full discovery now retains a separate [native suite receipt](ACCEPTANCE.md)
with the original runner log and exact test inventory. Keep those private logs and
the source-test environment for independent verification. Focused receipts, old
source receipts and incomplete attempts cannot satisfy full product acceptance.
A timed-out or killed runner may leave `attempt.json`, `outcomes.jsonl` and its
original log without `complete.json`. A subsequent product check then fails before
installation; the missing completion record must not be reconstructed from passing
individual cases. Inspect the retained timing spans and last outcome first. After
resolving the cause, run full native discovery against the final source again;
an earlier pass or a focused receipt cannot replace the interrupted attempt.

Hosted CI runs `python harness/scripts/offline_checks.py` from an isolated editable
source installation. Before discovery, `harness/scripts/provision_ci_uv.py`
downloads the installer's pinned uv 0.12.15 into a fresh runner-local directory,
verifies its SHA-256, validates the archive and checks the executable version.
Only then does it expose that directory to later workflow steps through
`GITHUB_PATH`. An ambient uv installation is not used for this prerequisite.
Download, integrity, archive or version failures stop the job before tests;
retain the failed job and rerun on a fresh runner after resolving the cause.
Do not bypass verification or skip resolver tests to address a missing tool.
For manual source tests above, keep the installer's verified uv on PATH.

CI preserves discovered offline cases and explicitly reserves
the installed safety/demo/release classes for the manager's native gate. Existing
per-test native prerequisites still apply there. CI success is not full product
acceptance; normal `PTW_LINUX_TESTS=1` discovery still executes every mandatory
case and accepts zero skips. Do not use the CI subset for a release receipt.

Timings are inclusive and nested, so do not add phase durations to test durations.
Resource counters are cumulative for the process and its waited-for children:
user/system CPU, block input/output, minor/major faults and voluntary/involuntary
context switches. Subtract corresponding start/end counters. Block counters do
not count cached reads; wall time minus CPU is not proof of a specific I/O or
scheduling cause. Detached systemd services and
still-running children are not included. An unmatched start indicates incomplete
evidence, not success. A deadline traceback identifies where interruption occurred,
not the cause of accumulated time. Retain failed attempts before diagnosing a
slow phase; timing evidence does not authorize skipping integrity verification.

The dependency integration suite runs six new/existing Python, Node and TypeScript
terminal journeys, the mixed project and an npm workspace control in both source
and fresh-wheel environments:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_ecosystems.py -v
```

The suite builds a wheel using the release builder's hashed build prerequisite,
installs hashed runtime dependencies in a fresh environment per case, and verifies
installed module hashes before and after useful protected work. A detached user
service checks the same installation without PYTHONPATH; the real project monitor
must use its interpreter. Failures and inputs remain in fresh private
`ECOSYSTEM_EVIDENCE` directories. This is dependency acceptance, not a cold
installer timing measurement or a live model trajectory. See the
[fixture guide](examples/product-ecosystems/README.md) for physical assertions.

From the repository root in that source-test environment:

    python harness/scripts/validate.py --linux --out ../ptw-validation
    python harness/scripts/walkthrough.py --out ../ptw-walkthrough
    python harness/scripts/walkthrough.py --live --out ../ptw-live-walkthrough
    python harness/scripts/native_history.py --out ../ptw-native-history

Use new output directories on each run. The live walkthrough makes real Codex calls and exercises both new and existing project workflows. The native history check records actual shell reads of synthetic files, then audits that history against a frontend policy. The walkthrough approves only its known synthetic fixtures; real project approval remains your responsibility.

## What this version does and does not cover

Runtime policy decisions and default interactive setup need no extra LLM calls.
`ptw codex` compiles explicit goal/scope fields into validated templates. Optional
`--model-proposal` may clarify descriptions with one call, under the same fixed
authority constraints. The separate `ptw propose`/`prepare` model workflow can
take up to three calls for structural repair. Drafts and failures are retained;
there is no automatic runtime policy widening. See [setup and recovery](ONBOARDING.md).

This is a controlled adapter, not an interceptor for arbitrary existing Codex sessions.
Existing sessions can be audited; protected execution starts through `ptw codex`
or the noninteractive `ptw run` adapter. Native tools are disabled or denied access
to controlled resources. Delegation is registered through the trusted adapter.

The host, operator, Codex runtime and supervisor are trusted. Keep policy state away from unconfined programs running as your operator. A typed policy may still misunderstand your intent. Approval is a content bound operator workflow, not a cryptographic signature or proof that prose was translated correctly.

Stop covers registered local work, not remote services or already completed effects. A failed termination remains pending and visible for retry. Resource failures stop the project conservatively and are not labeled malicious violations. Never reset a stopped project by reusing its ID; review and start an explicit new version.

See [the plan and design review](PLAN.md), [technical details](DESIGN.md) and [validation record](validation/README.md).
