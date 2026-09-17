# Project safety harness

A small working extension of the [paper](../paper/submission.pdf). Describe a project, review its proposed policy, and run agents through shared controls.

The usable prototype handles [repository editing and reviewed build/test commands](PRACTICAL.md) and [controlled Python and npm package installation](ECOSYSTEMS.md), including native Python libraries and JavaScript/TypeScript. It supports multiple independent agents, narrower tasks and delegates, shared escalation, automatic monitoring, and review of existing Codex logs. Project differences are JSON configuration, not custom code.

Current source extends typed setup with Python range resolution, reviewed system
interpreters and mixed backend/frontend command roots. Full ordinary ecosystem
support is not complete. See [dependency status](DEPENDENCY_STATUS.md) for the
implemented subset, missing adapters and native checks still needed.

For ordinary Python, JavaScript or TypeScript repositories, start with the
[interactive quickstart](INTERACTIVE.md): install once, run `ptw codex`, review
the policy, then work in the normal Codex terminal. The [automation workflow](PRACTICAL.md)
and exact-file workflow below remain supported.

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
