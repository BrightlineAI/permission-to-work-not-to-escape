# Use the harness on a repository

This is the explicit automation/operator guide. For the one-command Codex terminal
experience, use the [interactive quickstart](INTERACTIVE.md).

Version 0.4 added repository editing, Python/TypeScript commands, checked packages,
multiple agents and automatic monitoring. Start on a Linux VPS, using the
[installation instructions](README.md#install-on-a-linux-vps). Run ptw doctor
and proceed only when it reports ready=true.

The workflow is: describe the project, review its policy, approve its exact hash,
then run agents through ptw run. The agent uses the shared controller for edits,
package installation, commands and delegation. This is a controlled runner, not
an interceptor for an already running unrestricted coding session.

## Try a new Python project

Use fresh directories outside your source checkout:

    PTW_EXAMPLE="$PWD/../ptw-python"
    ptw sample --workspace python --out "$PTW_EXAMPLE"

This creates a small repository with a broken addition function, real tests,
six==1.17.0, a private customer file that must remain inaccessible, and a sample
policy. The sample policy is supplied configuration, not an LLM proposal.

    ptw review --policy "$PTW_EXAMPLE/policy.json" --inventory "$PTW_EXAMPLE/inventory.json"

Read the grants, package rules, commands and thresholds. Implementation can edit
source and build outputs; verification can edit tests; a readcheck delegate cannot
edit either. Nobody is granted the private data. Approve the displayed hash:

    ptw approve --policy "$PTW_EXAMPLE/policy.json" --inventory "$PTW_EXAMPLE/inventory.json" \
      --sha256 PASTE_REVIEW_HASH --reviewer "Your name" --out "$PTW_EXAMPLE/approved.json"
    ptw activate --bundle "$PTW_EXAMPLE/approved.json" --state "$PTW_EXAMPLE/controller"
    ptw register --state "$PTW_EXAMPLE/controller" --project python-demo --task implementation \
      --out "$PTW_EXAMPLE/implementation.json"
    ptw run --state "$PTW_EXAMPLE/controller" --session "$PTW_EXAMPLE/implementation.json" \
      --assignment "$PTW_EXAMPLE/task.md" --max-steps 30 --out "$PTW_EXAMPLE/run.json"

Authenticate your own Codex before run. The default is GPT-5.6 Sol/low; no model
is silently substituted. Check the actual source and the command receipt:
exit_code=0 and PYTHON_TESTS_OK, not merely the model's completion statement.
The customer file must remain unchanged.

Activation installs and starts a private, state-specific systemd user monitor.
You do not need another terminal running ptw watch. It restarts after a crash
and starts with the user manager after login. No global services are changed.
For jobs that must survive logout, ask the host administrator to enable lingering
for your operator account. Otherwise user services follow the host's login policy.

## TypeScript

Create another example with --workspace typescript. Before reviewing its policy,
generate the dependency lock without installing packages or running their scripts:

    PTW_TS="$PWD/../ptw-typescript"
    ptw sample --workspace typescript --out "$PTW_TS"
    npm install --prefix "$PTW_TS/repo" --package-lock-only --ignore-scripts \
      --no-audit --no-fund --registry=https://registry.npmjs.org

Repeat review, approval, activation, registration and run using that directory and
project typescript-demo. Expected result: TypeScript compiles to dist, and the
test receipt contains TYPESCRIPT_TESTS_OK with exit code zero. Package admission
still checks registry evidence, release age and vulnerabilities.

## Your existing repository

Keep operator descriptions, drafts, credentials and controller state outside the
repository. Write a short description of allowed work, forbidden data, task scopes
and escalation. Supply candidate commands as JSON, for example:

    [{"id":"test","argv":["/usr/bin/python3","-m","unittest","discover","-s","tests"],
      "resources":["src","tests"],"timeout_seconds":30}]

Be explicit about file lifecycle permissions. "Modify existing files" need not
authorize creating, renaming or deleting them. Say which directories permit those
operations. Review omissions as carefully as excessive permissions.

Resource names here are top-level repository paths. Include output directories
such as dist in the inventory and command inputs when builds need them; create
those directories yourself before preparing the project. Use exact Python pins
including transitive dependencies, or an npm lock. Then:

    ptw prepare --repo /absolute/my-project --description /outside/project.md \
      --commands /outside/commands.json --requirements /absolute/my-project/requirements.txt \
      --out /outside/review-draft

For npm use --npm-lock instead of, or alongside, --requirements. The model
proposes policy and tasks, but cannot add commands or package identities beyond
the supplied candidates. Review draft.json and inventory.json, then follow
the same approval/activation/run steps. Use the project/task IDs in the draft.

Inventory uses top-level files and directories. Hidden entries, links,
node_modules, venv and __pycache__ are omitted and reported. An inventoried
directory is not automatically granted. Split a broad resource into nonoverlapping
subdirectories in the inventory when tasks need finer scope. Add a declared file
resource for a future top-level file before approval; its parent must exist.

Optionally add --history selected.jsonl as untrusted evidence. Inspect and
sanitize it first. Historical access does not authorize future access. The
[existing log audit](README.md#existing-project) remains a limited retrospective
check, not a complete audit of every tool.

## Multiple independent agents and delegates

Register every parent against the same controller and project:

    ptw register --state "$PTW_EXAMPLE/controller" --project python-demo --task verification \
      --out "$PTW_EXAMPLE/verification.json"
    ptw register --state "$PTW_EXAMPLE/controller" --project python-demo --task readcheck \
      --parent "$PTW_EXAMPLE/implementation.json" --out "$PTW_EXAMPLE/child.json"

Run each with its own --session and assignment/output files. They may run
concurrently. Edits require current content hashes; conflicting edits publish
nothing and ask the agent to reread. A model can also request a registered
delegate through the runner. Children share the original model step budget and
may not gain file, package or command authority.

Do not give session files or administration commands to an unconfined model.
Session files are credentials for the trusted adapter; models see grants and
results, never those credentials.

## Requests, denials and policy changes

For a reproducible manual action, save a JSON request outside the repository:

    {"action":"read","resource":"src","path":"calculator.py",
     "destination":"","content":"","expected":""}

    ptw action --state "$PTW_EXAMPLE/controller" --session "$PTW_EXAMPLE/implementation.json" \
      --event inspect-1 --request /outside/request.json --out /outside/receipt.json

Use the returned sha256 as expected for write/append/delete/rename. Create
never overwrites. Rename takes destination="resource:path" and checks both ends.
Directory creation/removal uses mkdir/rmdir; removal requires an empty directory
and expected="directory". Directory rename checks every affected file against
source read/delete and destination create permissions. Repeat an identical event ID only
for transport retry; changed requests and edit retries need new IDs.

Run names a reviewed command in resource, with content such as
{"package_sets":["pkg_..."]}. Install names the readable dependency resource
and content pypi or npm. No agent-supplied host paths or arbitrary commands.

Denied scope counts toward shared escalation. An edit conflict, failing test or
unavailable vulnerability evidence does not count as misconduct. Allowed=true
means an authorized operation, not a passing test; inspect exit_code too.

If the policy really omitted necessary permission, the operator can draft one
narrow change, for example allowing verification to create test files:

    ptw change --state "$PTW_EXAMPLE/controller" --project python-demo --task verification \
      --resource tests --action create --reason "Add the requested regression test" \
      --project-id python-demo-v2 --out /outside/change-review

Review and approve the new draft/hash using its inventory, then:

    ptw replace --state "$PTW_EXAMPLE/controller" --project python-demo --bundle /outside/new-approved.json

This stops old work, confirms termination, and activates the reviewed new identity.
Old sessions stay stopped and old history remains. Register new sessions explicitly.
Agents cannot request or approve their own policy changes. Never widen policy
merely to silence a denial.

## Status, recovery and cleanup

    ptw status --state "$PTW_EXAMPLE/controller" --project python-demo
    ptw events --state "$PTW_EXAMPLE/controller" --project python-demo
    ptw monitor status --state "$PTW_EXAMPLE/controller"
    ptw recover --state "$PTW_EXAMPLE/controller" --project python-demo

Recovery restarts missing monitoring and reconciles pending terminations. It
never clears violations or resumes an uncertain/stopped project. Inspect affected
files and explicitly approve a new version if work should continue.

To stop and remove only this controller's monitor:

    ptw stop --state "$PTW_EXAMPLE/controller" --project python-demo
    ptw monitor remove --state "$PTW_EXAMPLE/controller"

Stop every project in that controller first. Removal retains all state/history.
On upgrade, stop projects and remove the old monitor using the old installation;
install the new version, run monitor ensure, then review/register new work.
Keep the installed environment in place while its monitor is enabled.

## Boundary and reproduction

Commands run in disposable snapshots with no network, home, host repository or
controller mount. Their checked package sets are read only. Outputs are validated
as a whole before publication; forbidden outputs publish nothing. A concurrent
input change causes a conflict. An interrupted publication stops the project:
multi-file publication is not an atomic filesystem transaction.

Limits: 8 MiB per file, 64 MiB/4096 entries per snapshot, 120 seconds per command,
and four nested model delegation levels. Links and special files are rejected.
Read access discloses content to the model/command. Code and output remain untrusted.
All execution is on one Linux host; arbitrary remote services are not covered.
The host, operator, controller and model runtime remain trusted.
The Codex integration follows the [official structured-output workflow](https://learn.chatgpt.com/docs/non-interactive-mode);
the tested CLI remains pinned to 0.154.0. Model completion is unverified until
the actual files and test receipts are checked.

    python harness/scripts/validate.py --linux --out /outside/new-validation
    python harness/scripts/repository_walkthrough.py --out /outside/new-walkthrough
    python harness/scripts/repository_walkthrough.py --live --out /outside/new-live-walkthrough
    python harness/scripts/repository_walkthrough.py --live --propose --out /outside/description-to-work

The first walkthrough uses real packages/processes and scripted requests. --live
also runs genuine model tasks; it does not relabel scripted probes as model actions.
Both preserve failures and verify actual useful work and unchanged protected files.
See [the design and acceptance plan](PRACTICAL_PLAN.md).
The [VPS validation record](validation/practical-20260916/README.md) includes the
successful runs, two rejected development proposals, timings and reproduction details.
