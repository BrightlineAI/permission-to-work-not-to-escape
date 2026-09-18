# Protected daily development

Package-backed commands and previews apply [installed dependency reassessment](REASSESSMENT.md)
before reuse. Fresh caches work offline; uncertain expired evidence blocks new
work without misconduct counts. Confirmed forbidden dependencies quarantine the
affected sets and terminate their registered commands/previews. Recovery needs a
fresh assessed replacement and never resets violation or stop history.

Protected resume, bounded preview and scoped Git are implemented. Focused native
checks verified resume on Codex 0.154.0, preview lifecycle behavior and Git's
native effects, operator approval and physical termination. The complete
composed PTY journey awaits manager acceptance. This is not a claim of full
product readiness.

After quitting a protected session, run `ptw codex --resume ID` in the same
repository, using the ID printed by the launcher. Use the same `--task` if it
was specified originally. With only one matching recorded conversation,
`ptw codex --resume` selects it. Multiple matches require an explicit ID.
Normal `ptw codex` opens a fresh conversation under the existing approval.

Missing, malformed or mismatched history fails closed. Start a fresh protected
conversation if no continuation was recorded. A second attachment is rejected
until the first exits. Resume never reactivates an old broker credential or
clears a project stop. Dependency reviews preserve the binding; full policy
replacement does not. Conversation history is untrusted context, not authority.

The trusted pinned client stores each conversation's rollouts and SQLite state
under private operator state. Authentication remains in its existing location
and is neither copied nor read by the resume adapter. Each attachment atomically
refreshes the restricted model catalog in the existing control workspace and
supplies the fixed permissions, tools and new broker path. Only bounded native metadata
headers determine the recorded ID. History with multiple native conversations
in the same protected workspace is rejected instead of selecting one silently.

## Local preview

Select a Python or Node entry script during policy setup, for example:

```sh
ptw codex --editable src,tests --preview-python src/server.py:8000
ptw codex --editable src,public --preview-node src/server.js:3000
```

These are separate project examples. For an already approved project, add
`--revise` and select the full intended scope again. Read the review before
approving: it shows the script, fixed port, snapshot resources, lifetime and
limits. Existing approvals gain no network authority. A script may be created
later inside its selected source resource. Both script options can be selected
for a mixed project with distinct ports. The script must listen on the `PORT`
environment value; `HOST` is `127.0.0.1`. Python can use
`HTTPServer((os.environ['HOST'], int(os.environ['PORT'])), Handler)`;
Node can use `server.listen(Number(process.env.PORT), process.env.HOST)`.

Then ask Codex, “Start the reviewed preview and give me its URL.” Open the
returned `http://127.0.0.1:PORT/` in a browser on the same machine. Ask “Stop
the preview” when finished. A VPS browser must run on that VPS; remote access
and port forwarding are outside this adapter. Quit closes previews belonging
to that session and its descendants. Project stop covers all registered
parents, delegates, application descendants and relays; other projects remain
separate. The focused native preview test verified these physical effects.

Every start takes a fresh authorized snapshot and validates selected assessed
package sets. Application writes stay disposable. After editing, ask Codex to
stop and restart the preview. Automatic hot reload against the repository is
not provided. Each preview has 768 MiB RAM, one CPU worth of quota, 128 tasks
and a 512 MiB writable target. The default lifetime is 900 seconds; select
`--preview-seconds` from 1 to 3600 during review. Startup has a 10-second
application deadline, requests have a 5-second upstream deadline, and responses
are limited to 2 MiB. HTTP GET only: redirects, WebSockets, streaming, request
bodies, cross-origin access and external subresources are unsupported. The
browser remains a trusted client; this is not general browser isolation.
The relay rejects absolute and leading-double-slash request targets before
checking the localhost Host header, using the original HTTP request line.

An occupied port, invalid package set, unavailable monitor, startup failure or
expired server blocks preview without a fallback or a malicious-violation
count. Inspect the protected status and fix the application or request an
operator review as appropriate. A denied command/task request still counts
under the existing policy. Private controller receipts retain input hashes,
launch failures, exit codes and bounded combined stdout/stderr startup diagnostics.
Do not publish raw logs.

## Scoped local Git

Select `--git` during setup, or include it in an explicit full `--revise` review
for an existing project. An ordinary `.git` directory must already exist at
the project root. Existing approvals gain no Git operations automatically.
Ask Codex to show Git status or diff. Results compare HEAD, staging and working
files only within the selected command resources and acting task. Untracked
files in that scope are included; ignore rules, filters and text conversion
are not applied. Binary differences report hashes. This is a scoped view,
not a claim that the entire repository is clean.

To save work, ask Codex to prepare a checkpoint for exact changed file paths
and a short message. In another terminal in the same project, run the returned
`ptw checkpoint ID`. Review the displayed changes and type the exact approval
phrase, or reject. Model text cannot approve. Keep the requesting session open
until review finishes. Changed working inputs, HEAD, staging, policy, stopped
projects and closed sessions invalidate the review; request a fresh checkpoint.

The checkpoint creates `refs/ptw/checkpoints/ID` in the real repository, with
the current HEAD as parent and only the selected changes. It preserves the
current branch, index, unrelated staged work and working files. The operator
can inspect the returned ref using their ordinary local Git client. Restoring,
merging, pushing and branch management remain operator work outside this adapter.
The checkpoint does not mark changes committed on the working branch.

For a dependency change, use `ptw deps update NAME==VERSION --ecosystem pypi`
or the corresponding reviewed add/remove operation. Approval closes all sessions
and their services in that project. Resume each conversation with its printed
protected continuation command, then reinstall the reviewed dependency set and
restart previews. Project/task identity and violation history survive the review.
When a revision first generates `ptw-requirements.txt`, its reviewed metadata
resource gains read access for the project and the requesting task. Existing
file grants and other tasks retain their scope; the generated file grants no
write access.

Git runs offline under the existing supervised namespace with a clean metadata
view. Repository/host configuration, hooks, credential helpers, attributes,
replacement refs, signing, maintenance and external diff programs are excluded.
Object/index metadata is needed to construct the view; unrelated working files
are not mounted and unrelated contents are not returned. The approved `.git`
identity is checked again before publication. A checkpoint request never writes
to the host repository until the separate operator review succeeds.

This adapter supports bounded ordinary SHA-1 repositories, including an unborn
branch. Linked worktrees, submodules in the selected scope, shallow or partial
clones, alternates, reftable, conflicted selected index entries and redirected
metadata fail closed. Object snapshots are limited to 256 MiB/16384 files;
working snapshots use the existing 64 MiB limit, and diff output is limited to
2 MiB. A busy Git lock causes a retryable failure without removing that lock.
An interrupted publication conservatively stops the project; retain the private
receipt and inspect the named checkpoint ref before reviewing a new project
version. The implementation assumes the existing trusted host/operator boundary.

## Verification and sources

`test_product_daily.py` includes offline binding, token, history, concurrency,
launch-failure and monitor checks. Its native tests invoke
`scripts/product_daily_acceptance.py` in real PTYs. That script checks an actual
conversation-only nonce across quit/resume, evaluated tool surfaces and globals
on fresh and resumed launches, a hostile repository config, fresh credentials
and retained counts. The composed live journey adds edits, a published build,
tests using assessed dependencies, model-started/stopped Python and Node previews,
scoped Git, an operator-approved checkpoint and a live narrower delegate. An
actual dependency review closes two independent parents and the child's running
service; the conversation then resumes with the new dependency set. Shared stop
must empty every registered cgroup and close listeners while an unrelated live
terminal and preview continue useful work. Scripted broker denials and child
service probes are labeled separately from live model work and operator answers.
The native preview probe covers Python and Node positive controls, fixed-target
HTTP, forbidden reads, connections and unapproved bind ports, occupied ports, startup/server failure,
response bounds, deadlines, normal quit and shared stop across two parents and
a narrower child, while an unrelated preview stays alive. These service probes
are deterministic, separate from the live model resume trajectory.
The script retains source hashes and failures in a fresh private directory; raw terminal
logs and session credentials must not be published.
The Git gate uses deterministic synthetic fixtures and actual operator PTYs to
test rejection, exact approval, real checkpoint refs and preservation of unrelated
staging. Its offline tests execute real Git plumbing in temporary views while
mocking supervision; they do not establish native confinement.
Physical assertions query supervisor state before cleanup. The controller's
workload reconciliation flag alone is not proof that a process has exited.

Native checks require the [isolated current-source installation](README.md#run-the-tests),
Linux systemd, bubblewrap and the authenticated pinned Codex. Detached services
must import the installed current source; PYTHONPATH alone is insufficient.
Fresh-wheel installed-user checks remain separate. No socket/systemd or live
Codex result is claimed from the coding sandbox.

In that isolated source environment, the daily suite is:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_daily.py -v
```

It makes paid calls using the authenticated pinned Codex and contacts the reviewed
public Python registry/advisory sources. Run only on the isolated Linux VPS.
Each native case prints a private `DAILY_EVIDENCE` directory, retaining failures,
source hashes, receipts and actual terminal input/output. Do not publish raw logs.

The [official CLI reference](https://developers.openai.com/codex/cli/reference)
documents explicit resume IDs and working-directory overrides. The
[0.154.0 CLI source](https://raw.githubusercontent.com/openai/codex/rust-v0.154.0/codex-rs/cli/src/main.rs)
defines the resume command. The
[pinned TUI source](https://raw.githubusercontent.com/openai/codex/rust-v0.154.0/codex-rs/tui/src/lib.rs)
requires an embedded server when CLI config overrides are present; persistent
server attachment can otherwise ignore resume overrides. The
[pinned configuration schema](https://raw.githubusercontent.com/openai/codex/rust-v0.154.0/codex-rs/core/config.schema.json)
defines the SQLite location override. The native test must verify this combination
on the installed 0.154.0 binary; the focused manager check passed.

Preview uses a trusted, read-only mounted nono 0.77.0 capability manifest.
The [pinned conversion](https://raw.githubusercontent.com/always-further/nono/v0.77.0/crates/nono/src/manifest_convert.rs)
supports blocked networking with one TCP bind exception and no connect or
localhost exceptions. Filesystem grants explicitly cover the mounted runtime,
devices, disposable target and assessed packages. The
[manifest loader](https://raw.githubusercontent.com/always-further/nono/v0.77.0/crates/nono-cli/src/sandbox_prepare.rs)
uses the default auto backend, with Landlock and static seccomp, instead of
the ordinary command's CLI policy override. The
[CLI definition](https://raw.githubusercontent.com/always-further/nono/v0.77.0/crates/nono-cli/src/cli.rs)
documents these backend semantics and mutually exclusive manifest flags.
The application also uses an isolated network namespace, with a fixed-target
pipe relay instead of host networking. The
[bubblewrap 0.12.0 source](https://raw.githubusercontent.com/containers/bubblewrap/v0.12.0/bubblewrap.c)
initializes loopback when unsharing networking. The focused native probe established
this path on the supplied tools; documentation alone is not confinement evidence.
Stable JSON validation, file locks and existing controller reuse need no new
dependency or broader web research.

The [Git environment reference](https://git-scm.com/docs/git) informed the fixed,
clean environment and disabled configuration/replacement/protocol surfaces.
[Index plumbing](https://git-scm.com/docs/git-update-index) accepts explicit
blob identities without running worktree filters. [Commit plumbing](https://git-scm.com/docs/git-commit-tree)
builds the reviewed tree with its real base parent; a separate narrowly controlled
publication creates the local ref. Diffs use scoped object bytes and Python's
standard diff library, avoiding the optional external helpers described in
[Git diff](https://git-scm.com/docs/git-diff). No new dependency was added.
