# First project setup

Use the [installer](INSTALL.md), authenticate your own Codex account, and run
`ptw codex` in an existing canonical project directory, including an empty one.
The [quickstart](INTERACTIVE.md) covers ordinary use. This implementation is an
experimental Linux prototype. Final-source native installer and first-user timing
acceptance are still required; offline PTYs do not establish either.

## Scope and review

Setup detects Python, JavaScript, TypeScript and Python/Node mixed layouts from
bounded configuration. `--editable src,tests` selects directories;
`--files README.md,app.py` selects exact files, including missing files.
Nested source paths such as `backend/src,frontend/src` are accepted when their
parents already exist without links. Overlapping scopes are rejected.
Use an empty argument or `-` for no entries of that kind. Root-directory grants,
traversal, hidden/control/credential paths, links and special files are rejected.
Repository descriptions and previous logs never become permission sources.

The goal describes intent; selected typed fields grant authority. Configuration
and generated dependency locks are read only. Default package restrictions are
minimum age 3 days, reject CVSS >=9, evidence maximum age 900 seconds, no native
wheels and no source/install-script builds. These remain enforced by the existing
package controller before use; there is no deferred unchecked execution.
Advanced package-policy edits use the separate explicit policy review workflow.

## Local Python preparation

Local sources require explicit resources and backend approval. They are not
public packages and do not grant access to the repository. The manager passed
the 300-test local-Python suite, including native terminal/build/import fixtures;
see [measured coverage and limits](DEPENDENCY_STATUS.md#local-python-evidence).
These deterministic fixtures do not establish model behavior or full product
acceptance.

### Select source and installation mode

For an existing PEP 621 project with `src`, `tests` and a required README:

```sh
ptw codex --editable src,tests --files README.md --python-editable src --setup-only
```

`--python-editable src` selects live implementation paths. They must also be in
`--editable` or `--files`, must exist, and cannot contain backend paths or build
configuration. Include required metadata files and in-tree backend directories
in the selected scope. For a nested project, paths are repository-relative:

```sh
ptw codex --python-root backend --editable backend/src,backend/tests --python-editable backend/src --setup-only
```

Selected resources inside the Python root, its manifest and authoritative
dependency inputs form the source snapshot. Unselected files stay unavailable.
For a fixed wheel, replace the editable option with `--python-wheel`; any change
to a bound source then requires reviewed re-preparation. The modes are mutually
exclusive for a single project. Use `--python-source` when multiple dependency
authority files exist.

A requirements file may contain `-e .` (also `--editable .` or `--editable=.`)
for editable mode, or `.` for a wheel. `./` denotes the same Python root:

```sh
ptw codex --editable src,tests --files README.md --python-source requirements.in --python-editable src --setup-only
```

The file entry alone never approves a build. Match it with the explicit mode.
Includes and constraints stay hash-bound through discovery, installation and
reuse. A root entry is required when combining requirements authority with
root-project preparation; its dependencies cannot be silently omitted. Mode
mismatches, duplicate entries, traversal, absolute paths, symlinks, URLs,
environment expansion, inline tool options and local entries in constraints
fail closed.

Select extras with `--python-extras web` and groups with `--python-groups test`.
A root entry `-e .[web]` also requires the corresponding explicit extra selection.
Unknown or duplicate selections fail; empty extras are valid. Self-referencing
extras such as `all = ["local-demo[web,test]==1.0"]` use a bounded local closure,
including cycles, without querying a public namesake. Incompatible local versions
or unknown active extras fail. Unselected extras remain validated metadata and
do not authorize installation.

### Review, preparation and normal use

For static metadata, setup parses declarations and assesses runtime/build
dependencies before review without importing a backend. The review shows source
identity, snapshot, live paths, interpreter, package rules and offline execution.
Use `details` to inspect resources and artifact bindings. `reject`, `cancel`,
EOF or Ctrl-C authorizes no backend execution or publication.

Only `yes` authorizes preparation. A pending controller gives each preparation
session access to its approved source; ordinary sessions stay blocked. Builds
receive disposable source copies and assessed wheels without the original
checkout, ambient configuration, credentials or network. Readiness requires
validated output, unchanged inputs, closed preparation credentials and confirmed
workload termination. Missing tools/artifacts, backend errors and interruption
fail without an unconfined fallback or automatic dependency approval.

After successful `--setup-only`, run `ptw codex` for protected work. Package
reuse checks source grants, command inputs, fixed configuration and installation
integrity. Pure-Python live edits appear on the next import, subject to the dynamic
metadata restrictions below. A narrower command or delegate cannot access a cached
installation unless it has every required source and package grant.

For fixed-input changes, repeat setup with `--revise` and the intended flags.
Rejection leaves the existing registration active. Once replacement publication
starts, old work stops; failed preparation retains history and requires a fresh
reviewed retry. Attempts and stopped identities remain in private operator state.
Concurrent user edits are preserved and recovery conflicts require inspection.
Do not edit generated pins or delete locks to bypass a binding failure.
`--revise --setup-only` prepares and exits; `--setup-only` cannot accompany
`--status`, `--stop` or `--review`.

### Dynamic metadata and additional build requirements

For unknown version, dependency or optional-dependency metadata, select the
required metadata/backend resources and use the same local mode, for example:

```sh
ptw codex --editable src,tests,metadata --python-wheel --python-source pyproject.toml --setup-only
```

`Approve metadata discovery?` authorizes offline hooks and a wheel build to
inspect metadata, not installation. Discovery wheels are discarded. A hook's
nonempty additional requirements are resolved under the original constraints and
package rules, then require `Approve additional build requirements?` before
execution. The discovered identity/dependencies and assessed runtime graph appear
at final policy review. That review needs another `yes` before installation.

Dynamic editable mode additionally requests `Approve build requirement discovery?`
for its distinct editable hook. Wheel and editable hook constraints both apply
to that source. Every refinement retains the same pending controller, source
binding and violation history. Rejection, cancellation, mutation or stop prevents
further discovery/publication. Retry with a fresh review after correcting the
cause; backend output never grants dependencies by itself.

For static metadata whose backend requests undeclared additional requirements:

```sh
ptw codex --editable src,tests --python-editable src --python-build-requirements --setup-only
```

This first requests approval for the selected mode's requirement hook, then
approval for any assessed additions, then final installation approval. An empty
proposal skips the additional-requirements review. Without the flag, ordinary
static setup retains one review; missing requirements fail offline. The flag is
for static hook discovery; dynamic metadata already has its own discovery flow.

Dynamic optional metadata still needs explicit `--python-extras feature`.
Discovery must supply that extra, retain static declarations and produce valid
requirements, even for inactive extras. Changed metadata in the installation
build denies publication. The adapter handles conventional final
`extra == "name"` guards, optionally conjoined with environment markers; other
boolean layouts currently fail closed.

Dynamic metadata inputs remain fixed during editable reuse. Declarative
setuptools file directives without plugins, setup.py or setup.cfg bind referenced
files even inside live trees. Attribute directives, custom backends and plugins
conservatively bind all inputs, including added files. Changes require reviewed
re-preparation; arbitrary dynamic backends do not promise live implementation edits.

### Compiled code and live Python edits

Request native output explicitly:

```sh
ptw codex --editable src,tests --python-editable src --python-native-wheels --setup-only
```

Use `--python-wheel` for a fixed native wheel. The review must show
`native wheels True`. The flag also permits assessed native dependency wheels;
it does not relax age, CVSS, hashes, runtime checks or backend approval. Without
it, a permitted backend may run but native output is rejected before installation.
Wheel tags must agree with the payload and selected runtime.

Provision compilers and development headers through trusted host setup first.
Compiler paths must resolve inside the mounted system runtime; host
`/etc/alternatives` aliases are unavailable. Select a concrete `/usr` compiler
in reviewed configuration. Ambient `CC`, `CFLAGS` and `LDFLAGS` are not inherited.

Simple static declarative setuptools extensions can use a projected build view.
Only simple src-layout implicit namespace discovery, setuptools/wheel build
requirements and explicit extension `sources`/`depends` qualify. Live `.py`
implementation files are absent from the build, including its read-only seed.
Original manifest bytes, directories, non-Python files, fixed resources and
explicit build dependencies remain bound. This is an enforced input view, not
an inference about what a compiler reads.

Wrapper edits and added Python modules in an existing approved directory can
then appear at the next protected import without rebuilding. Added headers,
changed C sources, declared Python build dependencies, deletion and type changes
in the visible build view deny stale reuse. A build that requires an omitted
file fails without automatically expanding its view.

To compile with every approved source file, explicitly review full binding:

```sh
ptw codex --revise --editable src,tests --python-editable src --python-native-wheels --python-full-build --setup-only
```

Full binding requires rebuilding even after wrapper edits. Custom backends,
setup.py/setup.cfg, dynamic metadata, opaque compiler/linker arguments, extra
objects and unsupported discovery also use full binding. They remain buildable
after approval. Older compiled receipts use full original-source verification.
There is no automatic broader retry. `--python-full-build` also works with
`--python-build-requirements` and multiple sources; the selected view stays bound
through every review. Existing `ptw-requirements.txt` remains a resolver preference
and a bound input during revised hook discovery.

Validated in-place libraries and site-packages payloads stay in the private
package set. They enter only disposable command snapshots with complete grants;
no generated library is written into the host checkout. Prepared-library changes
cannot be published as source edits. Symlink-based editable trees, generated
parent directories outside selected resources and uncontrolled network builds
are outside this adapter. Existing file/tree/build limits still apply.

### Authoritative uv locks

For a static project with `uv.lock`, use the same explicit mode. Native locked
export retains runtime versions/hashes while assessed build requirements are
resolved. Inspect lock authority and bindings in `details`. A stale lock or
incompatible exact constraint fails without silently overriding pins.

Dynamic locks first supply candidate versions/hashes through frozen export.
This does not certify freshness. Discovery and additional build reviews precede
final approval, which explicitly authorizes native offline locked validation
before installation. The original manifest and lock are read-only in that
namespace, with the assessed build environment. A fresh registry-only uv cache
supplies metadata; executable source stays out of the networked resolver.
Unavailable metadata, stale locks, changed inputs or inconsistent backend output
fail without lock repair or online backend execution. Correct the project through
operator tooling, then repeat review. The validation receipt is checked before
publication and reuse. Private-origin locks and local Poetry preparation still
require their own adapters and fail closed here.

### Multiple local projects

For two projects, `requirements.in` can contain:

```text
-e ./packages/one/
-e packages/two
```

Select resources separately:

```sh
ptw codex --language python --python-source requirements.in \
  --editable packages/one/src,packages/one/backend,packages/two/src,packages/two/backend,tests \
  --python-editable packages/one/src,packages/two/src --setup-only
```

Omit backend directories for assessed external backends. Local paths are relative
to the selected Python root; `-r` includes stay relative to their containing file.
Leading `./` and trailing `/` are normalized. Per-source extras use
`packages/one[feature]`. Plain entries select wheels and must not have mutable
paths in `--python-editable`; for an all-wheel list use `--python-wheel`.
Mixed wheel/editable entries are supported.

Review lists each source's mode, scope, snapshot and build graph. Each backend
runs in its own source namespace and build environment, so incompatible build-only
tool versions can coexist. One shared compatible runtime graph is installed.
Local-to-local runtime references use reviewed versions and extras, never registry
namesakes. They grant no access to another source during building. Local packages
in build requirements currently fail closed.

Dynamic sources each require discovery and any wheel/editable hook reviews.
Static sources can request per-source hooks with `--python-build-requirements`.
Static/dynamic entries may coexist. Each selected project may retain its own
`uv.lock`: static locks use locked export; dynamic locks require per-source
approved offline validation. An unselected root lock is rejected; include `.`
or `-e .` only when the root is an intended source.

The trusted assembler publishes one package set only after every build, metadata,
artifact, source, authority and termination check succeeds. Duplicate identities,
file collisions, conflicting runtime constraints, failure of a later build or
validation, mutation and stop leave no usable partial installation. Each source
must fit both the command inputs and session grants at reuse. Changing any lock
blocks reuse until reviewed re-preparation.

Local Poetry integration and broader ecosystem gates remain required queued
work. These limits do not waive ordinary required formats. See
[current status](DEPENDENCY_STATUS.md) for measured versus unverified behavior.

The concise review shows scope, commands, packages, warn1/stop3 and two tasks.
`details` expands command argv/inputs and generated file contents. `customize`
changes scope/thresholds and creates a fresh review. Only `yes` approves. Both the
policy/inventory and generated-content plan have displayed hashes and a retained
operator approval. Blank/invalid input, rejection, cancellation, EOF and Ctrl-C
leave project files unchanged before publication. Invalid attempts stay in private
state, not the repository.

No model is needed to compile the template. `--model-proposal` explicitly requests
one optional model call to clarify descriptions, subject to exact trusted
authority equality, including every package field. It cannot expand or silently
narrow the reviewed scope. Selected `--history` is evidence only and does not
invoke that option. Invalid model responses are retained and rejected.

## Commands and current layout boundaries

Python templates check selected Python sources without executing them or writing
bytecode. Selected test directories get pytest when present in reviewed pins,
otherwise unittest discovery. Empty discovery fails. Root-only `app.py` works
without fabricated `src/` or `tests/` directories. A syntax check is not a test.

Node templates expose reviewed test/build/lint/typecheck scripts. When no test
script exists, selected test directories use bounded `*.test.js`/`*.spec.js`
discovery (also cjs/mjs); no matching files fails. A selected single root JS file
gets a syntax check. Script exit zero alone does not prove a nonempty test suite;
the native acceptance requires an independent functional oracle.

New TypeScript metadata uses the pinned compiler through normal checked package
installation. Generated tsconfig includes selected paths and publishes to `dist`
only if that directory is selected; otherwise it uses noEmit. Existing reviewed
scripts/configuration determine existing-project commands. Work commands may
publish changes only to editable grants. The `verify` task has read-only grants
and only known no-output syntax commands; arbitrary repository scripts are not
assumed read only. Commands remain bounded by the existing workspace snapshot
limits and 120-second timeout.

Python templates select an installed interpreter under `/usr` that satisfies the
original `requires-python` and, when present, one numeric `.python-version`
request. `--python /usr/bin/python3.12` explicitly selects the interpreter for
review. No interpreter is downloaded. The executable hash, version, ABI and
requirements are bound to approval, package preparation and command reuse.
Existing older policies keep their original system-Python behavior.

Root-level mixed manifests and `backend`/`frontend` layouts are detected. Use
`--python-root backend --node-root frontend` for explicit roots; choose source
directories within those roots. Commands receive their reviewed working directory
inside the synthetic command tree. This grants no repository-root mount.

Requirements `.in`/`.txt` files support bounded `-r`/`-c` includes, SHA256 hashes
and markers. Static PEP 621 projects support extras and dependency groups,
including group includes. Select `--python-extras web --python-groups test` as
needed. The default groups are existing `dev` and `test` groups. If requirements
and pyproject both declare dependencies, choose `--python-source` explicitly.
Original declarations stay unchanged. uv performs compatibility resolution with
an age cutoff and additive exclusions for confirmed unsafe versions, followed
by the shared evidence evaluator and artifact checks.

Native frozen uv/Poetry exports, npm workspace descriptors, private npm routing
and same-project dependency revisions are implemented. PEP 621 edits use uv's
TOML editor; uv lock updates retain declarations and use additive exclusions.
Selected groups/extras remain bound to the policy across revisions. See
[current dependency status](DEPENDENCY_STATUS.md) for the format matrix and
remaining native validation. Local Python preparation and private Python routing
have passed focused manager checks. The full native manager check passed all 32
[Poetry tests](POETRY.md), including approval terminals and compatible age/CVSS
selection. pnpm/Yarn completion and full ecosystem integration are still required.

## Publication and recovery

Metadata resolution, proposals, approval and failure records live under private
operator state outside the project. The installer preserves `PTW_USER_STATE` for
an explicitly chosen location; onboarding validates that it is private, canonical
and separate from project data. Other installer runtime overrides remain filtered.

After approval, preparation stays outside the repository. A durable `preparing`
journal precedes staging creation; no project file or controller changes in that
phase. A failed or interrupted preparation is retained as evidence, even if a
file is partially written or its identity has not been recorded. Recovery marks
that attempt rolled back and permits a fresh review and retry without deleting
unknown content. Two consecutive recoveries have the same effect.

Staging normally lives in the private attempt directory. If private state is on
another filesystem, staging uses a private random directory beside the project
so publication can still use same-filesystem renames. This requires a writable
project parent; inability to stage fails before any project mutation. The journal
records that external path for inspection, including incomplete attempts.
A project at a mount root needs private state on that same filesystem.

Once every staged object has a durable identity, the journal records all
destinations and old/new identities and exits preparation before any publication.
Publication uses no-replace Linux renames. Only the
review copy and private registration may replace previous files, with retained
backups. Ordinary generated destinations cannot overwrite collisions. The
controller activates a pending project, validates live resource identities and
published artifacts, then commits readiness under its lock. Pending projects
cannot register any sessions. Setup-only creates no session.

The next `ptw codex` recovers under the onboarding lock before launching. Before
controller commit, recovery undoes only matching transaction-owned effects and
restores backups. Pending controller records remain stopped as history. After
commit, recovery finishes bookkeeping without activating the identity again.
Approved revisions stop old work; rollback never revives that work or clears its
violation history. A terminal-launch failure after commit closes its session and
leaves the approved setup available for retry.

Concurrent edits are preserved as an explicit recovery conflict. Inspect the
private `setup-journal.json`, attempt directory and affected files before moving
conflicting operator data aside and retrying; do not delete controller history.
This includes unexpected files, modified generated files and nonempty directories
inside staging: rollback validates them before cleanup and preserves conflicts.
Partial preparation outside the repository does not block recovery or retry.
Existing-project multi-file changes
are recoverable, not atomically invisible to unrelated filesystem readers.
Filesystem timestamps are not restored by rollback. Host/operator processes are
trusted; the journal is not a defense against malicious same-account state edits.

## Measurement and verification

Thirty seconds means first installer invocation through fresh review and an idle
protected Codex TUI, including downloads, doctor, preparation and scripted human
input delays. Readiness also requires the actual MCP initialized notification and
matching response listing both protected tools, a live registered broker, an open
session and healthy monitoring. A quiet banner alone cannot establish readiness.
The private `first-ready.json` records that connection without credentials. The
first successful controller receipt and useful work verified by the independent
functional oracle are separate timings. Warm reopening is separately labeled.
The target remains unproven for this change. No new-account OAuth/MFA is claimed.

On an isolated VPS, after building an operator-verified release artifact:

    python harness/scripts/product_onboarding_acceptance.py --out /absolute/new-evidence \
      --bootstrap /absolute/release/install.sh --artifact /absolute/release/application.tar.gz \
      --sha256 THE_ARTIFACT_DIGEST --language python

Add `--existing` or select javascript/typescript for other fixture paths. This
manager-only command makes real model calls. It measures one continuous clock,
uses a fresh private installation, unsets inherited PYTHONPATH, checks installed
source hashes, and drives the existing real PTY/physical-oracle acceptance with
the installed interpreter. It records failures and reports a missed 30-second
target as unmet. Retain each failed run when retrying; do not combine a warm
retry with a fresh-install claim. The independent installer lifecycle remains
`python harness/scripts/product_install_acceptance.py --out /absolute/new-install-evidence`.

`harness/tests/test_product_onboarding.py` tests six new/existing template cases,
real terminal input/output with explicitly mocked external integrations,
root-file controller effects, failure rollback, cancellation and process-death
recovery. Preparation tests inject failure and process death after staging-directory
creation, after each staged object is created, during file writing/fsync and before
identity journal updates. They verify unchanged project data, preservation of
concurrent edits and external evidence, repeated recovery and successful retry.
They are fast offline behavior tests, not real Codex/native acceptance.
Use the [isolated source-test environment](README.md#run-the-tests) for controller
and service regressions. Fresh installed-user acceptance must remain a separate
wheel installation with no editable source or inherited PYTHONPATH.

## Design sources

- [Linux rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html): RENAME_NOREPLACE prevents destination overwrite; unsupported filesystems fail without a weaker fallback.
- [Node 22 filesystem API](https://nodejs.org/docs/latest-v22.x/api/fs.html#fsreaddirsyncpath-options): recursive readdirSync supports selected test-directory enumeration.
- [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) and [tool discovery](https://modelcontextprotocol.io/specification/2025-11-25/server/tools): readiness observes the initialized notification and the matching tools/list response on the existing relay. The SDK still owns the protocol and all request handling.

Policy schema, approval hashing, SQLite locking and package enforcement reuse
existing repository interfaces. Additional research adds nothing to those stable
internal interfaces; behavioral tests are the relevant evidence.
