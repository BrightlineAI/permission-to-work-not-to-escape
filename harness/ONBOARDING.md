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

`--python-editable src` selects live implementation paths for one existing Python
project at `--python-root` (the repository root by default). These paths must also
be in `--editable` or `--files`, must exist, and cannot include backend paths or
build configuration. For a nested project use repository-relative paths, such as
`--python-root backend --editable backend/src,backend/tests --python-editable backend/src`.
All selected source paths inside that Python root, plus its `pyproject.toml`, form
the explicit source snapshot. Include any required README or backend files in
the selected scope. A root project location does not grant access to the whole
repository. Unselected files remain unavailable.

For a fixed wheel installation, use `--python-wheel` instead of
`--python-editable src`. The two modes are mutually exclusive. For example:

    ptw codex --editable src,tests --files README.md --python-wheel --setup-only

This builds the explicitly selected project, validates its wheel and installs it
with uv offline. The receipt retains the wheel digest, source binding and build
tool identity. Local code is never given a registry publication date or public
package grant. The manager passed both wheel and editable setup fixtures.

Requirements files may now reference the selected Python
root as `-e .` (also `--editable .` or `--editable=.`) or `.` for a wheel.
Use matching explicit preparation flags; a file entry alone never approves a
build. For a `requirements.in` containing `-e .`:

```sh
ptw codex --editable src,tests --files README.md --python-source requirements.in --python-editable src --setup-only
```

For `.`, replace `--python-editable src` with `--python-wheel`. `./` also denotes
the selected Python root, including inside requirements includes. The adapter
adds that project's dependencies, selected groups and constraints to the existing
resolver input without submitting the local path or identity to a registry.
With `-e .[web]`, also select `--python-extras web`; undeclared or unselected extras
fail before tooling runs. Multiple authority files still require explicit
`--python-source` selection. Included requirements retain their input hashes.

Mode mismatches, duplicate local entries, local constraints, traversal, URLs,
environment variables and inline tooling options are rejected. Use `reject` or
`cancel` to decline the review. The manager passed the static root requirements
terminal fixtures in the 144-test suite. Other local paths and multiple local
distributions remain unfinished ordinary integration work; do not remove
dependency declarations to bypass a rejection.

For dynamic projects, the same command now retains the selected requirements
file and included constraints through metadata discovery, distinct editable-hook
review when applicable, and final installation review. A matching root entry is
required when combining requirements authority with local preparation; it cannot
silently omit the project's dependencies. Local version constraints are checked
against discovered metadata before installation, without querying a public
namesake. Includes remain hash-bound at every phase. A changed input or rejected
review stops preparation; correct it and retry the same command. The new dynamic
requirements terminal fixtures await manager validation. The dynamic editable
source-change restrictions below still apply.

Select optional dependencies from `project.optional-dependencies` using the
existing `--python-extras` option, for either installation mode:

    ptw codex --editable src,tests --files README.md --python-editable src --python-source pyproject.toml --python-extras web --setup-only

The concise review lists selected extras and their assessed dependency packages.
Names are normalized using Python packaging rules; unknown or duplicate selections
fail before backend execution. An empty extra is valid. Unselected optional
requirements remain metadata and do not authorize installation. Built metadata
must retain every declared extra and its marked requirements, and selected
dependencies must fit the assessed graph. No installation-time dependency lookup
or new approval is inferred. Use `reject` to decline; to change a selection later,
use `--revise` with an explicit mode and the new selection. The manager passed
these extras paths in the 65-test local suite.

An extra may select other extras of the same local project. For example,
`all = ["local-demo[web,test]==1.0"]` in `project.optional-dependencies` can be
selected with `--python-extras all`. Current source expands this bounded closure
against the reviewed local version, retaining registry dependency constraints.
The local name never becomes a public-package request. Cycles terminate without
repeated expansion; an incompatible local version or unknown active extra fails
before a backend runs. Local version constraints also apply to the source version.
Self-dependencies in `build-system.requires` fail because a project cannot supply
its own unbuilt backend dependency. The new native fixtures await manager checks.

For unknown dynamic version or dependency metadata, use the same local mode with
`--python-source pyproject.toml`. For example, for `dynamic = ["version"]` and an
explicitly selected `metadata` directory containing its inputs:

    ptw codex --editable src,tests,metadata --python-wheel --python-source pyproject.toml --setup-only

First review the source paths, interpreter, assessed build requirements and limits
at `Approve metadata discovery?`. `yes` authorizes offline requirement hooks and
a wheel build to inspect metadata; it does not authorize installation. No project files are
published and ordinary sessions remain blocked. Discovery wheel bytes are discarded.
The resulting version and dependency declarations are displayed, then resolved
with the existing compatibility, age, CVSS and artifact checks. A second policy
review must receive `yes` before a fresh confined build and installation. Declining
either review publishes nothing. Declining the second stops the pending identity
and retains its history. `details` expands either review. The same controller
identity spans discovery and installation; refinement retains violation counts
and cannot revive a stopped project. The manager passed this dynamic terminal
flow in the 74-test local suite.
Static optional dependencies retain their source declarations during dynamic
dependency discovery. They are not relabeled as newly discovered base requirements;
the final review still selects extras explicitly. Changed or omitted static extra
declarations fail output validation. The manager passed this combined terminal
path in the 88-test local suite.

For `dynamic = ["optional-dependencies"]`, use the same explicit extra selection:

```sh
ptw codex --editable src,tests --python-editable src --python-extras feature --setup-only
```

Include any metadata input files and in-tree backend in the selected scope.
The first approval authorizes discovery, without assuming the requested extra
exists. Built metadata must then provide that extra. Empty extras are retained;
unselected extras do not enter the installed graph. All discovered requirements,
including inactive ones, must be valid and cannot contain URLs. The final review
binds the discovered declarations and assessed selected graph. Missing extras,
changed static declarations or different output on the installation build deny
publication. Use `--python-wheel` instead for fixed output. `reject` or `cancel`
at either review publishes nothing. The new native fixtures await manager checks.
This adapter accepts the conventional final `extra == "name"` guard, optionally
conjoined with an environment marker. Other boolean layouts of extra guards
currently fail closed; they are not silently simplified or resolved as public
local-package names. They remain a metadata compatibility limitation.

Dynamic metadata inputs stay bound on editable reuse. For declarative setuptools
file directives without plugins, setup.py or setup.cfg, the referenced files are
fixed even inside an otherwise live source tree. Attribute directives, custom
backends and plugin builds conservatively bind all source inputs, including newly
added files. Changes then need reviewed re-preparation. No dependency is granted
automatically after a failed hook.

The internal `discover_build_requirements(store, token, source_id)` adapter now
collects a bounded requirement proposal using the same pending source credential,
offline assessed bootstrap wheels and supervised confinement. It calls the wheel
or editable requirement hook according to the approved source mode. Its receipt
binds source, policy, runtime, hook runner and bootstrap artifact hashes. It does
not change policy or install newly requested packages. The manager passed its
native tests in the 97-test local suite.

For dynamic wheel discovery, current source now resolves a nonempty hook proposal
under the original build constraints and package rules. Review the resulting
versions at `Approve additional build requirements?`. `details` shows the exact
graph and artifact identities. `yes` authorizes one confined metadata build with
those wheels; final installation still requires `Approve exactly this policy?`.
`reject`, `cancel`, EOF or interruption at the additional review stops pending
preparation without building a wheel or publishing project files. Source mutation
or shared stop invalidates refinement. The same project identity and violation
counts survive every approval. Requirements that conflict with original pins,
lack usable evidence or demand URLs fail closed. The adapter does not iterate to
grant further packages after a build failure.

The manager passed this dynamic sequence in the 103-test local suite.

For a static project whose backend requests additional build requirements, use:

```sh
ptw codex --editable src,tests --python-editable src --python-build-requirements --setup-only
```

Use `--python-wheel` instead of `--python-editable src` for a fixed installation.
Include an in-tree backend's directory in `--editable` when applicable. At
`Approve build requirement discovery?`, `yes` authorizes only the confined
requirement hook for the selected installation mode. Editable preparation calls
the editable hook, which may differ from the wheel hook. A nonempty proposal is
resolved and assessed, then shown at `Approve additional build requirements?`.
That approval still does not install anything. The final policy review must also
receive `yes` before preparation. An empty proposal proceeds directly to final
review. `reject` or `cancel` at any review publishes no installation; retry the
same command after correcting the project or evidence problem. Backend failure
does not automatically grant new dependencies.

This explicit flag keeps the existing single-review static setup available when
all build requirements are already declared. Without it, missing additional
requirements fail offline. Do not edit generated pins or treat a proposal as
approval. Dynamic metadata discovery retains its own flow; this flag currently
requires static metadata. The manager passed its wheel and editable terminal
fixtures in the 112-test local suite.

For a dynamic project, `--python-editable src` now follows metadata discovery
with `Approve build requirement discovery?` for the distinct editable hook.
The discovered metadata and original wheel-hook requirements remain bound.
Any editable-hook additions undergo resolution, artifact assessment and a separate
`Approve additional build requirements?` review. The final installation still
needs `Approve exactly this policy?`. Empty editable proposals retain the already
reviewed wheel-hook constraints. Every review uses the same pending controller;
rejection, cancellation, mutation or shared stop prevents installation. Retry the
same setup command after correcting the problem. Earlier attempt receipts remain
in private operator state. This combined dynamic/editable terminal fixture awaits
manager validation. The dynamic source-change restrictions above still apply.

Before approval, setup parses static metadata and resolves build-system and
runtime requirements using the existing age, CVSS, compatibility and artifact
checks. It does not import a backend. The review shows the local identity,
snapshot, live paths and offline backend execution. `details` shows every bound
resource and assessed artifact. `reject`, `cancel`, EOF and Ctrl-C before approval
execute no backend and publish no project files.

After `yes`, setup activates a pending controller. Its preparation credential
can build only the approved source; ordinary agents and delegates remain blocked.
The build receives a disposable source copy and assessed wheels, without the
original checkout, ambient configuration, credentials or network. Readiness
requires a validated installation, unchanged review inputs, closed preparation
credentials and confirmed workload termination. Backend errors and interruption
roll back owned setup files. Attempts and stopped controller history remain in
private operator state. Correct the source and retry setup with a fresh review;
there is no automatic approval. Concurrent user edits are preserved, and recovery
conflicts require operator inspection.

Prepared package IDs appear in the protected adapter's context only for commands
and sessions with all required source and package grants. The command boundary
checks those grants, current fixed configuration and installation integrity again.
For pure-Python installations, ordinary edits in live paths become visible on the next import. Changes to
metadata or backend files need reviewed re-preparation with `ptw codex --revise`;
that existing workflow stops the old project and retains its history.
For wheel mode, any change to a bound source resource blocks reuse until reviewed
re-preparation. A cached wheel cannot expose source to a narrower command or
delegate, even if that delegate can use every registry dependency.

For a local wheel containing native code, request the existing native-wheel
policy explicitly, then inspect the review and type `yes`:

```sh
ptw codex --editable src,tests --python-wheel --python-native-wheels --setup-only
```

This flag also permits assessed native Python dependency wheels. It changes no
age, CVSS, hash, runtime or source requirements. The displayed policy must show
`native wheels True`; omitting the flag keeps the default false. Declining the
review executes nothing. An approved source backend may compile in its offline
build, but native output without native-wheel approval is rejected before
installation. This output rule is distinct from approval to execute a backend.
Backend output tags must agree with the wheel header and selected runtime.
Install required compilers and system development headers through trusted host
provisioning first. The build cannot download missing toolchains or libraries.
Compiler paths must resolve inside the mounted system runtime. Host aliases
through `/etc/alternatives` are unavailable; select the concrete `/usr` compiler
in reviewed backend configuration. Ambient `CC`, `CFLAGS` and `LDFLAGS` are not
inherited, and setup does not mount host configuration to satisfy an alias.
The manager passed the terminal fixture that compiles and imports a tiny shared
C library. Current source also accepts the flag with `--python-editable src`:

```sh
ptw codex --editable src,tests --python-editable src --python-native-wheels --setup-only
```

The manager verified a setuptools compiled editable import, stale-source denial
and the explicit terminal rebuild lifecycle in the 136-test suite. Compatible native
site-packages payloads and in-place libraries inside existing reviewed source
directories are retained in the private package set. They enter only disposable
command snapshots with the complete source grants and validated build inputs.
Backend scratch outside those resources is discarded; no generated library is
written into the host checkout. Command changes to a prepared library fail before
publication. Compiled-input modification blocks reuse until another explicit review:

```sh
ptw codex --revise --editable src,tests --python-editable src --python-native-wheels --setup-only
```

`--revise --setup-only` reviews and prepares the replacement, then exits without
opening Codex. Rejection leaves the existing registration active. Once replacement
publication starts, old work is stopped; a failed build retains its history and
requires a fresh reviewed retry. `--setup-only` cannot accompany `--status`,
`--stop` or `--review`.

Current source permits live `.py` edits in explicitly mutable resources alongside
static, declarative setuptools extensions. Use `setuptools.build_meta`, declare
the extension `sources` and `depends` in `tool.setuptools.ext-modules`, and use
only setuptools/wheel build requirements. The new native fixture awaits manager
validation. C/C++ sources, headers, other non-Python files, directory structure,
explicit extension dependencies (even `.py` files), and build configuration remain
bound to preparation. Changing or adding these inputs requires the review above.
For example, editing a Python wrapper can change its next import without rebuilding
the extension; editing the extension's C source makes reuse fail until re-prepared.

Custom backends, setup.py/setup.cfg, custom setuptools commands, dynamic metadata
and ambiguous extension input declarations retain the full compiled-source
binding. They can still build after review, but cannot claim live Python reuse
of compiled output. Older receipts also retain their original binding. This is
declarative dependency handling, not discovery of arbitrary compiler inputs;
code generation or undeclared compiler dependencies need a fresh build. Automatic
rebuilds are not implemented. Builds needing symlink-based editable trees, generated parent
directories outside the reviewed source layout, or uncontrolled network access
are not covered by this adapter. Native artifacts keep the existing workspace
file/tree limits; no build or output limits are increased.

For a static PEP 621 project with `uv.lock`, use the same explicit local mode:

```sh
ptw codex --editable src,tests --python-editable src --setup-only
```

The locked export retains runtime versions and artifact hashes while the native
resolver adds assessed build requirements. Review `details` to confirm uv.lock
authority, inputs, packages and source resources. A stale lock or a build tool
incompatible with a locked version blocks setup; no pin is silently overridden.
The manager passed all 162 preceding tests, including the empty-graph terminal
flows and nonempty combined runtime/build graph wheel/editable fixtures. Dynamic
locked projects and local preparation with Poetry locks still fail closed.

This setup integration covers a static PEP 621 pure-Python project and
its assessed wheel dependencies. Dynamic native-lock build integration, additional local
requirements paths and multiple local distributions
remain required work in this milestone, not waived ordinary
formats. Broader backend support for live Python edits alongside compiled output
also remains incomplete.
Dynamic editable hook review and dynamic optional metadata passed manager checks.
External/VCS source paths and uncontrolled network builds remain outside the
bounded adapter. The manager passed the previous editable CLI flow, including
rejection, cancellation, failed-build rollback, retry and import after a live edit.
Measured results are listed in [dependency status](DEPENDENCY_STATUS.md).

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
pending native validation. Task 3 remains incomplete: Python editable preparation,
pnpm, private Python routing and Poetry updates are ordinary required gaps.

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
