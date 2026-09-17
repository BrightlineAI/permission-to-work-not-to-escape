# Retained dependency implementation records

This is an archive of the implementation notes before the final local-Python
documentation consolidation. The text below is preserved, including failed
attempts and superseded pending statements. It is not the current usage guide
or acceptance status. See [current dependency status](DEPENDENCY_STATUS.md) and
[local Python preparation](ONBOARDING.md#local-python-preparation).

# Dependency implementation status

Task 3 is incomplete. These changes are an implementation subset, not a claim
that all ordinary project formats work or that full ecosystem acceptance has passed.
The private-Python milestone has passed the focused native checks described below.
The immutable PRODUCT_ACCEPTANCE.json requirements remain unchanged.

## Current dynamic combined-lock milestone

The manager's `check-probe-1-19-1.log` in `task-9-1789633139555642351`
passed all 292 local tests in 792.751 seconds, with no skips. Guard and diff
formatting passed. Test-source SHA-256 was
`ec8df6510c75056aa9d56d3f6f419c4acd9322f5eb0bb7a662a259c9bddf9e01`.
This establishes the static multi-project locks described below.

The next bounded change connects combined dynamic projects to the existing
candidate exporter and approved per-source offline validator. Candidate export
never certifies freshness. The validator checks each original manifest and lock
before returning any installable payload, and the existing assembler publishes
only after every source succeeds. Runtime pins and artifact hashes stay shared;
build graphs remain separate. No new tooling interface, dependency or resolver
was introduced. The existing researched uv interfaces are unchanged; additional
web research would not establish this internal integration's correctness.

Seven new offline tests and two existing lock regressions passed in 35.437
seconds. Native methods were not selected. Documentation validation checked
49 documents and 239 local links successfully; syntax and diff checks passed.

New offline coverage checks discovery binding, per-source receipts, cross-source
receipt substitution, final rejection, mutation, second-validation rollback and
export hash substitution. A new manager-only terminal fixture uses two dynamic
locks, distinct synthetic build-tool versions and an actual public idna wheel.
Advisory/age records are explicitly synthetic. Initial resolution uses the
fixture's broker, while offline cache warming uses the declared public origin
through native uv. No ambient cache is copied or manufactured. The fixture
requires approval/details/reject/cancel behavior, two native validations, one
combined protected import, unchanged lock bytes, changed-lock reuse denial,
private-file integrity and an unrelated-process control. It is not a model run.

Failed attempts: system Python could not import the test module because cvss was
absent. The next five-test offline run had four passes and one incorrect test
assertion against package-set listing, which does not validate freshness. The
test now checks the execution mount boundary; that focused rerun passed. These
were test-environment and test-oracle defects, not native evidence. All offline
commands explicitly disable native discovery; no socket, systemd or environment
provisioning operation was attempted. Manager verification and final usage-guide
consolidation remain pending.

## Prior static combined-lock milestone

The supplied manager run `check-probe-1-18-1.log` in
`task-9-1789633139555642351` passed all 282 tests in 757.625 seconds, with no
skips. Guard and diff formatting passed. This confirms the preceding compiled
rebuild input-binding correction against test-source SHA-256
`b8d030c6a4af1950649232b492dbee33c6b85b8b7ba2dedb40d9f7567d2281d5`.

The next bounded change imports each selected static local project's original
`uv.lock` through the existing native exporter. All exported runtime versions,
origins and hashes must agree in the combined graph. Exact constraints retain
every selected transitive artifact. Build graphs remain isolated and can retain
conflicting build-tool versions. Root locks require explicit root selection.
Locks are bound as individual source resources through hook review, installation
and reuse. Stale inputs, mutation, unavailable evidence, conflicting artifacts
and failed builds cannot publish a partial installation. No new solver, tool
interface, dependency or automatic approval was introduced. This reuses the
previously researched native locked-export interface; further interface research
adds nothing to the internal graph composition and resource-binding change.

Nine new offline tests and ten existing multi-project regressions passed across
two selected runs (20.100 and 11.412 seconds). Tools, builds and monitoring are
mocked in these runs. The new manager-only native fixture requires stale-lock
rejection, real per-source builds, combined imports and live edits, explicit
terminal rejection/cancellation/details/approval, changed-lock reuse denial,
private-file integrity and an unrelated-process control. It uses synthetic lock
inputs and registry evidence; native uv must validate the original bytes.
It is not a model trajectory or evidence of real registry advisory quality.

Failed attempts in this increment: the first selection inadvertently included
the native fixture because PTW_LINUX_TESTS was inherited as enabled. That test
failed before reaching approval; no native success is claimed and it was not
retried. The same run exposed missing Requires-Python in the mock wheel, which
was corrected without relaxing output validation. The next offline run exposed
a test using the package-ID listing API as a reuse validator; the corrected test
asserts denial at the actual mounted-set boundary. Subsequent selections list
offline methods explicitly and disable native discovery. Native checks remain
manager-owned: sockets/network and systemd user-directory writes are outside
the coding sandbox's supported execution boundary. No environment was provisioned.
An initial manifest patch used file rather than manifest order and was rejected
without changes; it was regenerated in manifest order.

Pending: manager verification of this static combined-lock increment, combined
dynamic offline lock integration, and final practical-document consolidation.
The implementation records below retain prior attempts and their limitations;
earlier pending statements describe those checkpoints, not current acceptance.

The retained local-Python baseline passed all 197 tests, including dynamic
optional-dependency discovery, a setuptools compiled editable import and the
reviewed terminal rebuild and static and dynamic root requirements terminal
fixtures and static uv-lock wheel/editable terminal flows with empty dependency
graphs and nonempty combined runtime/build graph wheel/editable imports.
The manager's `check-probe-1-7-1.log` in run `task-9-1789633139555642351`
records 197 passes in 357.498 seconds, including the projected-build confinement
correction and the approved offline dynamic-lock validation/import fixture.
Its test-source SHA-256 is
`dc8db86b17cee1a6b7bf94537e1aa23d3f92346911b8f68da49187b185e00af3`.
The following manager run passed all 209 tests in 418.885 seconds after correcting
the lower-level fixture's missing preparation-termination confirmation.
`check-probe-1-9-1.log` in the same run records that result against test-source
SHA-256 `b4193c13a7ec60b6398d790ad8ef480bfe75f402b26135b7ba827e776930eafe`.
Guard also passed. The subsequent combined-installation manager check passed all
221 tests in 459.151 seconds with no skips. The retained receipt is
`check-probe-1-10-1.log` in the same run, against test-source SHA-256
`47dbe22dd095e99fefb90b174a152caa8757ccd22083f408062d162f7b7c9e9a`.
Guard and diff formatting also passed. The next manager result,
`check-probe-1-11-1.log`, passed all 228 tests in 471.705 seconds against test-source
SHA-256 `728a6f6a0c7fe23e0895fecc7e17afabb2e92114cde4659476b44d1c1f3b8372`.
It confirms separate source build graphs and conflicting build-tool versions.
The next check, `check-probe-1-12-1.log`, passed all 235 tests in 485.430 seconds,
including static multi-project CLI review, confined builds, imports and live edits.
Guard also passed. That result predates the local-reference changes below.

The next manager check, `check-probe-1-13-1.log` in the same run, passed all
246 tests in 532.365 seconds. Guard and diff formatting also passed. Its test-source
SHA-256 is `e967bf503bb8a79debd350cd0da69183daf9e72af7d9185a2ede17bf1b739082`.
This establishes the local-reference and explicit-lock terminal fixtures below.

The next manager check, `check-probe-1-14-1.log` in the same run, passed all
255 tests in 563.006 seconds. Guard and diff formatting passed too. This confirms
the multiple dynamic wheel terminal fixture against test-source SHA-256
`9ff6ec3a3bcc3761c8535674df5093f78a959bf1f06c61ecb55db3352dfdb9a7`.

### Multiple dynamic editable discovery

The manager's `check-probe-1-15-1.log` in run `task-9-1789633139555642351`
subsequently passed all 266 tests in 666.803 seconds with no skips. Guard and diff
formatting also passed. The test-source SHA-256 was
`53c3b0b8d6ea39c070312f6affb630ab9a9d4f2da0eb1f99797f0e230b7ddbf2`.
This establishes the dynamic editable terminal fixture described below; it does
not establish the subsequent static hook extension.

### Multiple static build requirement reviews

Current source accepts `--python-build-requirements` with multiple local paths.
It reuses the existing pending controller, per-source hook runner, assessed build
graphs and atomic combined installer. Static sources execute only their requested
wheel or editable requirement hook after approval. Nonempty hook proposals need
another explicit review, and all builds wait for final installation approval.
Metadata discovery remains specific to dynamic sources, including mixed lists.
Prior sources stay snapshot-bound and violation history survives every refinement.
Static hook receipts must match the installation mode and cannot supply dynamic
metadata in place of the manifest. Build dependencies remain isolated per source.

Seven new offline tests passed in 21.802 seconds. They cover mixed wheel/editable
build graphs, shared history, reject/cancel/EOF at every review, source mutation,
stop, local-name and URL injection, mismatched receipts and mixed static/dynamic
sources. Executable integrations were mocked; no native confinement is inferred.
The new native PTY fixture requires actual hooks, builds and a protected import
with conflicting build-tool versions. Both hooks and builds probe sibling/private
files and injected environment variables; rejection, cancellation, details and an
unrelated process remain asserted.

The subsequent manager check, `check-probe-1-16-1.log` in run
`task-9-1789633139555642351`, passed all 274 tests in 708.902 seconds with no skips.
Guard and diff formatting passed too. Its test-source SHA-256 was
`792046ba039ae0b24cd4d311aab5ba7e1fead257b646b1c43fd57d12b2cc6724`.
That result establishes the static hook terminal fixture described above.

A further 33 retained offline regressions passed in 95.401 seconds before that
manager run, covering dynamic wheel/editable discovery, local requirement parsing
and closure, and single-project hook review. Both selections explicitly disabled
and excluded native tests. No test attempt failed in the static-hook increment.
Syntax parsing, diff formatting and documentation checks passed (49 documents,
239 local links). Generated fixture backends were syntax checked without running hooks.

The method reuses the [PEP 517 wheel requirement hook](https://peps.python.org/pep-0517/#get-requires-for-build-wheel)
and the distinct [PEP 660 editable requirement hook](https://peps.python.org/pep-0660/#get-requires-for-build-editable).
The official specifications establish these interfaces, not native success.

### Full build selection during hook review

The next correction passes the operator's `--python-full-build` selection into
single-source and multiple-source static and dynamic hook reviews. Previously,
an eligible declarative setuptools project could review projected inputs for its
hook and full inputs for installation. The controller correctly rejected that
binding change. The correction preserves its strict equality check and shows
the editable native build view before approving a hook. Wheel modes and the
default projected view remain unchanged.

New offline regressions cover a naturally projection-eligible declarative source
through setup and stale-use denial, single and multiple dynamic source reviews,
mixed static wheel/editable reviews, and rejection of a changed build view at
controller refinement. One initial test assertion failed because generated final
metadata shifts inventory IDs. The corrected assertion compares every source
field with resource IDs mapped to their actual paths, matching controller
semantics; neither product authority nor existing tests were weakened.
All five new offline tests then passed in 16.211 seconds.
Nine retained offline regressions passed in 25.705 seconds, including default
projected reuse, full-input reuse, hook rejection/cancellation, mutation and
controller binding checks. Native tests were explicitly excluded from these runs.

The new native PTY fixture combines explicit full inputs, a requirement hook,
additional-requirement approval, real compilation/import, stale-use denial and
reviewed rebuilding. It retains reject/cancel/details/failure/retry and unrelated
process controls. This is internal option
propagation using existing interfaces, so additional web research adds no design
evidence; no new dependency or tool API was introduced.

The manager's `check-probe-1-17-1.log` in the same run executed 280 tests in
737.508 seconds: 279 passed and the new compiled editable hook fixture failed
during reviewed rebuilding, after its initial installation and import succeeded.
Guard and diff formatting passed. Test-source SHA-256 was
`d3f38b20bffb8d7a4b8d93b388f614f49467b96df712f63801896879d54799ed`.
The temporary terminal transcript was already removed by fixture cleanup.
An offline reproduction established that the initial empty discovery graph did
not bind existing `ptw-requirements.txt`, whereas the expanded graph did. The
unchanged preference file consequently looked like a changed metadata input.

Current source reads and hashes existing resolver preferences before returning
an empty graph. It reuses those same bytes for nonempty resolution, preserving
the exact input-equality check and treating preferences as preferences rather
than hard constraints. The new revision regression failed before this correction
and passes afterward. Negative cases separately change the real input and its
staged copy: the former denies before the hook, the latter before additional
approval, and neither publishes an installation. An initial negative assertion
expected the later rejection for a real-file mutation; it was corrected to assert
the earlier denial and zero executed hooks, with a distinct staged-mutation case.
Six focused offline tests passed in 15.974 seconds. Seven retained full-build
and resolver compatibility tests passed in 5.015 seconds, including exact-pin,
artifact-hash, critical-version, empty-graph and unavailable-evidence behavior.
These mock executable tool
integrations and do not establish native success. The original native rebuild
fixture and all its assertions remain unchanged, pending another manager check.
The first offline reproduction could not import `cvss` using system Python;
subsequent checks used the existing manager-provided isolated test interpreter
without provisioning or changing it. No new tooling interface or dependency is
involved, so web research adds nothing to this internal input-binding fix.

Multi-project authoritative native locks and final documentation consolidation remain mandatory
unfinished work. The native suite requires sockets/network and systemd user-directory
writes outside the coding sandbox's writable roots; neither it nor environment
provisioning ran in this sandbox.

### Dynamic editable implementation record

The current increment extends that passing flow with separate per-source PEP 660
hook approval, including mixed wheel/editable requirements. Prior metadata and source
snapshots remain bound, and each source keeps the union of its wheel and editable
hook constraints. Hooks resolve build requirements without importing another local
source or applying runtime constraints to build tools. This uses the existing uv
resolver, controller and atomic installer, with no new dependency or execution path.
Explicit controller refinement may update an assessed build graph; source identity,
mode, resources and snapshot bindings cannot change after editable-hook approval.

Hook-only authorization checks the pending source-bound session and build graph.
It parses runtime declarations but does not require the shared runtime graph before
discovery is complete. Actual builds and publication still validate all runtime
requirements and metadata. Native hooks receive only their own assessed build graph,
selected source, fixed interpreter and filtered environment.

New offline cases cover distinct approvals and violation history, reject/cancel/EOF,
mutation, stop, a local build-identity injection, incompatible and empty hook proposals,
mixed modes, build/runtime separation, and second-build rollback. The new native PTY
fixture requires actual isolated discovery, editable builds and a protected import
of two distributions plus their shared runtime dependency. It retains private and
sibling-file probes, environment injection, details/reject/cancel and an unrelated
process control. This fixture has not run in the coding sandbox.

The first two-test offline attempt exposed the premature runtime-graph check during
hook discovery; the wheel regression passed. The subsequent 15-test run passed 14
cases and exposed an incorrect rollback-test expectation: the existing adapter
deliberately replaces raw backend errors with a fixed public error. The test now
checks that public error, its original exception context, and absence of any partial
installation. The original single-project hook selection passed all 31 tests in
58.014 seconds. A following ten-case run passed nine and exposed a second test-only
error: an explicitly suppressed exception has context, not an explicit cause.
After correcting that assertion, the rollback case passed in 7.014 seconds.
Across these focused runs, all ten new offline cases and 39 retained cases passed.
This is not a complete native-suite result. Syntax parsing passed for seven touched
Python files, and documentation validation passed for 49 documents and 239 links.
No socket, systemd or source-environment operation ran in the coding sandbox.

The design follows [PEP 660's distinct editable requirement hook](https://peps.python.org/pep-0660/#get-requires-for-build-editable)
and its requirement for an environment provisioned with approved build dependencies.
The official specification was checked for this increment. Research establishes
the interface, not successful native execution. Dynamic-source mutation restrictions
remain unchanged. The static hook extension above follows this measured increment;
authoritative native locks remain mandatory unfinished integration work.

### Multiple dynamic wheel discovery

The current increment reuses the existing offline metadata and build-hook discovery
flow for each dynamic wheel source. Every discovery and additional build graph needs
its own approval. All refinements retain one pending controller identity and its
violation history. Earlier source snapshots stay bound while later backends receive
only their own source and assessed build dependencies. Conflicting build-tool versions
remain isolated. Discovered values feed data-only shared runtime resolution, then
final review and the existing atomic combined installer. The final build independently
checks metadata again. Source mutation, stop, rejection and runtime changes fail closed.
Local build identities cannot be replaced with public registry namesakes.

The new native terminal fixture must discover two wheel projects, review additional
conflicting build requirements, install once and import both alongside the shared
runtime dependency. It retains backend private/sibling-file and environment-injection
probes, explicit reject/cancel/details behavior and an unrelated-process control.
The manager subsequently verified it in the 255-test run above. The editable
extension is described separately; static additional-hook review and authoritative
native locks remain mandatory unfinished integration. No existing single-project
or compiled-input behavior was removed.

Two initial five-test offline attempts each failed one test. The first exposed a
real receipt-publication bug: the exclusive-create writer was called once per source
for the same final receipt. It now writes the final receipt only after all discoveries
finish; intermediate approvals remain in their unique stages. The second exposed a
mock that passed provider/runner keywords twice; the test seam now replaces those
keywords explicitly. The next five-test run passed in 10.311 seconds. These are
offline orchestration results, not native confinement evidence.

A broader focused selection passed 24 tests in 37.397 seconds, including the
eight new offline cases, retained local-reference/resolution coverage and six
single-project dynamic/lock regressions. Tests explicitly excluded native cases;
no sockets, systemd operations or environment provisioning ran. Documentation
checked 49 maintained documents and 239 local links. Native behavior still needs
the preauthorized manager checks against this increment.
After aligning per-source Python version requests and making combined-discovery
selection explicit, the eight new offline cases passed again in 12.140 seconds.
The final test-source SHA-256 for this handoff is
`9ff6ec3a3bcc3761c8535674df5093f78a959bf1f06c61ecb55db3352dfdb9a7`.

Design references are the official [pyproject metadata specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
and [PEP 517 build hooks](https://peps.python.org/pep-0517/#get-requires-for-build-wheel).
The implementation retains its bounded supported dynamic fields and explicit
approval of additional build requirements; it does not infer installation authority
from backend output or promise all metadata forms. No new dependency was added.

### Local runtime references and explicit lock dispatch

Current changes validate references between selected local sources against their
reviewed versions, extras and runtime markers. Extras propagate through a bounded
closure, including cycles. Only registry requirements reach uv; the local identity
never becomes a registry candidate. Local constraints restrict the reviewed version
without selecting sources or activating extras. Each build retains its separate
artifact graph and namespace. Backend output and final assembled metadata are
checked against all reviewed identities, then published atomically. An individual
install cannot publish an incomplete multi-source set.

The retained review's explicit `--python-source uv.lock` dispatch finding was still
present despite the passing baseline. Source discovery now defers that authority
to native locked validation, including when requirements files coexist. A failed
lock check never falls back to those requirements. New offline tests cover both
boundaries, and a native PTY regression retains review/reject/cancel/failure/retry
and protected import assertions with an explicitly selected lock.

The new local-reference native fixture builds a fixed wheel and an editable peer
using conflicting isolated build-tool versions. A cycle activates optional registry
work; the installed wheel imports the peer both before and after a protected edit.
Backend probes retain checks for sibling/private file access and environment
injection. Neither new native fixture has run in the coding sandbox.

These semantics follow the PyPA [dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/)
for versions, markers and unioned extras, and pip's
[constraints guidance](https://pip.pypa.io/en/stable/user_guide/#constraints-files)
that constraints restrict versions rather than trigger installation or request extras.
Existing packaging parsers and uv perform parsing and registry resolution; no
solver or dependency was added. Cross-source build dependencies, multi-project
dynamic metadata/hook reviews and native-lock integration remain unfinished.

Worker validation for this increment passed 185 explicitly selected offline tests
in 170.435 seconds, with `PTW_LINUX_TESTS=0` and native cases excluded. An earlier
28-test focused selection also passed; it overlaps the broader result. These
tests mock executable integrations and do not establish native success. Generated
native backend syntax and metadata were inspected without executing them.
Documentation checks found 49 documents and 239 valid local links.

Three earlier focused attempts exposed fixture construction errors: the namesake
probe omitted an unrelated required package and hit an earlier validator, added
metadata assumed a blank terminator absent from the synthetic wheel, and inserting
new tests displaced the end of an existing test. The fixtures and placement were
corrected; all original assertions remain. A safety assertion also stopped one
test-selection command before any test ran because several offline cases have
`native` in their names. The successful broader selection excludes those names.
No socket, systemd or environment-provisioning operation ran in this increment.
Both new terminal fixtures require the existing manager checks.

### Combined local installation prerequisite

Current source stages local installation payloads without publishing individual
Python sets. Each backend retains its own source-bound preparation session and
namespace. A trusted assembler installs the shared assessed registry graph once,
rejects distribution/file collisions and revalidates every source before publishing
one directory and one database row. The existing one-set-per-ecosystem execution
rule is unchanged. Version 2 receipts contain per-source snapshot, runtime, tool,
lock and native-overlay bindings; legacy singular receipts retain their checks.
Every constituent source must fit both the caller's grants and command inputs.

Offline tests exercise assembly, second-build rollback, mutation, identical-file
collision rejection, publication failure, unconfirmed termination, stop, malformed
receipts and narrower scopes. The manager's native fixtures confirmed useful
imports and live edits with two confined sources and a shared synthetic registry
wheel. These are deterministic protected workloads, not model trajectories or a
completed multi-project terminal journey. Prior passing terminal tests remain in
the suite. Local-to-local runtime requirements now have the implementation above;
multi-project dynamic discovery/lock integration remains mandatory work.

The trusted preparation adapter now accepts an optional `build_dependencies`
object on each approved source, containing exact `pins` and assessed `artifacts`
with name, version, origin and SHA-256. The project descriptor then describes the
shared runtime graph. Preparation credentials require task package grants for
both graphs. Each backend receives only its own assessed build wheels and offline
constraints; its build-only dependencies are not installed in the published runtime
set. Final wheel and editable metadata are checked against the runtime graph,
independently of the build graph. New receipts bind each source's build artifacts;
missing or swapped bindings deny publication and reuse. Policies without this
field retain their previously reviewed union graph and receipt behavior.

Do not manually edit an approved policy or remove requirements to get conflicting
versions past setup. Current source connects static local requirement paths to
explicit CLI source selection and review, confirmed by the 235-test manager run.
See the [multi-project usage](ONBOARDING.md#local-python-preparation).
The new native fixture builds two local distributions using `builder==1.0` and
`builder==2.0`, with one wheel and one editable installation, then imports both
beside the shared runtime dependency. Backends assert the intended build-tool
version and absence of the runtime-only package; protected commands assert the
build tool is absent. It retains live-edit, environment-injection, narrower-command
denial and unrelated-process controls. Manager validation passed in the 228-test run.

The new requirements adapter preserves file-relative includes and uses the selected
Python root for local project paths. It normalizes leading `./` and trailing `/`,
rejects traversal, symlinks, duplicate roots and identities, malformed extras and
local constraints, and binds every original manifest and included input. One
compatible runtime is selected before resolution. The existing uv resolver gets
only derived registry declarations in isolated metadata directories, never local
paths or backend source. The returned policy retains original input hashes.
Runtime and each build graph share a 180-second/256-candidate ceiling; separate
build constraints can select conflicting build-tool versions. Native output and
evidence are checked by the existing resolver. All inputs are rechecked before
returning the plan and before transactional publication.

New offline coverage checks path/extras interpretation, malformed inputs, duplicate
identities, conflicting build pins, unavailable evidence, mutation, incompatible
runtimes, namesake rejection, per-source review and mutable scopes. The new native
PTY fixture requires rejection, cancellation, details, approval, actual resolution,
confined builds with distinct tool versions, import of both distributions and the
shared runtime wheel, no installed build tool, and a protected live edit. It also
checks environment injection, unchanged private files and unrelated-process survival.
This is deterministic native acceptance, not a model trajectory. Multiple
dynamic/locked sources still fail closed and are required remaining work.

One worker test selection mistakenly relied on skip decorators while inheriting
`PTW_LINUX_TESTS=1`. Its 228-test attempt produced 4 failures and 48 errors,
including read-only systemd-directory, denied socket and unavailable-network errors.
It is invalid native evidence and does not supersede the manager result. Those
checks were not retried here; subsequent worker selections explicitly exclude
native test names and clear the native-test flag. Two new offline test errors
were fixture-directory reuse, corrected by allocating a fresh directory per attempt.
The explicit offline selection then passed 176 tests in 150.608 seconds. After
the final containing-directory rejection and evidence-outcome correction, the
focused discovery plus existing ecosystem compatibility selection passed 33 tests
in 10.315 seconds. These selections overlap and are not a native acceptance count.
Documentation validation checked 49 documents and 238 local links successfully.

The accepted subset follows the official
[requirements file format](https://pip.pypa.io/en/stable/reference/requirements-file-format/).
Its documented environment expansion is deliberately rejected at this boundary;
only reviewed path and package data enter the resolver. This is a bounded adapter,
not an implementation of every pip requirements option.

The separation follows [PEP 517 build environments](https://peps.python.org/pep-0517/#build-environment)
and keeps uv's existing offline
[build constraints](https://docs.astral.sh/uv/reference/cli/#uv-pip-install--build-constraint).
These sources justify separate environments, not successful native confinement.

Worker validation of this increment ran 164 explicitly selected offline tests in
148.082 seconds, all passing. The initial system-Python invocation could not import
`cvss`; tests then used the existing manager-prepared source environment without
installing dependencies. The first focused run in that environment passed five
tests and found a missing `scan` argument in the sixth test fixture. Correcting
that argument preserved its missing/swapped-receipt rejection assertions; the
broader passing run includes the corrected test. Native socket/systemd tests were
not attempted in the coding sandbox.

This patch reuses internal preparation, installation and controller APIs with no
new tooling switches or dependencies. Additional web research would not validate
its transaction semantics; offline fault tests and manager-native effects do.

The first six focused assembly tests passed in 8.110 seconds. A broader run
executed 170 offline tests in 141.771 seconds: 169 passed and one fixture retry
failed because it reused the previous attempt's evidence directory. The
no-overwrite guard correctly refused that reuse. The retry now uses a new
directory; it and three singular-installation/lifecycle regressions passed in
5.506 seconds. No native test was run in the coding sandbox. The manager must
run the existing local-Python check for the new two-editable, mixed wheel/editable
and second-backend-failure fixtures before their effects are claimed. One
documentation patch failed to match its context; the corrected patch succeeded.

## Implemented in current source

- Static requirements `.in`/`.txt`, confined includes and constraints, hashes,
  markers, PEP 621 dependencies/extras and dependency-group includes.
- uv compatibility resolution with the configured age cutoff and independent
  artifact/advisory evaluation. Confirmed rejected versions become additive
  exclusions. Original exact pins and artifact hashes cannot be overridden.
  Bounds are eight rounds, 256 candidate assessments and a 180-second deadline,
  checked between evidence calls as well as for resolver subprocesses. A single
  in-flight evidence request may run until its existing transport timeout.
- Separate results for solver conflicts, evidence/transport unavailability and
  exhausted budgets. Candidate exploration does not change violation counters.
  Each attempt records inputs, tool/runtime hashes, rejected candidates and outcome.
- An installed system Python under `/usr`, selected against the unchanged
  requires-python declaration and optional numeric `.python-version`. Runtime
  identification does not import user/project code. Tool downloads and arbitrary
  interpreter-directory mounts are not supported.
- Python declaration, resolution and registry artifact identities bound into
  the approved bundle. Changed inputs block install/reuse. Newly published
  package sets bind to their policy revision; old incompatible sets cannot be
  reused under a different reviewed runtime.
- Root-level Python/Node projects and one Python backend with one Node frontend.
  Explicit nested source grants and command cwd remain inside the synthetic
  command tree. No whole-repository mount is added. Python startup hooks use the
  actual mounted package directory in both launch modes.
- Native uv and Poetry lock exports with manifest consistency and artifact-hash
  checks. Dynamic uv sources use candidate-only frozen export, explicitly approved
  discovery, and offline locked validation before local installation. Unapproved
  dynamic sources still fail before native execution: `--no-build` alone does not
  prevent editable or first-party backend execution.
- npm lock v2/v3 graph checks, native age cutoff and bounded CVSS candidate
  exclusions. TypeScript shares npm policy. Yarn Classic v1 imports use npm;
  review explicitly identifies migration to npm authority and retains yarn.lock.
- npm workspaces and in-tree `file:` dependencies, including sibling references.
  Parent directories cannot be symlinks. A file dependency must resolve to its
  exact local source path, not a registry package with the same name/version.
  Local packages use approved source resources, not fabricated registry evidence.
- Narrower commands select complete source resource sets, mask excluded local
  packages, and use current authorized snapshots. Cached environments contain
  no application source; full-workspace lock metadata is removed before reuse.
- Exact-name private npm routing through the trusted broker. Credentials are
  external private operator files. Resolver metadata, artifacts, receipts and
  model results never intentionally receive credentials. Private advisory
  evidence must identify the origin/name/version and declare complete coverage;
  an empty public advisory lookup is insufficient. The native test below is
  still needed to validate the complete credential-confinement path.
- Same-project journaled dependency revisions preserve counters, unrelated
  grants and task identities. Approval revokes sessions and stops registered
  work before publishing. Recovery preserves concurrent edits and stop state;
  it never reopens old sessions. Unrelated package authority is retained.
- Metadata subprocesses see staged metadata, system runtimes and public network
  configuration, with an environment allowlist and isolated home/cache. They do
  not mount the host home or project. They have networking for metadata only;
  this is not an application network capability. Build and application execution
  keep the existing offline supervised boundary.

## Format and revision boundary

| Format | Import/setup | Operator add/remove/update |
|---|---|---|
| requirements.in/txt | Confined includes, constraints, hashes, markers | Select the direct declaration file; unrelated lines remain intact |
| Static PEP 621 | Selected extras and dependency groups | uv edits TOML; only the selected array may change semantically |
| uv.lock | Native locked export | Native constraint-only re-lock, then independent frozen export/evidence checks |
| Poetry lock | Native consistency check and official export plugin | Not implemented |
| npm v2/v3 lock | Root, workspaces, in-tree file sources | Root or reviewed member package.json; native npm re-lock |
| Yarn Classic v1 | Reviewed npm migration | Subsequent changes use npm authority |
| pnpm v9 lock | Not implemented | Not implemented |

For uv re-locking, `uv add --no-sync --raw` receives an empty requirements file
and additive constraints. Rejected packages are explicitly unlocked; other
locked versions remain preferences. The original dependency declarations and
runtime requirement cannot change. A native feasibility test proves compatible
downgrade and exact-pin conflict with generated local wheels. The full production
re-lock/export path still needs native acceptance with registry artifacts.

Examples from the project directory, in the operator terminal:

```sh
ptw deps add 'idna>=3.10,<4' --ecosystem pypi --source requirements.in
ptw deps update 'idna>=3.10,<4' --ecosystem pypi --source pyproject.toml
ptw deps remove idna --ecosystem pypi --source pyproject.toml --group test
ptw deps update 'typescript@>=5.8 <6' --ecosystem npm --root frontend --group devDependencies
ptw deps add 'lodash@^4.17.21' --ecosystem npm --source packages/client/package.json
```

`--group extra:web` edits a PEP 621 optional group. Edits do not automatically
select additional install groups: the setup's groups/extras stay bound. Use
`details` to inspect the files and resolved versions. Only `yes` approves;
reject, cancel, EOF and interruption do not authorize publication. Successful
revision ends old sessions, so start protected work again afterward.

Complete Python local/editable format integration, pnpm, Poetry updates,
local executable/bin preparation and a unified preparation lifecycle for dynamic
build dependencies remain ordinary required gaps. They are not waived or labeled
unusual. The existing explicit registry source-build/lifecycle policies remain
available. Yarn Berry/PnP, arbitrary VCS sources, repository-selected plugins and
builds requiring uncontrolled downloads are outside the bounded adapters.

Poetry with its official export plugin must currently be supplied in the trusted
system runtime. The worker environment has no Poetry and only a Corepack pnpm
shim; a version probe attempted a registry lookup and failed DNS. No successful
tool download was observed. A shim is not a provisioned, pinned pnpm payload.
Do not invoke automatic Corepack downloads to satisfy this requirement. Trusted
isolated Poetry/pnpm tool provisioning remains implementation work.

## Private npm setup

An operator may pass `--npm-registry-config /absolute/operator/routes.json` to
setup. The private JSON file uses this shape, with credentials in another
owner-only file outside the repository:

```json
{"version":1,"packages":{"@company/example":{"registry":"https://packages.example.com","advisories":"https://advisories.example.com","credential_ref":"/absolute/operator/credential.json"}}}
```

Credential references must also be outside system runtime trees (`/usr`, `/bin`,
`/sbin`, `/lib`, `/lib64`, `/proc`, `/sys` and `/dev`) and the resolver's additional
host mounts (`/etc/ssl/certs`, `/etc/resolv.conf` and `/etc/hosts`). Both the named
paths and their resolved targets are excluded, including host mount aliases
pointing into data directories. Workers can read these mounts even when a file
is owner-only. Setup and broker reload reject these paths before reading credentials.
Use an operator data directory outside the project, such as a private directory
under the operator's home. Existing private-file ownership and symlink checks
still apply.

The credential file contains an `authorization` string. Configure exact package
names, not a fallback registry; the broker must not send private names to public
advisory services. The advisory endpoint is `/v1/query` and returns
`origin`, `name`, `version`, `coverage: "complete"` and an OSV `vulns` array.
Registry credentials go only to the configured registry origin. Redirects,
credential-bearing URLs and credential echoes fail closed. Production requires
HTTPS. Loopback HTTP is a test-only injection seam, unavailable to model callers.
No real private account was tested.

## Private Python setup and verification

Current source implements exact-name Python routing with
`ptw codex --python-registry-config /absolute/operator/python-routes.json`.
Use the same external owner-only configuration and credential-file contract as
private npm above, with canonical Python package names such as `company-example`.
The approved bundle binds the configuration hash, not the credential contents.
Requirements files and static PEP 621 declarations use native uv resolution
through a credential-free wheel view. Private uv/Poetry locks currently fail
closed pending a reviewed adapter; they are not silently re-resolved.

The private registry must provide Simple API JSON at `/simple/NAME/`, including
wheel hashes, sizes, upload times and runtime constraints, plus PyPI-compatible
release JSON at `/pypi/NAME/VERSION/json`. Its configured advisory origin must
provide the origin/name/version/complete-coverage envelope above. The broker
fetches artifacts and supplies uv with local view URLs, without upstream
authorization. Credentials are sent only to the configured registry origin;
a distinct advisory origin receives no registry authorization. The resolver
receives neither that header nor the operator's credential file.

For an existing project with `company-example>=1,<2` in `requirements.in`:

```sh
ptw codex --python-registry-config /absolute/operator/python-routes.json --setup-only
```

Use `details` to inspect `registry_config_sha256`, input hashes, selected versions
and package restrictions. Type `yes` only for the intended scope; `reject` or
`cancel` leaves the project unpublished. Then use `ptw codex` to start protected
work. Do not put authorization headers in project files, CLI arguments or model
prompts. Provision the credential JSON separately through the operator's secret
management workflow. Each private transitive name also needs an exact route.
There is no private-to-public fallback for configured names. A registry without
the required release and complete advisory evidence is blocked.

Wrong credentials or unavailable/malformed evidence block installation without
counting misconduct. A confirmed too-young or critical package request counts
against the approved escalation policy. No denied install publishes a usable
package set. Resolve operational failures in the operator configuration or
service, then retry; do not disable age, CVSS or digest checks.

The manager baseline for `PrivatePythonTests` passed seven unit tests and failed
the native fixture during uv resolution, before installation or import. The
next diagnostic manager run passed eight unit tests and again failed resolution:
uv returned code 2 with HTTP-method/status signals after fetching one listing
and before any artifact download. The wheel view implemented only GET, while
the pinned uv client probes wheel metadata with HEAD. The view now handles HEAD
through the same checked routes and bytes as GET, returns no response body,
and advertises no byte-range support. uv can then use its full-wheel metadata
path. The manager subsequently passed all ten private-Python tests, including
real authenticated resolution, installation and protected import of the generated
wheel. This is deterministic synthetic-fixture evidence, not an external private
account test or model trajectory.

The fixture emits a bounded
`PRIVATE_PYTHON_RESOLUTION` summary into the manager's retained check log before
temporary files are removed. It includes every recorded resolver attempt's
return code, fixed diagnostic labels, metadata-view counts, fixture stage counts,
and tool/runtime/source hashes. It excludes raw subprocess output, request URLs,
headers, configuration and credential contents. Diagnostic labels describe text
observations, not policy decisions or a proven root cause. The protected import
must also assert the generated wheel's known exported value.

The expanded suite adds install-denial effects for wrong credentials, release,
filename and advisory identity, altered bytes, young/critical releases, missing
coverage, malformed severity/JSON and service outage. It also probes the actual
resolver, supervised build and protected application boundaries for ambient
environment injection and attempted access to the external synthetic credential
file, checks unchanged policy identity and verifies unrelated work survives stop.
The manager passed all 13 private-Python tests with no failures or skips in
6.868 seconds on 2026-09-17, including these expanded native assertions.
All 13 denied installs published no package set. The eleven operational/evidence
failures left the violation count at zero; young and critical requests raised
it to one and two. The subsequent valid install and protected import succeeded
under the unchanged policy, with both violations retained. Resolver, build and
application isolation probes passed, and unrelated work survived project stop.
The retained receipt is `check-probe-1-2-1.log` in manager run
`task-8-1789612512736493724`; its test-source SHA-256 is
`3a8da7bc8fef2c1426e031a9c8cbea6f97c57d6ba3aa2628a519e77419a172b7`.
The same run passed the immutable-intent guard. Raw logs stay outside the checkout.
The build probe exercises the existing offline boundary, not a new source-build
adapter; wheel resolution never authorizes a build backend.

Review then identified that an owner-only credential file in a system runtime
tree could still be read through worker mounts. Credential validation now reuses
the policy's data-directory restriction during setup and before broker reads,
including reload. Synthetic tests reject runtime paths, symlink aliases, relative
paths and malformed references for Python and npm before any credential read.
The manager passed all 15 private-Python tests with no failures or skips in
7.312 seconds on 2026-09-17, including the same native install, import, denial
and isolation assertions. The retained receipt is `check-probe-2-0-1.log` in the
same manager run; its test-source SHA-256 is
`2b4486d0d2bbade4683a1beea0e169160c8119c12777c2fa745999e371d24180`.
Its runtime-source hashes match that implementation, and the associated
immutable-intent guard passed. This supersedes the earlier result for this
milestone; it does not establish the remaining ecosystem gates.

Fourteen non-native tests pass in the manager-prepared editable-source environment,
including actual CLI PTY rejection, cancellation and approval with doubled
login/monitor integrations. The in-memory HTTP handler test covers HEAD, full GET,
cache reuse, rejected paths/methods and tampered bytes. Other unit cases check
separate advisory-origin authorization and embedded wheel identity. These unit
and PTY checks are separate from native installation evidence.

The manager's subsequent `check-2-1.log` passed all 15 tests without skips in
7.707 seconds, including runtime-tree path validation. Review then identified
an additional accepted location: the resolver mounts `/etc/ssl/certs`, which
the general runtime-tree restriction did not exclude. Credential validation now
also uses the resolver and build runtime mount declarations, checking their
resolved host targets. Synthetic tests cover CA-directory references, mount
aliases pointing into data directories, setup and broker reload before credential
reads, and an allowed sibling path. They never read credentials from system trees.
Twenty selected non-native tests pass against this correction, including Python
and npm routing and the existing CLI PTY review tests with mocked login/monitor
integrations. The existing successful external-credential native journey remains
unchanged. The manager subsequently passed all 17 private-Python tests without
failures or skips in 7.515 seconds on 2026-09-17, including the added mount
exclusions and the native journey. The retained receipt is `check-baseline-1.log`
in manager run `task-8-1789614885942527504`; its test-source SHA-256 is
`ace0e6eba8b52aebab77b6f58f389ace0ecc8946a989f9202d20554bc2acd1cb`.
All four recorded runtime/test source hashes match this implementation, and the
associated immutable-intent guard passed. The native assertions again confirmed
actual wheel installation and protected import, resolver/build/application
isolation, all 13 denied installs without a published package set, retained
violation counts and unrelated-process survival. This supersedes the earlier
private-Python results for the corrected source; other ecosystem gates and
external private accounts remain unverified. Raw logs stay outside the checkout.
This correction changes no tooling interface or dependency; local mount
construction and retained manager receipts establish the finding and verification,
so additional external research adds no evidence.

The HEAD compatibility fix follows the pinned
[uv 0.12.15 wheel client](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-client/src/registry_client.rs).
The credential-free view follows the
[Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/).
The added denial and isolation tests reuse existing interfaces and dependencies;
they introduce no new resolver or transport API.

## Validation and reproduction

### Current dynamic uv-lock setup integration

Use the same explicit `--python-wheel` or `--python-editable src` setup command
for a dynamic project with an existing uv.lock. Include in-tree backend resources
in the selected scope. The discovery review binds both original files. Backend
requirement additions retain their own approval; editable setup also reviews its
distinct hook. Candidate exports identify artifacts for independent assessment,
but are labeled `candidate-only` and cannot establish lock freshness.

The final review explicitly authorizes a confined offline freshness check before
installation. A successful `--locked` check is required, even when the candidate
graph already resolved. The original manifest and lock remain read-only in that
namespace. Setup retains the validation receipt with the installation and checks
its source, policy, runtime, groups/extras, tool, inputs and dependency bindings
before publication, readiness and package mounting. Missing or obsolete receipts
require new reviewed preparation. Failed validation does not publish a usable set
or add misconduct violations. No lock is repaired or dependency pin overridden.

Offline regressions exercise both installation modes, hook/final approval,
rejection, stale-validation rollback, input mutation and missing/forged receipts.
New native terminal fixtures exercise discovery, details, reject/cancel,
failed-build retry, validation, import and stale source denial. Both passed in
the manager's `check-probe-1-8-1.log` in run `task-9-1789633139555642351`.
That run finished 209 tests in 416.857 seconds with one error and no skips,
against test-source SHA-256
`8dbcd0a101c9509b8c0a5fe5222a69bbccd2c941d1849397fc0d1cd71e312d7c`.
Guard passed. The lower-level dynamic-lock fixture closed its preparation
session and immediately called setup commit without reconciling its workloads.
The controller correctly refused unconfirmed termination. Production setup
already reconciles before committing. The fixture now follows that lifecycle,
checks actual stopped state for every recorded unit, and validates the prepared
receipt at commit. The offline regression also checks that a failed termination
confirmation still blocks both commit and ordinary registration. No readiness
gate or native assertion was relaxed. The subsequent manager run passed all 209
tests in 418.885 seconds, as recorded in the current baseline above.
For this correction, ten selected offline lifecycle/setup/receipt tests passed
without skips in 21.191 seconds using the manager-provided source-test Python
with native tests explicitly disabled. An initial system-Python attempt failed
all ten imports because `cvss` was absent; it executed no test bodies. No
environment was created or modified. Native tests were not retried in the
coding sandbox, where systemd user configuration is read-only and networking
is restricted. Documentation verification checked 49 documents and 237 links.
An initial nine-test offline run passed eight tests and found a receipt runtime
descriptor mismatch. The receipt now binds the approved runtime descriptor and
independently verifies the exporter's interpreter; the focused retry passed.
An invalid broader worker run inherited `PTW_LINUX_TESTS=1`, so its selection
unexpectedly included native tests: 88 ran, with 2 failures and 19 errors in
91.830 seconds. Native attempts reached the sandbox's read-only
`/home/loon/.config/systemd/user` and restricted DNS, with secondary missing-project
and terminal-prompt failures. Source also changed during that run, so it is not
final-source evidence. No native retry was made. The subsequent worker selection
explicitly disables native cases; mandatory native validation remains with the
manager, without relaxed assertions or limits.
That offline selection passed 66 tests without skips in 74.129 seconds. A final
review then corrected runtime comparison so discovered requires-python may refine
the constraint while retaining the exact interpreter identity. Two focused
regressions passed in 1.353 seconds, including rejection of an incompatible
discovered constraint. Native results for the corrected source remain pending.

The termination correction uses existing internal lifecycle APIs, so additional
tooling research adds no information. No new interface or dependency is introduced. The existing
[uv locking distinction](https://docs.astral.sh/uv/concepts/projects/sync/) between
frozen candidates and locked validation was rechecked for this integration.
Offline metadata unavailability remains an operational failure with no network
fallback. Private dynamic locks, additional local paths and transactional
multiple-distribution preparation remain required work. The earlier milestone
records below describe their source at the time, not current coverage.

### Local Python preparation prerequisite

The local Python milestone is in progress. `python_local.describe_source` creates
review data from explicit inventory resource IDs. The optional `sources` field in
the existing Python dependency descriptor binds a project-relative location,
canonical distribution identity, source snapshot digest and explicit `allow_build`
decision. An empty location denotes the project root but adds no inventory grant.
Local identities cannot collide with reviewed registry identities and do not
receive fabricated publication or advisory evidence.

The trusted `python_local.build_wheel(store, token, source_id)` adapter requires an
approved active controller and every source read grant. It uses uv's wheel build
frontend in the existing offline supervised namespace, with only the reviewed
snapshot mounted. It validates output identity, wheel members, dependency closure
and runtime compatibility, then rechecks source bytes, session and approval before
returning wheel bytes and a digest receipt. No source-bearing registry cache or
reusable package set is published. Backend failure details are not returned because
they may contain source data. Staging is removed on failure.

The second prerequisite accepts static pure-Python projects with an in-tree or
registry backend. Put the complete build/runtime dependency graph in the existing
Python descriptor's `pins` and `artifacts`, with matching project/task package
grants, before approving the local source. The trusted adapter reassesses this
graph using the existing age/CVSS and private-registry policy, verifies downloaded
wheel bytes, metadata and runtime compatibility, then supplies only these wheels
to uv using offline find-links and exact build constraints. Static declarations
must fit the reviewed graph. URL requirements are rejected. Inactive markers are
evaluated against the reviewed interpreter. Build extras cannot fetch outside the
supplied wheel set. Additional hook requirements without compatible supplied
wheels fail closed; the operator must resolve and review a new graph before retry.

Backends receive a writable disposable copy because ordinary setuptools builds
write egg-info and intermediate files. The original resources remain untouched.
Only the validated wheel and digest receipt leave preparation, and source/session
approval is checked again before backend execution and before returning bytes.
Registry dependency hashes appear in that receipt; local code still receives no
fabricated publication dates. This trusted preparation API reports denied or
uncertain build dependencies as errors without changing misconduct counters;
model-facing package installation retains its existing escalation semantics.

At this prerequisite it was not yet an operator-facing local installation workflow. Dynamic metadata
review, preparation during pending setup, combined multiple-local-source installation,
and CLI/PTY review remain mandatory work. The editable adapter and its pending
native checks are described below.
The public quickstart continues to use the existing supported formats. These are
implementation gaps, not newly declared unsupported ordinary project formats.
External/VCS sources and uncontrolled build downloads remain outside the bounded
adapter. Existing registry requirements and security checks have not been removed.

The first prerequisite's eight non-native tests and native fixture passed the
manager's `guard` and `ecosystem-python-local` checks in run
`task-9-1789615391105128659`, receipt `check-probe-1-0-1.log`. That evidence covers
the earlier source with no registry build requirements, not this extension.

`test_product_python_local.py` now has twelve non-native tests and three native
fixtures. The twelve non-native tests passed in the manager-provided existing editable source
environment. An initial system-Python attempt failed at import because `cvss` was
absent; the next attempt exposed a missing `requires_python` fixture field, which
was corrected before the original eight tests passed. During extension work, an
unintended discovery invocation inherited `PTW_LINUX_TESTS=1`. Its twelve unit
tests passed, but two native tests failed while creating a service in the read-only
systemd user directory, and the standard-backend fixture failed resolving the
public artifact host. These are failed attempts, not native evidence; they were
not retried in the coding sandbox. Native verification is deferred to the manager.

The original native fixture requires real uv build, offline wheel installation, import
and distribution metadata, host-file read/write denial, environment-injection
exclusion and an unrelated process surviving project stop. The backend is a
synthetic PEP 517 fixture, not a model trajectory or a standard-backend coverage
claim. Its bounded receipt records tool, runtime, source, approval and wheel hashes.
The additional native fixtures test a denied hook-added requirement and a real
setuptools wheel build/import using the release builder's existing hashed pin.
The latter downloads that exact public artifact; its age/advisory records are
explicitly synthetic test evidence. It does not certify setuptools' current
vulnerability status. Tests do not import the backend into the controller.
New unit negatives cover denied build dependency grants, incompatible or absent
pins, malformed/critical evidence, tampered bytes, unsafe filenames and unexpected
output dependencies, with no artifact publication or backend execution.

The prerequisite follows the official [uv build interface](https://docs.astral.sh/uv/concepts/projects/build/).
uv invokes a backend, so static project metadata does not imply approval to build.
[PEP 660](https://peps.python.org/pep-0660/) requires genuine editable behavior,
including distribution metadata and source edits becoming visible. The current
wheel-only prerequisite did not claim that behavior. Research established these
interfaces and the next test requirements, not successful native execution.

### Editable Python preparation and reuse

The manager subsequently passed all 15 local tests without skips in 12.221 seconds
in `check-probe-1-1-1.log`, run `task-9-1789615391105128659`, including actual
setuptools build/import and denied hook requirements. The associated guard passed.
That result covers test-source SHA-256
`e19b7bdc0f2b29ac1bc34b35b053c656461c2d82363df72f58009fdc2f68cc8e`,
before the editable extension. It does not establish editable success.

The trusted adapter now offers `install_editable(store, token, source_id)`.
Create the descriptor with `describe_source(..., allow_build=True,
editable_resources=[...])`, review it and activate the approved policy before
calling this adapter. `editable_resources` contains explicitly selected resource
IDs for implementation code, for example the `src` tree. It must be a subset of
the source resources and cannot include the project build configuration or
in-tree backend paths. All remaining source resources are bound by digest.
A wheel approval alone never authorizes an editable install. Local source IDs
remain distinct from registry package names.

Preparation runs native `uv pip install --editable` with offline assessed build
wheels and exact constraints inside the existing bounded supervisor. It creates
the PEP 660 installation against `/target`, the stable confined command root,
without mounting the original repository. Installed distribution metadata,
runtime compatibility, dependency closure and editable origin are inspected as
data. Backend output cannot supply `sitecustomize.py` or overwrite a registry
payload. Only the empty regular `.lock` created by both uv target installations
may overlap; the final integrity manifest still covers it. Registry wheels are
installed independently using the existing
offline installer. The trusted startup adapter processes editable `.pth` and
finder code only in the protected application process, never in the controller.

The returned `package_set` uses the existing command setting:

```json
{"package_sets": ["pkg_REPLACE_WITH_RETURNED_ID"]}
```

Every consuming command must include every bound source resource, and its session
must retain all source read and dependency package grants. Direct non-workspace
launches cannot reuse this source-bearing set. Even a narrower command that needs
only an import must include the complete source binding; excluded inputs deny
reuse before execution. The installation is checked against its stored manifest
and policy revision on each use. Only the current command snapshot is exposed at
`/target`, so permitted implementation edits can become visible without rebuilding.
Build configuration or backend edits block reuse and need a newly reviewed source
and installation. Package-set publication rechecks the source, session, runtime,
policy and evidence, then registers the completed installed tree atomically.
Failed preparation does not expose a partial registered set.

This was an adapter prerequisite, not a completed `ptw codex` local-project flow.
Dynamic metadata, initial setup approval and terminal review remain incomplete.
Native editable extensions, backend-generated source-tree link farms, multiple
local distributions in one environment, and local extras still need integration;
ordinary workflows are not waived by these current implementation limits.
External/VCS sources and builds that require uncontrolled network access remain
outside the bounded design. Private registry credential handling is unchanged.

New unit tests cover editable-specific approval, fixed build inputs, implementation
edits, command/session exclusions, tampered cached files, output dependencies,
invalid origins/startup hooks, mutation and failed publication. The first unit run
of the extension had three fixture errors because a synthetic distribution used a
hyphenated metadata directory. The fixture now locates its actual metadata directory;
production validation was not relaxed. The corrected local suite passed all 17
non-native tests, with five native fixtures explicitly excluded using
`PTW_LINUX_TESTS=0`. Package, ecosystem and workspace regressions passed 53, 29
and 27 non-native tests respectively; their native portions were also excluded.
The documentation check passed for 49 documents and 226 local links.
No native tests were attempted in the coding
sandbox during this extension. Manager verification must exercise both a synthetic
PEP 660 backend and the real pinned setuptools backend: install, protected import,
brokered source edit, second import without reinstalling, denied narrower command,
unchanged host controls and policy, environment injection and unrelated-process
survival. These are deterministic fixture requests, not model trajectories.

The implementation follows the documented
[uv editable install interface](https://docs.astral.sh/uv/reference/cli/#uv-pip-install)
and [PEP 660](https://peps.python.org/pep-0660/). uv owns the ephemeral editable
wheel lifecycle; the adapter retains installed files, not editable wheel artifacts.
The existing source-test environment instructions below apply to these tests too.

The next manager run passed 21 of 22 local tests. Real wheel builds with the
synthetic and pinned setuptools backends passed, as did synthetic editable
installation, protected import, source edit and second import without rebuilding.
The real setuptools editable fixture failed before publication because the two
installation trees shared files. The
[pinned uv target lock implementation](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-python/src/interpreter.rs)
and [lock creation](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-fs/src/locked_file.rs)
show that both target installations create an empty `.lock`. A new offline
fixture reproduces that collision. The adapter now permits only that empty
regular file overlap, rejecting even identical package payload overlaps,
nonempty lock collisions and local symlinks. The native fixture is unchanged;
its rerun remains required to confirm the diagnosis and real setuptools reuse.

During this correction, the first offline invocation could not import `cvss`
from the system interpreter. Using the manager's existing isolated source-test
environment, the new positive fixture reproduced the collision before the fix;
the negative fixture passed. After the fix, all 19 non-native local tests passed.
Five native tests were deliberately excluded from this worker run. No source
environment was created or modified and no socket/systemd test was attempted.
Dynamic metadata, setup preparation authority, combined local sources and
operator CLI/PTY flows remain mandatory incomplete work.

### Reviewed dynamic Python metadata prerequisite

The manager passed all 24 local tests without skips in 24.747 seconds in
`check-probe-1-3-1.log`, run `task-9-1789615391105128659`; guard also passed.
That result covers test-source SHA-256
`1aaa58a9b7538ee4bb1457087c475d3ceb71ee8ad2b1283e45efe11aad3f2e41`.
It confirms the empty uv target-lock correction and real setuptools editable
reuse. It predates the dynamic-metadata changes below.

The trusted local preparation API now accepts explicit expected values for
`project.dynamic` version, dependencies and requires-python. For example, for
`dynamic = ["version", "dependencies"]`, prepare review data with:

```python
source = describe_source(
    inventory, ["source", "backend", "metadata"], identity="application",
    allow_build=True, editable_resources=["source"],
    dynamic_metadata={"version": "1.0", "dependencies": ["example>=1,<2"]},
)
```

These are explicit inventory resource IDs, not directory grants inferred from
the project location. Insert this descriptor into the proposed policy's Python
sources, together with the independently resolved and assessed registry graph.
Review and approve that exact policy using the existing operator approval flow
before calling `build_wheel` or `install_editable` with its registered session.
The example constructs data only; it does not approve or execute a backend.
Review every source resource, expected metadata field and build dependency.

Expected dynamic fields must exactly match the declared dynamic fields. Missing
expectations, duplicate/conflicting fields, URL requirements, incompatible pins
and unsupported runtimes fail before hooks. uv executes approved hooks with the
existing offline wheel set, exact constraints and confined snapshot. The backend
cannot fetch additional requirements. If it needs an absent build dependency,
preparation fails; assess that dependency and explicitly review a new graph before
retrying. No failure repairs the policy automatically.

Validated output must retain the declared dependencies and Python requirements,
as well as the approved identity. Wheel metadata cannot add, remove or relax a
requirement merely because the selected version would still be compatible.
PEP 660 allows editable-only runtime additions; those must still fit the assessed
graph. Requirements are compared after parsing, so ordinary spacing and specifier
ordering differences are accepted. Backend logs are not presented as trusted
review data. Dynamic version files and other metadata inputs should have fixed
source bindings, separate from editable implementation resources. Changing those
fixed bytes requires a new review and preparation.

This is a bounded expected-value adapter, not automatic dynamic discovery or a
completed local-project terminal workflow. Discovery of unknown metadata and
additional requirements, pending-setup workflow integration, combined local
sources, local extras and operator CLI/PTY integration remain mandatory work.
Other dynamic fields still require integration; this does not waive ordinary
project support. External/VCS source and uncontrolled network builds remain
outside the bounded design. No new dependency was introduced.

The worker passed all 24 non-native local tests in the existing manager source
environment, explicitly excluding native tests with `PTW_LINUX_TESTS=0`. The
first run passed without failures. Four new native fixtures await manager checks:
real pinned setuptools dynamic wheel/import, dynamic editable/import/edit/reuse,
a synthetic dynamic hook using an explicitly assessed extra build requirement,
and rejection of an unexpected dynamic version with no publication. Nine native
tests in total now require the manager's Linux runner. No socket/systemd tests or
source-environment setup were attempted by the worker in this segment.

Design sources: [PEP 621](https://peps.python.org/pep-0621/) distinguishes static
fields from explicit dynamic declarations and prohibits conflicting declarations.
The [uv build interface](https://docs.astral.sh/uv/concepts/projects/build/)
supplies build constraints. The standard-backend fixture uses setuptools'
documented [dynamic version file interface](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html#dynamic-metadata).
These sources establish interfaces, not native success on the installed tools.

### Preparation authority while setup is pending

The manager subsequently passed all 33 local tests without skips in 39.489
seconds, including the nine native tests above, in `check-probe-1-4-1.log` of
run `task-9-1789615391105128659`. The test-source SHA-256 was
`e6818bf1c81c23d0b8aba691b169390fb696985f2279a73f7a180336cff9239a`.
That result establishes the previous dynamic/editable implementation. It does
not validate the new pending-setup authority described here.

`Store.register_preparation(project, task, source_id, policy_sha256)` is now a
trusted setup-adapter API. It requires the exact approved pending project, an
explicitly build-enabled local source, task read access to every bound source
resource and task permission for the complete assessed registry graph. It
issues one read-only credential with no commands or delegation. Only one
preparation session may be active per project. Ordinary registration stays
blocked until setup commits; no second controller or temporary policy is used.

The credential can call the existing local build/editable adapters for its
single source. Normal session admission rejects it for file operations,
registry installation, workspace commands, raw launches, MCP and delegation.
Only the local source adapter opts into preparation-aware build supervision.
Source bytes, runtime, artifact evidence, confinement and publication checks
still apply. A stopped project rejects further preparation and cannot commit.

The setup adapter must close this credential and reconcile its workloads before
calling `commit_setup`. Commit refuses both open preparation sessions and any
preparation workload whose termination is not confirmed. Once closed, the
credential cannot be reused after commit. Reopening the controller preserves
pending state and the credential's restricted purpose. Existing ordinary
sessions and databases remain compatible through an additive nullable column.
Do not expose preparation credentials to agents or use this API as an approval
endpoint. The caller still has to validate durable setup artifacts at commit.

Five new non-native tests cover these admission and commit boundaries. All 29
non-native local tests and 66 controller/setup regression tests passed in the
manager's existing source environment. The first attempted unit invocation used
system Python and failed during import because `cvss` was absent; no test body
ran. Reusing the existing isolated environment resolved that test-environment
error without installing or modifying dependencies.

Two new native fixtures await manager validation. One prepares a real editable
installation while ordinary registration is blocked, closes and reconciles the
preparation session, commits, and then imports and edits under an ordinary
session. The other observes a marker from a real blocked build backend, stops
the project, and checks physical termination, no publication and survival of an
unrelated process. These are deterministic native requests, not model journeys.
The worker did not attempt socket or systemd operations in the coding sandbox.

This was the pending authority prerequisite. Setup transaction orchestration,
CLI/PTY preparation review, unknown dynamic metadata discovery, additional
requirement review, combined local sources and the final quickstart remain
mandatory work at that point. The next step connects this API to `ptw codex` setup.
No new tooling API or dependency is introduced in this step; controller source
and focused tests establish the state-transition behavior. The existing native
frontend design still follows [PEP 660](https://peps.python.org/pep-0660/) and
the [uv build interface](https://docs.astral.sh/uv/concepts/projects/build/).

### Static editable setup integration

The manager passed all 40 tests without skips in 44.893 seconds in
`check-probe-1-5-1.log`, run `task-9-1789615391105128659`. This includes the
pending-setup import and physical-stop fixtures. Test-source SHA-256 was
`23b2cb1c3d3b31db0395903dbeccf9187c64fb2f7eb2cb971429901203462528`.
The associated guard passed. That result precedes the setup integration below.

Current source connects `ptw codex --python-editable src` to the existing pending
controller and transactional publication. The selected live paths must already
be explicit source grants. The source is an exact resource snapshot, separately
identified from registry packages. Static build-system requirements enter the
existing native resolver and artifact/evidence checks alongside runtime
requirements. No backend executes before the operator's policy approval.
The short review shows backend execution, live paths and the source hash; details
shows the full descriptor. Preparation runs offline after approval. Commit
requires closed preparation sessions, reconciled workloads, unchanged source
bytes and the validated installation manifest. Failure rolls back owned setup
files, preserves concurrent source edits and retains stopped history and receipts.

The protected MCP context and delegate adapter expose prepared package-set IDs
only for compatible command/session source and package grants. Use still checks
the full source binding and installed bytes. See the
[setup workflow](ONBOARDING.md#local-python-preparation) and
[quickstart](INTERACTIVE.md) for positive and rejection/recovery examples.

The new native PTY fixture uses the real CLI, policy transaction, controller, uv
and confinement, replacing only the login check. It rejects and cancels before
execution, forces an approved backend failure, retries with a fresh approval,
then imports through a protected test command, edits source and imports the new
value under the same policy. It checks distribution metadata, unchanged host
controls, and unrelated-process survival. This is scripted operator interaction,
not a model trajectory. Native validation of this new path remains pending.

Unit tests cover the transaction, receipt visibility, rejection/cancellation,
malformed mutable scopes, failed-build rollback/retry, mutation before commit,
unconfirmed termination and build requirements entering assessed resolution.
All 35 non-native local tests passed, as did 62 onboarding/adapter regressions,
including the existing PTY transaction tests. No socket, systemd or source-environment
setup operations were attempted in the coding sandbox during this step.
No new dependency or backend frontend was introduced. The existing uv/PEP 660
interfaces above were rechecked against their official documentation; research
adds no evidence of native success. Unknown dynamic metadata discovery,
additional hook-requirement review, local requirement entries, combined sources,
extras, native output and durable wheel publication remain mandatory work.
Native lock/build integration is also pending; no lock is silently discarded.

### Fixed local wheel installation

The manager subsequently passed all 47 local tests without skips in 53.402
seconds in `check-probe-1-6-1.log`, run `task-9-1789615391105128659`; guard and
diff formatting also passed. That run includes the actual editable CLI approval,
rejection, cancellation, failed-build rollback, retry, import and live edit.
Its test-source SHA-256 was
`2529e78b74d0a11ca2b6cba353b1bcc7671ba67f25a2abf03fffa74ea1fdff8d`.
It predates the wheel extension described here.

Current source adds `--python-wheel`, mutually exclusive with `--python-editable`.
It reuses the approved confined wheel builder, the offline hash-checked uv
installer and the same atomic package-set publication used by editable setup.
The receipt retains the built wheel digest and provenance. Local identities stay
separate from registry evidence and grants. Registry artifacts are re-assessed
for installation; their identities must match the build receipt. No new backend
frontend or dependency was introduced. Full source grants and command inputs
remain required on every reuse, and any bound source change invalidates a fixed
wheel. Editable implementation changes retain their existing live semantics.

The native PTY fixture now also covers wheel-mode rejection, cancellation,
approved build failure, rollback, retry, protected import/distribution metadata
and stale-wheel denial after an authorized edit. It checks unchanged host files
and unrelated-process survival. This fixture awaits manager execution. Its
scripted inputs are not a model trajectory.

The first worker unit run found three mistakes in new assertions: the shared
synthetic wheel uses literal `local-demo` paths, while the new tests assumed
`local_demo`. Assertions and the collision injection now address the actual
fixture paths; no validation checks were removed. All 41 non-native local tests
then passed, along with 62 onboarding/adapter regressions including PTY tests.
An additional CLI reopen assertion initially expected a numeric return code;
the existing `main` returns None on success. That assertion was corrected while
retaining the no-rebuild and conflicting-options checks. Native checks are
delegated to the manager because the coding
sandbox restricts sockets and systemd user-service writes. Unknown dynamic
metadata discovery, additional hook-requirement review, local requirements,
combined sources, extras, native output and native-lock/build integration remain
mandatory unfinished work. The immutable product requirements are unchanged.

Official [uv build documentation](https://docs.astral.sh/uv/concepts/projects/build/)
and [package installation documentation](https://docs.astral.sh/uv/pip/packages/)
were rechecked for the native build/install distinction. These establish the
tool interfaces, not successful execution against the manager's installed tools.

### Local optional dependencies

The manager passed all 54 local tests without skips in 67.444 seconds in
`check-probe-1-7-1.log`, run `task-9-1789615391105128659`. Guard and diff formatting
also passed. That includes the wheel and editable PTY flows, rollback/retry,
protected imports, source-change denial for fixed wheels and unrelated controls.
The test-source SHA-256 was
`6954241ffd1fe15d893a16fdfe200929521a9252a6b0b2e8d92168974dd55371`.
It predates this extras extension.

Current source accepts static local `project.optional-dependencies` using
`--python-extras`, with either `--python-editable` or `--python-wheel`. It reuses
the existing uv resolver and independent evidence checks. Selected normalized
extras are bound into the approved source descriptor and shown in the short
review. Unknown selections, ambiguous normalized names and malformed declarations
fail closed. Unselected extras grant no dependencies; empty extras are valid.
Wheel and editable output must preserve declared extras and marked requirements.
The combined installed distribution metadata is checked before publication so
editable hook dependencies cannot bypass transitive-extra closure checks.

The source tests cover parse/selection, invalid inactive declarations, missing
approved dependencies, changed output markers and extras, transitive-extra
failure, and setup approval binding. New native fixtures exercise actual
setuptools wheel and editable installs with a synthetic assessed extra, protected
import, unselected-package absence, narrower-command denial and unrelated
controls. A PTY fixture reviews, rejects, cancels, fails, retries and imports an
editable project with an explicitly selected empty extra. These additions await
manager execution, not a model self-report of native success.

The first offline invocation stopped at import because system Python lacked
`cvss`; no tests ran. Using the existing manager test interpreter, the first 46
non-native local tests passed. A subsequent expanded run passed 73 tests and
failed one new setup test because an existing CLI assertion had accidentally
moved outside its method's import scope. The assertion was restored to its
original test without changing its expectation. No sockets, systemd services or
test-environment installation were attempted in the coding sandbox.
The corrected run passed 75 selected non-native tests in 33.481 seconds, including
49 local tests and 26 ecosystem regressions. The documentation checker passed
49 maintained documents and 231 local links. Native checks are still deferred.

This uses no new dependency. The mapping of optional declarations to
`Provides-Extra` and marked `Requires-Dist` follows the official
[pyproject specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
and [core metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/).
Metadata comparisons normalize requirement names, versions and marker syntax;
arbitrary Boolean rewrites of markers are not proven equivalent.

### Unknown dynamic metadata discovery

The manager passed all 65 local tests without skips in 88.327 seconds in
`check-probe-1-8-1.log`, run `task-9-1789615391105128659`; guard and diff formatting
also passed. This confirms the preceding local extras extension, including the
native setuptools imports and terminal selection flow. It predates discovery.

Current source adds a first operator review for an offline uv wheel build when
the local project declares unknown dynamic version or dependency metadata. The
discovery descriptor has no invented version and cannot publish a package set or
make the project ready. Only a source-bound pending preparation credential may
execute it. The adapter reads bounded wheel metadata as data and discards the
wheel. Static fields must match declarations; URL dependencies and malformed
metadata fail closed. The existing resolver assesses discovered requirements,
then a second explicit policy review precedes the actual build and installation.
See the [terminal workflow](ONBOARDING.md#local-python-preparation).

Both stages use the same controller and project identity. Refinement requires
closed sessions, confirmed workload termination, unchanged discovery source and
the exact preceding approval. It preserves project/task counters and cannot
revive a stopped identity. Rejection after discovery stops that pending project;
its private receipt and history remain. A durable discovery journal lets retry
stop interrupted work. No project file is published by discovery.

Dynamic editable inputs now have enforced reuse bindings. Declarative setuptools
file directives retain every referenced file even if it lies inside a mutable
resource. Missing files and traversal reject preparation. Custom backends,
attribute directives, plugins and setup.py/setup.cfg bind the entire source
snapshot conservatively. This is a current restriction: such projects require
renewed preparation after implementation edits, rather than reusing potentially
stale metadata. Ordinary dynamic editable usability remains part of the goal.

Eight new non-native tests cover the two reviews, same-project refinement with
preserved counters, no ready state during discovery, cancellation, mutation,
URL output rejection, dynamic file bindings, and discovered dependency resolution.
The initial run of all 49 preceding non-native local tests passed in 28.035
seconds; the expanded 57-test selection passed in 37.852 seconds. Another 25
selected resolver/ecosystem regressions passed in 2.641 seconds. There were no
failed test attempts in this segment. The new native PTY fixture requires real
discovery, rejection/cancellation, failed-backend recovery, a second review,
protected installation/import and unchanged unrelated controls. It has not run
in the worker sandbox. Socket creation and systemd user-service writes are
restricted there; native validation remains with the manager. No test environment
was installed or modified. Documentation validation passed for 49 maintained
documents and 232 local links. Changed maintained sources are hashed in
MANIFEST.sha256; the native fixture emits its test-source hash with its results.

The design reuses [uv build](https://docs.astral.sh/uv/reference/cli/#uv-build)
instead of implementing backend invocation. [PEP 517](https://peps.python.org/pep-0517/)
allows metadata to require a wheel build when the optional metadata hook is
unavailable, so the first review explicitly authorizes that work.
[Setuptools dynamic metadata documentation](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html#dynamic-metadata)
distinguishes file directives from attribute loading and plugins; that distinction
informs the bounded file binding above. These sources establish interfaces, not
native success against the installed tools. No new dependency was introduced.

Additional hook-requirement review, local
requirements entries, combined distributions (including self-referencing extras),
native output and native-lock/build integration remain mandatory work.
Self-referencing active extras are rejected before public registry resolution;
there is no local/public identity substitution. No ordinary requirement is waived.

### Native local wheel output increment

The manager passed all 74 local tests in 98.520 seconds in
`check-probe-1-9-1.log`, run `task-9-1789615391105128659`. Guard and diff checks
also passed. This establishes the preceding dynamic-discovery terminal flow,
not the native-output changes below.

Current source replaces unconditional native local wheel rejection with the
existing `allow_native_wheels` policy. `--python-wheel --python-native-wheels`
requests that policy in setup and discovery reviews, including assessed Python
dependencies. Defaults, age/CVSS assessment, artifact hashes, source bindings,
runtime checks and supervision remain enforced. Existing projects require
`--revise` for a changed request. The flag is unavailable for editable mode until
compiled editable outputs have a complete source/rebuild lifecycle.

Wheel tags must match the embedded WHEEL header and reviewed runtime. Native
tags, platlib placement, ordinary binary extensions and ELF payloads require
native-wheel approval. These are bounded format checks, not classification of
arbitrary code. Executing a reviewed source backend and admitting its resulting
native artifact are separate decisions. Failed validation publishes no package
set and is not counted as misconduct.

Four new non-native tests cover explicit setup/revision handling, invalid mode,
default-denied and approved output, mislabeled native payloads, malformed headers
and incompatible runtime tags. Two new manager-only fixtures compile an actual
shared C library using the system compiler inside the supervised backend. One
exercises the full terminal review, rejection, cancellation, backend failure,
retry, protected import and stale-source denial; the other denies unapproved
native output and checks environment injection and unchanged host controls.
No native workload or service setup was attempted in the coding sandbox.

The first non-native run passed 60 tests and failed one new assertion because
the test passed a policy instead of a bundle to `short_review`. The fixture call
was corrected; production validation and test expectations were unchanged.
An expanded test selection was interrupted with exit 130 before completion
because the ecosystem module also contains unguarded native-tool tests. Its
partial output is not a pass; the replacement selection names only non-native
local and resolver cases. No sandbox-incompatible test is retried.
Updated-source validation results are recorded in the handoff. Maintained source
hashes are in MANIFEST.sha256; manager fixtures emit their test-source hash.

The [wheel format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
and [compatibility tags](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/)
define the header/filename and runtime checks. The
[uv backend documentation](https://docs.astral.sh/uv/concepts/build-backend/)
confirms that extension builds use an appropriate PEP 517 backend. These primary
sources informed validation; they are not native execution evidence. No new
dependency or compiler download path was added. Compiled editable output,
additional hook-requirement review, broader dynamic metadata, local requirements
entries, combined distributions and native-lock/build integration remain required.

### Native compiler fixture correction

Manager run `task-9-1789615391105128659`, `check-probe-1-10-1.log`,
passed 78 of 80 local tests. The two new compiled-library cases failed during
backend execution, before native-output approval checks or protected import.
Guard and diff checks passed. These failures are not successful native denial
or import evidence.

Read-only inspection found `/usr/bin/cc` points through `/etc/alternatives/cc`
to `/usr/bin/x86_64-linux-gnu-gcc-14`. The shared namespace mounts `/usr` but
does not mount `/etc`. The fixture now resolves that alias before generating
the reviewed backend, requires its concrete executable under `/usr`, and uses
that bound path. It does not execute the compiler during fixture generation,
inherit compiler environment variables, or expand runtime mounts. A non-native
regression checks the generated invocation, ambient-selection rejection and
unchanged namespace. The original native success and denial assertions remain.
The manager must validate compilation and import against this correction.

This diagnosis uses the installed filesystem and existing namespace code;
web research adds no evidence about that local alias. Prior official wheel/uv
interface references above remain applicable. The first worker test invocation
failed to import `cvss` using system Python. The next used the existing manager
environment, but incorrectly selected tests using skip markers while inheriting
`PTW_LINUX_TESTS=1`. It ran 81 tests in 46.783 seconds: 62 passed and 19 errored.
Native cases hit read-only systemd paths, unavailable network evidence and
setup failures. This was an invalid sandbox selection, not native acceptance.
No environment was installed or modified. Native cases will not be retried in
the worker sandbox; validation remains with the manager. All previously listed
incomplete ordinary formats remain required.

The subsequent explicit five-test non-native selection passed in 2.618 seconds.
It covers the compiler fixture, output approval, wheel headers/runtime tags,
setup review and invalid mode. Native flags were disabled for that selection;
none of the five tests require services or sockets. Documentation and diff
checks passed. These results do not replace the pending manager native checks.

### Local self-referencing extras and discovery composition

The manager passed all 81 local tests in 107.580 seconds in
`check-probe-1-11-1.log`, run `task-9-1789615391105128659`, with guard and diff
formatting passing too. This confirms the compiler-fixture correction, including
the compiled-library terminal import and denied native output. It predates this
increment.

Current source expands requirements referring to the reviewed local distribution
into its selected optional requirements before invoking uv. It does not request
that distribution from a registry. Active self references must match the local
version and declared extras; inactive runtime markers remain inactive. The bounded
closure handles cycles without repeated expansion, preserves registry ranges,
and checks local version constraints. Build dependencies on the same unbuilt
distribution fail before execution. Independent output dependency closure checks
remain in place. No new solver or dependency was introduced.

Dynamic dependency discovery now separates known static optional declarations
from discovered base requirements using the same normalized requirement comparison
as installation validation. Static extras cannot disappear or change through
discovery. Selected self references are expanded after discovery supplies the
candidate version and before final review, not resolved as public namesakes during
discovery. See the [operator flow](ONBOARDING.md#local-python-preparation).

New non-native tests cover no-public-lookup resolution, registry range preservation,
pre-build missing-graph rejection, cyclic closure, markers, incompatible local pins,
unknown extras, URL inputs, closure bounds, local version constraints, self build
dependencies and altered discovery output. New native fixtures exercise actual
setuptools editable installation with a self-referencing extra and a dynamic
discovery/extras CLI flow with rejection, cancellation, failure, retry, import,
stale-wheel denial and unrelated-file/process controls. These native additions
await manager execution. The initial eight focused non-native tests passed in
2.493 seconds. All 67 selected non-native local tests then passed in 34.059 seconds,
with native flags explicitly disabled and native methods excluded. No native
services, sockets or environment setup were attempted in this increment.

The [PyPA metadata specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/#dependencies-optional-dependencies)
maps optional requirements into Requires-Dist with extra markers. The existing
[packaging Requirement interface](https://packaging.pypa.io/en/stable/requirements.html)
provides parsing, extras, specifiers and markers. These primary interfaces informed
the source/metadata separation and bounded expansion; they do not prove native
tool behavior. The implementation retains its existing bounded dynamic field set.
Dynamic optional metadata, additional hook-requirement review, compiled editable
output, local requirement entries, multiple local distributions and native-lock
build integration remain required work. This increment does not complete the
milestone or the overall ecosystem task.

### Additional build requirement collection prerequisite

The manager passed all 88 local tests without skips in 120.234 seconds in
`check-probe-1-12-1.log`, with guard and diff checks also passing. This confirms
the preceding self-referencing extras and dynamic/static extras terminal flows.
It does not validate the following hook-collection increment.

The pending source adapter now collects `get_requires_for_build_wheel` or
`get_requires_for_build_editable` output in the existing supervised build
boundary. Bootstrap artifacts use the existing assessment, hash validation and
offline uv wheel installer. Only the approved source snapshot and bootstrap
installation are mounted; package startup code and backend imports execute
inside confinement. A missing optional hook returns an empty proposal. Actual
wheel and editable construction still belongs to uv; no resolver or dependency
was added.

The returned list is untrusted data, limited to 64 requirements of 4096 characters
each. Malformed output, URLs, local/public identity substitution, control
characters, oversized output and symbolic links fail closed. Original specifiers,
extras and markers are retained. The receipt binds the source snapshot, policy,
runtime, hook runner and assessed artifact hashes. Before returning it, the adapter
rechecks source authority, shared stop, package scope and evidence policy. It
neither approves nor installs a newly requested dependency, publishes a package
set, nor changes the pending controller's history.

New tests cover bounded proposals, denied non-preparation access, wheel/editable
hook selection, stale and concurrently mutated source, missing/malformed/unsafe
output, redacted failures, stop and bootstrap evidence denial. Two manager-only
fixtures exercise a missing optional hook and an actual bootstrap import whose
hook requests a package absent from the approved graph. The latter verifies
environment and host/network isolation, unchanged policy, denial of the subsequent
unapproved uv build and an unrelated live process. Native checks are pending;
the worker did not run services or sockets in the coding sandbox.

All 70 selected non-native local tests passed in 38.934 seconds. After the final
hook-runner adjustment, all seven new focused non-native tests passed again in
3.681 seconds. Native methods were explicitly excluded and native flags disabled.
The initial six focused tests also passed; no failed attempts occurred in this
increment. The documentation checker passed 49 documents and 233 local links.

This is an early implementation handoff, not completion of the operator journey.
Next connect these bound proposals to the existing pending setup review: resolve
and assess additions, obtain explicit approval, retry in confinement and prove
import, rejection, cancellation, incompatibility and stopped-project behavior.
No prepopulated graph fixture may stand in for that journey. Dynamic optional
metadata, compiled editable output, local requirement entries, multiple local
distributions and native-lock/build integration remain required as well.

[PEP 517](https://peps.python.org/pep-0517/#get-requires-for-build-wheel)
defines the optional hook and its bootstrap environment;
[PEP 660](https://peps.python.org/pep-0660/#get-requires-for-build-editable)
defines the distinct editable hook. These interfaces justify collecting proposals
before a build can install additional requirements. They do not establish native
confinement or full operator workflow success.

### Dynamic hook requirement review integration

The manager passed the preceding collection increment: all 97 tests in
126.763 seconds, without skips, in `check-probe-1-13-1.log`. The supplied guard
and diff checks also passed. Those results do not cover the following changes.

Dynamic metadata discovery now calls the approved wheel requirement hook first.
A nonempty proposal goes through the existing uv resolver and independent
artifact assessment, preserving original requirements, runtime and metadata.
The terminal displays requirements and resolved pins and asks for explicit
approval before supplying those wheels to a metadata build. It uses the existing
pending-controller refinement, retaining project identity and violation history.
The original approval and proposal remain alongside the refined approval and
resolution receipts. Final installation has its own review. A build failure
does not trigger further automatic dependency expansion.

New unit tests exercise the review boundary and retained counters, rejection,
cancellation, EOF, interruption, mutation, stop, incompatible original pins and
unsafe URL proposals. The new native PTY fixture uses a synthetic evidence
provider with the real broker HTTP wheel index and native uv resolution. Its
backend requires the newly reviewed wheel for a real build. It requires a
protected import, rejection/cancellation before the build, failed-backend recovery,
source integrity and an unrelated live process. Login alone is bypassed; no model
trajectory or live public registry assessment is claimed. Native validation of
this terminal increment remains pending.

The first worker test attempt used system Python and failed at import because
`cvss` was unavailable: eight loader errors, no tests executed. Repeating the
eight selected non-native methods in the manager-provided existing isolated
source environment passed in 13.442 seconds. All 79 selected non-native local
tests then passed in 52.643 seconds. Native methods were explicitly excluded,
with native flags disabled. No environment setup, services or sockets were
attempted by the worker.

This is a bounded integration milestone. Additional-hook terminal review for
static projects and editable-specific hooks, dynamic optional metadata, compiled
editable output, local requirement entries, multiple local distributions and
native-lock/build integration remain mandatory. The PEP 517 and PEP 660 sources
above were rechecked for the separate hook contracts; no dependency or general
resolver was added. See [the operator flow](ONBOARDING.md#local-python-preparation).

### Static wheel and editable requirement review

The manager passed the dynamic review integration in all 103 local tests without
skips, in 147.215 seconds (`check-probe-1-14-1.log`). Guard and diff checks also
passed. This establishes the preceding increment, not the following changes.

Static local setup now accepts `--python-build-requirements` with either
`--python-wheel` or `--python-editable PATHS`. It reuses the confined hook adapter,
uv resolver, artifact assessment and pending-controller review. The initial
approval authorizes requirement collection; nonempty proposals need a separate
graph review; installation requires the final policy review. Empty proposals
skip only the additional graph review. Original static setup remains available
when declared dependencies suffice, and fails offline on missing requirements.

Static refinement preserves source identity, mode, mutability and snapshot even
when generated metadata changes inventory IDs. It requires closed sessions and
stopped workloads, refuses existing package sets and retains counters. The new
unit cases cover both modes, all three rejection boundaries, empty proposals,
mutation, shared stop, malformed flag use, unsafe requirement URLs and attempted
source changes during refinement. Native PTY fixtures require actual wheel and
editable builds, protected imports, live editable changes, failed-build retry,
rejection, cancellation and an unrelated-process control. The editable fixture
deliberately fails if the wheel requirement hook is used instead.

The first five new non-native tests passed in 8.958 seconds in the existing
manager-provided source environment. All 84 then-selected non-native local tests
passed in 57.672 seconds. Two further boundary tests and the updated malformed
flag test passed in 1.940 seconds. Documentation checking passed for 49 documents
and 234 local links. No failed test attempt occurred in this increment. The first
manifest patch used filename order instead of manifest order and failed to apply;
the corrected patch preserves the existing entry order.
Native validation of this increment is
pending; the coding sandbox cannot run the required sockets/systemd paths.
The separate hook contracts were rechecked against
[PEP 517](https://peps.python.org/pep-0517/#get-requires-for-build-wheel) and
[PEP 660](https://peps.python.org/pep-0660/#get-requires-for-build-editable).
No new resolver or dependency was added. Dynamic editable-specific hook review,
dynamic optional metadata, compiled editable output, local requirements,
multiple distributions and native-lock/build integration remain mandatory work.

### Dynamic editable requirement review

The manager passed all 112 preceding local tests in 201.141 seconds, without
skips (`check-probe-1-15-1.log`), plus guard and diff checks. This verifies the
static wheel/editable hook-review increment above.

Dynamic editable setup now preserves wheel metadata discovery, then asks for
explicit approval before collecting the separate editable requirement hook.
It retains both sets of receipts and the same pending controller identity.
Editable additions use the existing resolver and assessment, preserve previous
wheel-hook constraints, and need a separate graph approval. Installation remains
behind the final review. No new dependency, resolver or policy authority was added.

New tests cover the distinct hook, preserved identity/counters, empty proposals,
constraint conflicts, URL rejection, cancellation at each new review, mutation
and shared stop. The native PTY fixture requires a real backend whose wheel hook
returns nothing while its editable hook requires a synthetic assessed package.
It exercises rejection, cancellation, failed-backend retry, a protected editable
import with distribution metadata, denied stale dynamic-source reuse and an
unrelated live process. It does not claim that arbitrary dynamic backend inputs
can be edited without re-preparation. Existing native declarative-setuptools
tests cover allowed live edits under their narrower metadata read set.

The first test invocation used system Python, which lacks `cvss`, and failed
during import before running five selected tests. Those five tests then passed
in 14.657 seconds using the existing manager-provided source environment.
The broader selection then passed 87 non-native local tests in 74.944 seconds.
The subsequently added wheel/editable constraint-conflict test passed in 2.228
seconds. Documentation checking passed for 49 maintained documents and 235 links;
diff formatting passed. These results do not establish native behavior.
No native test was attempted in the coding sandbox. The new combined terminal
flow awaits manager validation; sockets and systemd paths require the manager.

[PEP 660](https://peps.python.org/pep-0660/#get-requires-for-build-editable)
was rechecked: editable requirements have their own hook, so a wheel-hook result
cannot substitute for it. Dynamic optional metadata, compiled editable output,
local requirements entries, multiple distributions and native-lock/build
integration remain mandatory unfinished work. See the
[operator flow](ONBOARDING.md#local-python-preparation).

### Dynamic optional metadata

The manager passed all 119 preceding local tests in 218.799 seconds without
skips (`check-probe-1-16-1.log`), plus guard and diff checks. This verifies the
dynamic editable-hook increment above, superseding its pending native status.

Current source adds discovery of `project.dynamic = ["optional-dependencies"]`
through the same explicit metadata and installation reviews. Requested extra
names are validated before execution and checked against actual output before
resolution. Empty extras and environment markers are retained. Only selected
requirements enter resolution, while every output requirement, including inactive
extras, is checked for malformed declarations and URL sources. The bound output
must preserve static base dependencies and match the later installation build.
No additional authority, resolver, dependency or unconfined process was added.

The adapter inverts conventional trailing extra equality guards. It rejects
other boolean arrangements rather than guessing equivalent declarations. This
is a bounded compatibility limitation, not a claim of arbitrary marker support.
The distinction between `Provides-Extra` names and guarded `Requires-Dist` entries
follows the [PyPA core metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/#provides-extra-multiple-use).
Environment conditions remain parsed by packaging according to
[dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/).

Five new offline tests passed: discovered optional/base separation, empty and
inactive extras, environment conditions, selected graph/source binding, and
malformed/unsafe/unknown output rejection. New native wheel and editable PTY
fixtures require actual uv resolution of a selected synthetic wheel, confined
build, protected import, cancellation, failure/retry and an unrelated process
control. These fixtures await manager validation.

The worker's broader test selection mistakenly relied on skip decorators while
inheriting `PTW_LINUX_TESTS=1`. It ran 126 tests in 97.350 seconds with 25 errors
and four failures, all in native tests. Systemd service files were read-only,
network evidence lookup failed DNS, and terminal fixtures consequently failed
before usable setup. This is a failed sandbox attempt, not native acceptance.
It was not repeated. Subsequent offline selection explicitly excludes every
`test_native_` method with `PTW_LINUX_TESTS=0`; manager checks remain required.
That explicit selection passed all 93 offline tests in 78.906 seconds. Syntax
checks passed for the three changed Python modules and the test module.
Documentation checks passed for 49 maintained documents and 235 local links.
The maintained file hashes are recorded in MANIFEST.sha256. No successful native
result is claimed for this increment.

Compiled editable output, local requirements entries, multiple distributions
and native-lock/build integration remain mandatory unfinished work.

### Native editable in-place output

The manager passed the preceding 126 tests in 249.959 seconds without skips
(`check-probe-1-17-1.log`), plus guard and diff checks. This establishes the dynamic
optional-metadata increment above, including its real wheel/editable terminal
fixtures. It does not validate the newer compiled editable changes.

Current source extends `--python-native-wheels` to editable setup. It validates
installed tags against the reviewed interpreter, native payloads against the
existing package policy, and original inputs against backend mutation. In-place
native files are retained only under existing approved source directories.
Their hashes are part of the private installation receipt and package manifest.
They enter only a complete authorized command snapshot; attempts to mutate these
generated files fail before publication. Backend scratch is not a repository
grant. Registry dependencies retain their existing independent assessment.

Compiled editable reuse currently requires the entire reviewed source snapshot,
including Python implementation files. Changes require explicit re-preparation
with `ptw codex --revise`; the controller does not infer arbitrary backend inputs
or silently reuse stale libraries. Automatic scoped rebuilding and live Python
edits alongside compiled artifacts remain unfinished. This restriction does not
change pure-Python editable reuse. Symlink-based editable layouts and generated
parent trees outside the reviewed source layout are not covered by this adapter.
Existing file, tree, build-time and output limits are unchanged.

New offline coverage checks explicit native approval, payload/tag/runtime
validation, source and artifact mutation, symlinks, reserved storage collisions,
narrower commands/delegates, disposable artifact injection and prevention of host
publication. Six focused tests passed in 4.902 seconds; a broader explicit
non-native selection passed 102 tests in 86.162 seconds. The selection sets
`PTW_LINUX_TESTS=0` and excludes decorated native cases before constructing the
suite. No socket, systemd or source-environment setup was attempted this turn.
After adding executable-mode preservation and the final native fixtures, the
six focused offline tests passed again in 4.747 seconds. Changed Python syntax
and diff checks passed; documentation checking found no missing targets across
49 maintained documents and 236 local links. Maintained hashes are recorded in
MANIFEST.sha256.

New manager-only fixtures require a real compiled editable PTY flow with rejection,
cancellation, backend failure/retry, protected import, stale C-source denial and
explicit reviewed recompilation yielding a changed value. A second fixture uses
the existing pinned setuptools artifact and its real extension builder to leave
a library beside the source. A third requires compiled editable output to be
denied without native approval. They retain environment-injection and unrelated
process controls. These fixtures have not run in the coding sandbox; manager
validation is still required.

[PEP 660](https://peps.python.org/pep-0660/#build-editable) permits in-place outputs
and requires runtime-compatible editable wheels. It also distinguishes source
changes needing recompilation from Python-only edits. The setuptools fixture
uses its documented [extension configuration](https://setuptools.pypa.io/en/latest/userguide/ext_modules.html)
and selects the concrete system compiler in reviewed backend code, without
inheriting the operator's compiler environment. No new dependency, solver,
policy engine or unconfined fallback was added. See the
[operator flow](ONBOARDING.md#local-python-preparation).

### Setup-only revision parser correction

Manager run `task-9-1789615391105128659`, `check-probe-1-18-1.log`, ran 134
tests in 271.547 seconds: 133 passed and one failed. Guard and diff checks
passed. The setuptools compiled editable import and unapproved-output denial
passed. The compiled editable PTY failed before its replacement-policy prompt,
so successful terminal recompilation is not established.

An offline parser reproduction confirmed that `--revise --setup-only` exited
with code 2 before onboarding: both options were in one mutually exclusive
group. The parser now accepts that combination while continuing to reject
setup-only status/stop/review combinations. No confinement or approval boundary
changed. New regression tests exercise the actual CLI and setup transaction
with mocked native builds: rejection, cancellation, approved build failure,
rollback, stopped-history retention and a successful reviewed retry. The
existing native PTY keeps its full rebuild/import assertions unchanged.

The first focused invocation failed at import because system Python lacks
`cvss`. Using the existing manager-provided source environment, the regression
failed before the fix because the parser prevented the build, then both focused
tests passed after the fix. No environment was installed or modified. This
was followed by 104 passing non-native local tests in 87.435 seconds, with native
flags disabled and native methods excluded. Syntax and diff checks passed;
the documentation checker found 49 maintained documents and 236 valid links. This
correction concerns local argparse wiring; external research adds no evidence
about that defect. Earlier official backend interface sources remain applicable.
Native validation remains with the manager because sockets and systemd user
service paths are outside the coding sandbox. Local requirements entries,
multiple distributions, native-lock/build integration and live Python edits
alongside compiled output remain required unfinished work.

### Root requirements references

Manager `check-probe-1-19-1.log` passed 136 tests in 267.843 seconds without
skips. Guard and diff checks passed. This confirms the parser correction and
compiled editable terminal rebuild described above, not the subsequent increment.

The requirements adapter now recognizes `-e .`/`--editable .`/`--editable=.` and
`.` (including `./`) only for the selected Python root and with matching explicit
preparation mode. It imports the project's dependency/group/constraint declarations
into existing registry resolution. A local path never reaches the network-enabled
metadata tool. Local code retains separate source identity and resource grants.
Extras in the entry must also be explicitly selected; no review expansion occurs.
Includes remain hashed, and mutation blocks reuse. Dynamic discovery with
requirements authority and additional local paths remain unfinished.

Six focused offline tests passed in 1.342 seconds, covering declarations, extras,
constraints, registry separation, invalid/mismatched modes, path and environment
injection, symlinks, includes, setup and post-approval mutation. Two new native
PTY fixtures retain approval/rejection/cancellation, failed-build retry, real
wheel/editable import and unrelated-resource controls. They require manager
execution; no native result is claimed for this increment.
The complete selected non-native local suite then passed 110 tests in 98.819
seconds. Native flags were disabled and decorated native methods excluded before
suite construction. Changed Python syntax, diff formatting and documentation
checks passed (49 maintained documents, 236 local links). No test required an
environment installation or socket/systemd attempt in the coding sandbox.

The official [pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/)
documents local editable entries, includes and options, but does not promise a
portable parser for all pip syntax. This adapter accepts only the described
subset and rejects environment expansion. [uv package installation](https://docs.astral.sh/uv/pip/packages/)
documents native editable installs. Existing confined uv preparation still owns
that execution; this increment adds no backend, dependency or solver.

### Requirements authority during discovery

Manager `check-probe-1-20-1.log` passed 144 tests in 298.957 seconds, including
both static root requirements terminal fixtures. Guard and diff checks passed.
That result supersedes their pending status above, not the following increment.

Discovery now accepts the same explicit requirements authority as final local
preparation. The existing parser removes the reviewed root entry before registry
resolution; the same controller binds includes and constraints across discovery,
hook refinement and final review. Local version constraints wait for discovered
metadata and never refer to a registry namesake. Requirements authority without
a matching root entry fails before tools run, preventing silent omission of
project dependencies. No new backend, dependency or resolver was introduced.

Five focused offline tests passed in 4.228 seconds. They cover retained authority
and constraints, incompatible discovered versions, changed includes before hook
execution, rejection/cancellation/EOF and missing root entries. The first attempt
with system Python failed at import because `cvss` was absent; the successful run
used the manager's existing isolated source-test interpreter without modifying it.
Two new native PTY fixtures exercise dynamic wheel and editable preparation,
explicit review, failure/retry, import, stale-source denial and unrelated controls.
Their native effects await manager checks; sockets and systemd operations were
not attempted in the coding sandbox. Additional local paths, multiple local
distributions, native-lock/build integration and live Python edits alongside
compiled output remain unfinished ordinary requirements.

The official [pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/)
and [PEP 517](https://peps.python.org/pep-0517/) were rechecked for this increment.
Local entries do not eliminate executable backend hooks or their additional
requirements. This change reuses existing confined tooling and preserves every
approval boundary; documentation does not establish native success.

The complete selected non-native local suite passed 115 tests in 91.328 seconds.
Native methods were excluded before suite construction; no native result or skip
was counted as a pass. Documentation checks passed for 49 maintained documents
and 236 local links, and diff formatting passed.

### Static uv lock and local preparation increment

The retained manager result passed 151 tests in 304.280 seconds, including both
dynamic requirements terminal flows. This supersedes their pending status above.

Static local wheel/editable preparation now uses the existing native locked
export before resolving build requirements. Every selected locked dependency is
retained as an exact version and SHA256 constraint. Additional build requirements
must fit that graph; neither solver output nor a later artifact assessment may
substitute a different locked version or digest. The lock and manifest hashes,
runtime, extras and groups remain bound to approval. Export and build resolution
share the existing deadline and assessment budget. Backend execution still occurs
only after explicit approval, inside the existing offline supervisor.

The first five-test offline run passed two tests and reported three fixture errors
because repeated attempts reused an exclusive receipt directory. Each attempt now
uses a fresh directory; all five then passed in 1.777 seconds. The critical-package
fixture's provider mapping was also corrected before the rerun. No product check
or limit was relaxed. A sixth test covers the shared assessment budget.

Two new manager-only PTY fixtures generate a real static uv lock, then exercise
wheel/editable approval, rejection, cancellation, build failure, retry and import.
They assert that the resulting policy retains uv.lock authority and its digest.
Their native behavior still needs manager validation in this increment. The combined nonempty
locked runtime/build graph currently has offline injected-tool coverage; it still
needs a real native graph fixture. Dynamic locked projects, private locked sources
and Poetry/local-build integration continue to fail closed. These ordinary paths
remain required work, as do additional local paths and multiple distributions.
Compiled editable reuse remains conservatively bound to all source inputs.

A broader worker run mistakenly inherited `PTW_LINUX_TESTS=1`: filtering test
skip markers therefore included native cases. It ran 158 tests in 131.460 seconds,
with four failures and 34 errors. Observed restrictions included read-only
systemd user-service files and unavailable DNS; terminal cases consequently
failed before their intended effects. This was an invalid offline selection,
not acceptance evidence. Source was also being edited while that process ran.
No native cases were retried. Subsequent offline selection explicitly sets
`PTW_LINUX_TESTS=0` and lists the focused methods. Native acceptance remains
delegated to the supplied manager check.

With native cases explicitly disabled, the six new focused tests plus the
existing locked hash/identity/age/CVSS regression passed: seven tests in 2.542
seconds. Documentation checks passed for 49 maintained documents and 236 local
links. These results do not replace the pending manager terminal checks.

Official [uv export documentation](https://docs.astral.sh/uv/concepts/projects/export/)
and [uv constraint documentation](https://docs.astral.sh/uv/pip/compile/) informed
the reuse of locked export and additive constraints, instead of a new solver or
an override. No dependency was added. Tool documentation is not native evidence.

### Nonempty locked runtime and build graph verification

Manager run `task-9-1789615391105128659`, `check-probe-1-22-1.log`, passed
159 tests in 325.826 seconds, with no failures or skips. Guard and diff checks
also passed. This establishes the preceding static uv-lock terminal fixtures,
whose dependency graphs were empty; it does not establish nonempty resolution.

Two new native fixtures generate an actual uv lock for `idna==3.10` and resolve
the existing release-builder setuptools pin separately as a build requirement.
They use actual upstream wheels, verify their hashes, build through setuptools,
install wheel/editable modes under confinement, and import both the local module
and idna. The fixtures supply explicitly synthetic age/advisory records. They
do not assert current public vulnerability status or constitute model journeys.
An incompatible additional build pin and a changed artifact hash must fail before
backend execution. Locked inputs must remain unchanged throughout, narrower
command inputs must deny reuse, and unrelated work must survive project stop.
These new native effects are pending manager validation, not worker self-reports.

No runtime implementation, policy boundary, dependency or budget changed in this
increment. The existing [uv export](https://docs.astral.sh/uv/concepts/projects/export/)
and [constraint interfaces](https://docs.astral.sh/uv/pip/compile/) were rechecked
against official documentation; native checks must still establish installed-tool
behavior. Dynamic lock integration, additional local paths, multiple local
distributions and live Python edits alongside compiled output remain unfinished.

The first focused offline attempt used system Python and failed all seven test
imports because `cvss` was absent. No test body or native operation ran. Subsequent
offline checking uses the already provisioned isolated source-test interpreter,
without installing or changing that environment. Native sockets and systemd
checks remain delegated to the manager.

Seven focused lock-resolution/security tests passed in 2.579 seconds using that
environment. The added controller test passed in 0.664 seconds: its reviewed
lock grants only read access, and a post-approval lock mutation prevents backend
execution and package-set publication. Documentation checks passed for 49
maintained documents and 236 local links; diff formatting also passed. The new
nonempty native tests have not been run in the coding sandbox.

### Declarative compiled editable reuse

The 162-test manager result passed the preceding nonempty lock fixtures in
331.735 seconds, with no skips. Those tests used real upstream wheel bytes,
native uv resolution, protected setuptools builds/imports and explicitly
synthetic age/advisory records. This supersedes their pending status above.

The previous suffix-based receipt ignored mutable Python files even when a
compiler consumed them. The correction materializes only a reviewed projected
seed for simple declarative setuptools src-layout extensions. Excluded Python
implementation files cannot enter the build namespace through the seed or the
original repository. The original manifest is preserved. Export validation rejects
collisions with omitted paths. Versioned receipts bind the actual view and retain
the existing source, policy, tools and artifact hashes. Both the command snapshot
and current source must reproduce that view. Custom/dynamic builds and legacy
receipts use full-source binding; `--python-full-build` explicitly selects it.
See the [usage and boundaries](ONBOARDING.md#local-python-preparation).

Focused offline tests exercise seed contents, export collisions, existence/type
changes, opaque arguments, legacy/invalid receipts, review visibility and live
edits. The native fixtures require compiler checks for omitted files at source,
seed and host paths, protected wrapper/new-module imports, and unchanged native
artifacts. A forced Python include must deny stale reuse after mutation and
return the new value only after reviewed rebuilding. A direct include of an
omitted file must fail without publication. The subsequent 176-test manager
result above verifies these physical effects; no socket/systemd check ran in the
coding sandbox.

The design follows [PEP 660](https://peps.python.org/pep-0660/) and
[setuptools editable behavior](https://setuptools.pypa.io/en/latest/userguide/development_mode.html):
Python implementation edits can become live while native changes require
recompilation. The [extension interface](https://setuptools.pypa.io/en/stable/userguide/ext_modules.html)
documents additional compiler/linker inputs. The
[package discovery documentation](https://setuptools.pypa.io/en/stable/userguide/package_discovery.html)
documents implicit namespace discovery, which informs the narrow projected view.
This adapter does not infer arbitrary compiler reads or code-generation dependencies.
No new dependency, permission,
runtime mount or build budget was introduced. Dynamic locks, additional local
paths and multiple local distributions remain required implementation work.

### Offline dynamic-lock feasibility milestone

Current source adds an internal, approved preparation operation for dynamic uv
locks. It is not connected to setup yet. Ordinary setup continues to reject these
locks until the native feasibility check and discovery/final-review integration
are complete. No frozen export can authorize an installation.

The operation assesses frozen candidates, warms a fresh cache through the existing
registry-only resolver, and supplies assessed wheels to an offline build environment.
Only the scoped source is copied; the original manifest and lock have read-only
mounts during `uv export --locked --offline --no-build-isolation`. The existing
supervisor owns termination. Final evidence binds source, policy, authoritative
inputs, runtime, tool, build graph and exported artifacts. Missing metadata fails
without network fallback or lock repair. Private origins remain outside this
milestone; their already implemented requirements workflow is unchanged.

The [uv CLI reference](https://docs.astral.sh/uv/reference/cli/) requires build
dependencies to be installed when isolation is disabled and documents the
first-party exception to `--no-build`. The [locking guide](https://docs.astral.sh/uv/concepts/projects/sync/)
distinguishes frozen reuse from locked freshness validation. Those interfaces
inform the operation, but do not establish native success.

Twelve focused offline tests passed in 9.153 seconds, including five new cases
for scope, receipts, output substitution, source mutation, unavailable artifacts,
stop and failure cleanup. They mock executable tooling. New native fixtures must
prove that a dynamic backend actually ran, could not modify the manifest/lock,
could not access the network or private files, and could import an additional
approved build dependency. They then require a protected local/idna import and
stale-lock denial without installation. The idna bytes are upstream artifacts;
age/advisory records are explicitly synthetic.

The manager's `check-probe-1-1-1.log` in run `task-9-1789633139555642351`
records 183 tests in 351.286 seconds: 181 passed and both new native fixtures
failed during candidate export, before approved backend execution. Inspection
found an invalid `--frozen --no-sources` combination, explicitly rejected by the
[uv 0.12.15 export argument definitions](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-cli/src/lib.rs#L4576-L4580).
Candidate export now uses `--frozen --offline`; manifest source overrides and
nonpublic lock origins are still rejected before invocation. Authoritative
validation retains `--locked --no-sources`. Failure diagnostics expose only
fixed labels; export receipts retain the stderr hash, not its raw contents.
This correction awaits the same native manager check. It does not establish
dynamic-lock feasibility or relax either native test.

No native sockets, services or environment provisioning ran in the coding
sandbox. The first focused retry used system Python, which lacks `cvss`, so all
11 selected tests failed during import without running their bodies. A documentation
patch with mismatched context also failed without changes. The retry uses the
existing manager-provisioned test interpreter without modifying its environment.
Ten focused tests then passed; the new source-rejection test failed in four
subcases because its fixture reused a write-once receipt directory. Giving each
subcase a fresh directory corrected the fixture, and that test passed on retry.
The 11 distinct passing tests cover candidate arguments, source rejection,
redacted failure evidence, approval, source mutation, output validation, stop,
artifact failure and static/private resolver compatibility. Their tooling is
mocked; they do not replace the two pending native journeys.

Dynamic setup sequencing, final-review receipt checks, additional local paths,
multiple-source preparation and final guide consolidation remain required.

The next manager run, `check-probe-1-2-1.log` in the same retained run directory,
passed 184 of 185 tests in 350.134 seconds. The positive dynamic-lock fixture
failed in confined validation with the bounded `interpreter` diagnostic. The
stale-lock fixture accepted any validation failure, so its pass did not establish
stale-lock handling. It now requires both the export stage and uv's lock-mismatch
diagnostic; interpreter and provisioning failures cannot satisfy that assertion.

The runner provisioned `/tmp/build-env` but did not select it as uv's project
environment. The [uv 0.12.15 project interpreter implementation](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv/src/commands/project/mod.rs#L1372-L1408)
checks the project environment before falling back to system-only interpreter
selection. The runner now sets the fixed `UV_PROJECT_ENVIRONMENT=/tmp/build-env`
inside confinement and retains the reviewed system interpreter as `--python`.
This follows the [documented project environment selection](https://docs.astral.sh/uv/concepts/projects/config/#project-environment-path).
The native backend additionally asserts its actual environment, and the fixture
injects hostile project-environment and virtual-environment variables alongside
the existing index and Python-path probes. Stage labels identify environment
creation, artifact installation or export failures without publishing raw logs.
These diagnostics are observations, never policy authority.

Nine focused offline tests passed in 6.773 seconds after the environment fix.
They include runner sequencing, fixed environment selection, failure at every
subprocess boundary and retained approval/output/mutation/stop checks. All native
operations in those runner tests are mocked. No native check or source-environment
provisioning ran in the coding sandbox. The corrected native flow still needs
the manager's existing checks before integration or any success claim.

The subsequent manager run, `check-probe-1-3-1.log` in the same retained run
directory, passed 186 of 188 tests in 340.095 seconds. Both dynamic-lock fixtures
failed during export with `signals=unclassified`. The stricter stale-lock test
correctly rejected this as insufficient evidence of a stale lock. All preceding
compiled-editable and terminal fixtures passed; dynamic-lock feasibility remains
unproven.

The runner now exits unsuccessfully without appending a Python traceback and
repeated argv, which could displace uv's diagnostic from the supervisor's bounded
2,000-byte stderr tail. Fixed labels additionally distinguish backend import and
assertion failures, disabled builds, read-only mounts and missing offline cache
data. Raw backend output remains private. These labels are troubleshooting data,
not authorization or proof of confinement. The
[pinned uv build frontend](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-build-frontend/src/error.rs)
provides the backend error context; no uv arguments, grants, mounts or native
assertions were relaxed. The underlying export failure has not yet been identified.

Twelve focused offline tests passed in 7.163 seconds, including preserved failure
diagnostics, timeout and launch failures, approval, mutation and redaction checks.
Native operations were mocked in these tests. The existing manager check must
exercise the export again with these diagnostics before any further lock
integration. No native test or environment provisioning ran in the coding sandbox.

The next manager run, `check-probe-1-4-1.log`, passed 188 of 190 tests in
356.091 seconds. Both dynamic-lock tests still failed at export, this time with
`signals=interpreter`. That label also matched the normal "Using CPython ...
interpreter at" progress message, so it does not identify an interpreter defect.
The [pinned uv project implementation](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv/src/commands/project/mod.rs#L1424-L1443)
confirms that this message can describe successful selection. Environment
selection remains a hypothesis, not a verified explanation or correction.

The diagnostic method now captures each uv subprocess separately and preserves
the first and last 750 bytes of a failed subprocess's combined output before the
supervisor truncates it. Successful provisioning messages no longer contaminate
the failed export's diagnostic, and interpreter labels require failure language.
The synthetic native fixture retains a bounded diagnostic in a new private
`/tmp/ptw-local-lock-failure-*` directory, with test, runner, source and policy
hashes. The manager test log prints only its path and digest. These files are
private debugging evidence, not public results or authority to install. Ordinary
application errors still expose fixed labels only. No build arguments, approvals,
input mounts or positive/stale-lock assertions changed.

This diagnostic correction needs the same manager-native check before further
implementation. Dynamic-lock export and setup integration are still incomplete;
additional local paths and transactional multi-source preparation also remain.
Fourteen focused offline tests passed in 7.266 seconds after this correction,
with no failed local test attempts. They cover subprocess output separation,
bounded first/last diagnostics including malformed bytes, private evidence
retention, approval, output validation, mutation, redaction and stop. Native
operations remain mocked; no sockets, systemd operations or source-environment
provisioning were attempted in the coding sandbox.

The manager's `check-probe-1-5-1.log` passed 190 of 192 tests in 350.557 seconds.
The retained private diagnostic digests match the references in that log. They
identify the same failure in both dynamic-lock fixtures: the named local root
was rejected by `--no-build` before metadata execution. This is a product
argument defect, not a demonstrated interpreter or sandbox defect. The pinned
[uv 0.12.15 metadata builder](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-distribution/src/source/mod.rs#L2864-L2878)
explicitly applies build restrictions to named editables; the current CLI's
broader first-party exception is insufficient to predict this pinned behavior.

The confined locked export now uses `--no-build-package` for every approved
registry identity and every registry entry in the authoritative lock, including
unselected groups. Only the reviewed local source is exempt. Malformed registry
names and collisions with the local identity fail before backend execution.
The [pinned build-option implementation](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-configuration/src/build_options.rs)
supports package-specific denial. Provisioning still uses `--no-build`, assessed
wheel hashes and no index. Export remains offline, with preinstalled build
dependencies, read-only authoritative inputs and no automatic retry or lock
rewrite. The fresh cache is populated only by the data-only registry resolver.

Seventeen focused offline tests passed in 9.908 seconds with no failed local
test attempts in this correction. They include unselected registry restrictions,
ambiguous/malformed names, fixed environment selection, output validation,
mutation, stop and failure diagnostics. Executable operations remain mocked.
The existing native positive/import and stale-lock assertions are unchanged.
A new native negative fixture additionally places the local root in the
package-specific deny list and requires rejection before its backend marker is
written. This tests the uv restriction, not a policy denial. All three native
fixtures await manager execution. One documentation patch failed its context
match without changing files and was reapplied at the correct heading. No
sockets, systemd operations or environment provisioning ran in the coding
sandbox. Dynamic-lock user integration, additional local paths and transactional
multi-source preparation remain incomplete.

The next manager run, `check-probe-1-6-1.log`, passed 195 of 196 tests in
361.567 seconds. Package-specific build denial and stale-lock rejection passed.
The positive dynamic-lock fixture failed with `lock_stale` after resolving two
packages. Its retained diagnostic SHA-256 is
`98cae19b6f343380cde032dad0295e570a5a60f056d50f0cdd8968f565ae2ced`.
The fixture had generated a static-version lock, then changed the manifest to a
dynamic version. The pinned
[uv lock validator](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-resolver/src/lock/mod.rs#L2693-L2696)
requires a dynamic local version to be represented without a locked version.
Equal computed version values do not make these inputs equivalent. This is a
fixture defect; production `--locked` rejection remains required.

The corrected fixture first generates its dynamic lock through the real backend
in a separate approved offline preparation session. It reuses the assessed
artifacts, fresh registry cache and supervised build boundary. Only a disposable
copy receives `uv lock`; the seed manifest and lock stay read-only. This test-only
operation publishes no package set or validation receipt. After terminating that
controller, the fixture binds the generated lock in a fresh approval before
exercising the unchanged production validator. Stale identity and denied-build
cases still require failure before installation; the positive case still requires
an actual protected import. The fixture wheel now also includes its declared
`Requires-Python`, which the independent output validator requires.

An offline orchestration regression checks the separation between fixture
generation and locked validation, unchanged authoritative bytes and no package
publication. Native fixture generation and the corrected import remain pending
manager verification. An initial worker test command failed during import because
system Python lacked `cvss`; using the existing manager-provided isolated
environment passed that test. The subsequent focused run passed all 12 offline
lock tests in 3.217 seconds. An initial manifest patch listed hunks in reverse
file order and was rejected without changes; it was reapplied in file order.
No dependencies were installed and no sockets,
systemd operations or source-environment provisioning ran in the coding sandbox.
Dynamic-lock setup integration and transactional multi-source preparation remain
unfinished requirements.

### Running focused source tests

Install this checkout in the isolated source-test environment described in
[the developer instructions](README.md#run-the-tests). Detached systemd services
must import that editable source; setting PYTHONPATH alone is insufficient.
Installed-user acceptance must use a separate fresh wheel installation with no
editable source or PYTHONPATH.

Run the focused test file using that environment:

```sh
python -B -m unittest discover -s harness/tests -p test_product_ecosystems.py -v
```

Tests cover normal, malformed, conflicting and failed input/output, direct and
transitive candidate exclusions, original hashes and pins, runtime requirements,
environment filtering, source binding and PTY mixed-project rejection/approval.
Native metadata-only tests run uv over generated wheel metadata, exercise frozen
lock export, and edit real TOML while retaining comments, runtime requirements
and other groups. These establish tool behavior, not live registry evidence or
application confinement. PTY setup tests mock login/monitor startup; dependency
revision PTYs exercise real review/rejection/approval without model calls.

On a native isolated VPS, run the lightweight subset journey driver in a new
directory outside the checkout:

```sh
python -B harness/scripts/product_ecosystems_acceptance.py --out /tmp/ptw-ecosystems-UNIQUE
```

The driver stages Python, Node and TypeScript fixtures, creates new-project
sources through protected actions, installs public dependencies through the
broker, and runs imports/tests/builds with actual command cwd and publication.
It also probes a forbidden resource and checks its bytes. It records source
hashes, every failed case and explicit uncovered requirements. Synthetic fixture
approval is scripted; this is not a live model trajectory or full task gate.

An earlier broader focused run executed 57 tests: 55 passed and two native tests failed
before their intended effects. Socket creation returned `Operation not permitted`
for the authenticated fixture. Monitor service creation returned `Read-only file
system` under the operator's systemd user directory. These failures were retained;
they are not skips or successful credential/workspace evidence. The new native
tests require a private authenticated install/build/import and a narrower
workspace import after an allowed source edit, excluded-source probes, and an
unrelated-process control. The native workspace driver also found a missing
staging-parent directory for nested manifests; that defect was fixed and gained
a regression test. Its next attempt reached the systemd-directory restriction.
The subsequent manager private-Python result above supersedes the private
fixture's sandbox failure only; it does not establish the other ecosystem gates.
Run native checks outside the model sandbox. The manager suite
also needs its environment lock outside the worker's writable scope.

## Sources and assumptions

The implementation uses native additive uv constraints instead of overrides,
which can replace original compatibility requirements. It retains existing
output versions as preferences. See [official uv compile documentation](https://docs.astral.sh/uv/pip/compile/).
The settings documentation distinguishes project `constraint-dependencies`
from pip constraints. The update adapter uses uv add's constraint input and
explicit package upgrades, not dependency overrides. See
[official uv settings](https://docs.astral.sh/uv/reference/settings/#constraint-dependencies).

npm lock generation uses the documented `--before` cutoff plus a broker-filtered
metadata view for confirmed CVSS exclusions, followed by artifact checks. See
[npm 10 install documentation](https://docs.npmjs.com/cli/v10/commands/npm-install/).

The worker PATH exposed uv 0.12.1, whereas the manager's resolver notes describe
uv 0.12.15. The local resolver feasibility test used the actual installed binary;
its hash is recorded per attempt. Final manager runs must record their own tool
versions and results. No new dependency or toolchain was installed by this work.
uv's mutually exclusive `--frozen` and `--no-sync` switches were checked against
the installed CLI: declaration-only edits use `--frozen`; resolver updates use
`--no-sync`. See [uv CLI reference](https://docs.astral.sh/uv/reference/cli/).
The documented first-party exception to `--no-build` prompted the explicit
static-metadata guard. pnpm's native lock inspection is versioned and is not
an npm converter: [pnpm list](https://pnpm.io/10.x/cli/list) and
[pnpm install](https://pnpm.io/10.x/cli/install). Research establishes these
interfaces, not successful confined integration.

The Python wheel view uses the official
[Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
JSON representation; version 1.1 defines file size and upload-time metadata.
The protocol and uv CLI documentation were checked for the private-Python
diagnostic milestone. The subsequent HTTP-method fix follows the pinned
[uv 0.12.15 registry client](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-client/src/registry_client.rs),
whose `wheel_metadata_no_pep658` sends HEAD before trying range requests and
streams the wheel when ranges are unsupported. No dependency, policy or
confinement change was needed. Native success is limited to the measured
synthetic private-Python journey above.
