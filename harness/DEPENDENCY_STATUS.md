# Dependency implementation status

Task 3 is incomplete. These changes are an implementation subset, not a claim
that all ordinary project formats work or that full ecosystem acceptance has passed.
The private-Python milestone has passed the focused native checks described below.
The immutable PRODUCT_ACCEPTANCE.json requirements remain unchanged.

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
- Frozen uv and Poetry lock exports with manifest consistency and artifact-hash
  checks. uv rejects dynamic first-party metadata before invoking a native tool:
  `--no-build` alone does not prevent editable or first-party backend execution.
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

Python local/editable preparation, pnpm, Poetry updates,
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
unchanged; its manager rerun against this correction is pending. Earlier native
results do not certify the added mount exclusions. This correction changes no
tooling interface or dependency; local mount construction establishes the issue,
so additional external research adds no evidence.

The HEAD compatibility fix follows the pinned
[uv 0.12.15 wheel client](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-client/src/registry_client.rs).
The credential-free view follows the
[Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/).
The added denial and isolation tests reuse existing interfaces and dependencies;
they introduce no new resolver or transport API.

## Validation and reproduction

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
