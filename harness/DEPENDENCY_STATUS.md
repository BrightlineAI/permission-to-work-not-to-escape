# Dependency implementation status

Task 3 is incomplete. These changes are an implementation subset, not a claim
that all ordinary project formats work or that native acceptance has passed.
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

Python local/editable preparation, private Python routing, pnpm, Poetry updates,
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

The credential file contains an `authorization` string. Configure exact package
names, not a fallback registry; the broker must not send private names to public
advisory services. The advisory endpoint is `/v1/query` and returns
`origin`, `name`, `version`, `coverage: "complete"` and an OSV `vulns` array.
Registry credentials go only to the configured registry origin. Redirects,
credential-bearing URLs and credential echoes fail closed. Production requires
HTTPS. Loopback HTTP is a test-only injection seam, unavailable to model callers.
No real private account was tested.

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

The current focused run executed 57 tests: 55 passed and two native tests failed
before their intended effects. Socket creation returned `Operation not permitted`
for the authenticated fixture. Monitor service creation returned `Read-only file
system` under the operator's systemd user directory. These failures were retained;
they are not skips or successful credential/workspace evidence. The new native
tests require a private authenticated install/build/import and a narrower
workspace import after an allowed source edit, excluded-source probes, and an
unrelated-process control. The native workspace driver also found a missing
staging-parent directory for nested manifests; that defect was fixed and gained
a regression test. Its next attempt reached the systemd-directory restriction.
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
