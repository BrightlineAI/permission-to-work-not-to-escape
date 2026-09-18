# Dependency implementation status

The bounded adapters below are implemented. Private/local Python, Poetry, pnpm,
Yarn and combined Node milestones passed manager acceptance. Focused native
checks also passed the source journey matrix, npm policy-aware fallback and
mixed/local dependency revisions. Manager checks passed the fresh-wheel journey
matrix too; final-source integration acceptance remains pending. These
results do not establish the full [product contract](PRODUCT_ACCEPTANCE.json).

## Current formats and approvals

| Input | Current behavior | Remaining boundary |
|---|---|---|
| requirements.in/txt | Confined includes/constraints, hashes, markers and explicit local directory entries | Local entries in constraints, external paths and URL/VCS sources are rejected |
| PEP 621 | Static dependencies, extras and dependency groups; approved dynamic discovery | Dynamic metadata requires backend execution approval before final installation review |
| Local wheel/editable projects | Explicit source resources, isolated builds, validated imports and reviewed rebuilding | No repository-wide grant or automatic missing-dependency approval |
| Multiple local projects | Separate build graphs, local version/extra checks, one shared runtime installation | Local packages in build requirements fail closed |
| uv.lock | Static native locked export; dynamic candidate export followed by approved offline freshness validation | Private-origin locks and unavailable offline metadata fail closed |
| Poetry lock | Native locked export, manifest-rooted wheel checks and reviewed revisions with compatible age/CVSS/wheel selection | Public wheels only; Poetry-local/private combinations are unimplemented; see [Poetry setup](POETRY.md) |
| npm v2/v3 lock | Root, workspaces and in-tree file sources; reviewed native revisions | Source closure must be approved for each command/session; no external source trees |
| Yarn Classic v1 | Native frozen authority, protected imports/builds, workspace/directory sources, private registries and reviewed revisions | Yarn Berry/PnP is unsupported; see [Yarn guide](YARN.md) |
| pnpm v9 lock | Native workspace/peer/directory imports, approved builds, private registries and reviewed revisions with exact artifact/edge checks | Pinned native tooling required; see [pnpm guide](PNPM.md) |

Python uses an explicitly reviewed installed interpreter under `/usr` satisfying
the original runtime requirements. uv resolves compatible candidates with the
approved age cutoff and additive exclusions for confirmed unsafe versions.
Independent advisory, identity and artifact checks still apply. Original exact
pins, hashes and runtime constraints cannot be overridden to obtain a pass.
Resolver work is bounded; unavailable evidence and exhausted budgets are
operational failures, not misconduct. No new general resolver was introduced.
npm similarly uses its native age cutoff and a broker-filtered metadata view
for confirmed CVSS exclusions. A safe older compatible version may be selected;
exact pins remain exact. Frozen lock import rejects forbidden versions; changing
the lock requires a reviewed revision. TypeScript uses npm security throughout.

Use the [local preparation guide](ONBOARDING.md#local-python-preparation) for
single/multiple sources, dynamic metadata, hook reviews, native code and lockfiles.
The [interactive guide](INTERACTIVE.md) covers normal protected work. Source code
and registry packages have distinct identities: a local name is never silently
substituted with a public namesake.

## Node import integration

The pnpm and Yarn milestones passed their separate manager acceptance checks.
The combined `test_product_node_import.py` gate adds protected use of both tools,
narrower delegates, foreign authority/package-set denial, changed-input and
unapproved-hook rejection, explicitly approved builds and an unrelated-project
control. This gate, including npm workspace and TypeScript compatibility,
passed its manager acceptance; final ecosystem acceptance remains separate.

The gate explicitly selects existing regressions for stale/malformed locks,
missing/corrupt artifacts, source escapes and directory copies, registry identity,
critical/young releases, compatible updates and exact-pin failure. Real terminal
tests exercise details, reject, EOF and approval, revision rollback and concurrent
edits. Authenticated local fixtures check credential confinement without an
external account. Tests retain the original assertions and use native tooling.
The TypeScript case uses the existing example and real public `typescript@5.8.3`
compiler through npm security, then compiles and executes its emitted JavaScript.
It requires live registry/advisory evidence; outages must fail, not skip.
Native npm resolution disables its unrelated CLI update notification with
[`--update-notifier=false`](https://docs.npmjs.com/cli/v10/using-npm/config/#update-notifier).
The [pinned npm implementation](https://github.com/npm/cli/blob/v10.9.8/lib/cli/update-notifier.js)
otherwise requests npm's own metadata through the project's registry view.
Dependency metadata errors still abort resolution even if npm exits successfully;
age, advisory, origin, integrity and response limits remain enforced.

On the isolated Linux VPS, first install this checkout in the
[source-test environment](README.md#run-the-tests), then run:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_node_import.py -v
```

Each native tool bootstraps into a fresh private directory. Test receipts record
source/input hashes and physical outputs, including failures. The suite requires
Node 22/npm, bubblewrap, nono, uv, openssl, sockets/network and a systemd user
session. Run through the manager outside the coding sandbox. These deterministic
fixtures and synthetic approvals are not model trajectories, fresh-wheel
installed-user journeys or complete product acceptance. The accepted pnpm/Yarn
adapters are unchanged; this gate reuses the primary
sources documented in the [pnpm](PNPM.md#interface-sources) and
[Yarn](YARN.md#interface-sources) guides.

## Local Python evidence

The accepted local-Python suite covers static/dynamic wheel and editable builds,
compiled imports, extras, multiple source/build environments, uv lock freshness,
hook reviews, narrowing, rollback and stop. Local identity comes from reviewed
source resources and digests, not fabricated registry release/advisory evidence.
All registry build/runtime dependencies still use the common package policy.
See [preparation and rebuilding](ONBOARDING.md#local-python-preparation) for
the precise live-edit boundary. Historical hashes and failed attempts remain in
the [implementation records](DEPENDENCY_IMPLEMENTATION_LOG.md) and private manager
receipts. These deterministic fixtures are not model trajectories.

## Private npm setup

Pass `--npm-registry-config /absolute/operator/routes.json` to setup. The external
owner-only file maps exact names to registry/advisory origins and a separate
credential reference:

```json
{"version":1,"packages":{"@company/example":{"registry":"https://packages.example.com","advisories":"https://advisories.example.com","credential_ref":"/absolute/operator/credential.json"}}}
```

The credential file contains an `authorization` string. Both files must be
outside project data, system runtime trees and resolver/build host mounts,
including `/etc/ssl/certs`, `/etc/resolv.conf` and `/etc/hosts`; resolved aliases
are checked too. Provision these files through the operator's secret-management
workflow. Never place credentials in project files, CLI arguments or model prompts.

Registry authorization goes only to the exact configured registry origin.
Redirects, credential-bearing URLs and credential echoes fail closed. HTTPS is
required in production; loopback HTTP is a synthetic test seam. The advisory
endpoint `/v1/query` must return `origin`, `name`, `version`, `coverage: "complete"`
and an OSV `vulns` array. An empty public lookup is insufficient for a private
package. Authenticated local fixtures with synthetic credentials exercise real
Python/npm resolution, installation, imports and approved builds, plus wrong
credentials, missing coverage, origin confusion and echo rejection. They check
that credentials stay out of resolver, build, application and model-visible
outputs. No external private account is claimed tested.

## Private Python setup and verification

Use the same configuration contract with canonical Python names, for example
`company-example`, and run:

```sh
ptw codex --python-registry-config /absolute/operator/python-routes.json --setup-only
```

The bundle binds the configuration hash, not credential contents. Each private
transitive name needs an exact route; configured names never fall back to public
registries. The registry must supply Simple API JSON at `/simple/NAME/` with
wheel hashes, sizes, upload times and runtime constraints, plus compatible release
JSON at `/pypi/NAME/VERSION/json`. The advisory origin uses the coverage contract
above. uv receives a credential-free wheel view, not upstream authorization or
the credential file. A distinct advisory origin receives no registry authorization.
Requirements and static PEP 621 declarations are supported; private uv/Poetry
locks require an additional adapter and currently fail closed.

Use `details` to review routes' bound hash, input hashes, versions and restrictions.
Only `yes` approves. Wrong credentials or unavailable/malformed evidence block
installation without misconduct counts; confirmed age/CVSS violations follow
the approved escalation policy. Correct the operator configuration or evidence
service and retry without disabling checks.

## Dependency revisions

In the operator terminal, dependency revisions use explicit review:

```sh
ptw deps add 'idna>=3.10,<4' --ecosystem pypi --source requirements.in
ptw deps update 'idna>=3.10,<4' --ecosystem pypi --source pyproject.toml
ptw deps remove idna --ecosystem pypi --source pyproject.toml --group test
ptw deps update 'typescript@>=5.8 <6' --ecosystem npm --root frontend --group devDependencies
```

`--group extra:web` selects a PEP 621 optional array for editing. Setup's selected
groups/extras remain bound; editing a group does not automatically install it.
Use `details` and approve only the intended revision. Approval preserves unrelated
scope and violation history, revokes old sessions and stops registered work.
Successful publication requires restarting protected work. Reject/cancel/EOF
does not authorize publication; recovery never revives stopped sessions.

For an approved static local Python source, registry edits preserve local entries
such as `-e .` and their confined source resources. The revision review explicitly
lists offline backend execution, installation mode and source snapshots. Approval
rebuilds the local installation with the revised assessed dependencies before
ordinary sessions may resume. A failed build restores metadata and prior authority;
sessions remain revoked and violation history remains intact. A concurrent source
replacement is preserved as a stopped recovery conflict, never silently rebound.
Dynamic metadata changes need the existing explicit discovery flow through
`ptw codex --revise`. A local native lock remains frozen during this revision path;
stale or incompatible locks fail rather than silently changing their authority.

Trusted isolated Poetry/pnpm/Yarn payloads must be provisioned explicitly; an ambient
shim or automatic Corepack download is not a verified tool installation.
External/VCS sources, repository-selected plugins, arbitrary extra-marker boolean
forms, symlink-based editable trees and uncontrolled build downloads are outside
the bounded adapters. Private uv/Poetry locks and Poetry-local combinations are
unimplemented combinations of ordinary inputs, not unusual formats. Use the
supported requirements/PEP 621 private and local paths instead of silently
changing lock authority. These limits do not imply every imaginable package works.

## Validation and reproduction

First install this checkout in a new [isolated source-test environment](README.md#run-the-tests)
on the Linux VPS. Detached systemd services must import that exact editable source;
PYTHONPATH alone is insufficient. Installed-user acceptance uses a separate fresh
wheel install with PYTHONPATH unset and verified installed hashes.

With the native tools and active systemd user session available:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_python_local.py -v
```

Do not run this native suite in the coding sandbox. Its sockets/network and
systemd operations belong to manager validation. For offline methods, explicitly
disable `PTW_LINUX_TESTS` and select only non-native cases; skipped native tests
cannot count as acceptance. Each run needs fresh temporary/evidence directories.

The approved `test_product_ecosystems.py` suite now includes
`NativeJourneyTests`: all six new/existing Python/Node/TypeScript cases, the mixed
backend/frontend case and an npm workspace control. It invokes the existing
driver with real CLI/PTY reviews, useful protected installs/tests/builds,
private-file denial and unrelated-process survival. Mixed setup checks details,
reject, cancel and EOF before approval. The first focused manager run passed this
matrix; final-source acceptance remains separate. See the [fixture guide](examples/product-ecosystems/README.md).

`NativeNpmResolutionTests` uses native npm and the real broker metadata view
with synthetic age/advisory evidence. It checks direct/transitive fallback past
a young newest release and a critical older release, frozen-lock rejection,
reviewed lock resolution, exact pins, unavailable evidence and exhausted limits.
Original declarations/lock bytes must remain unchanged until reviewed publication.
The first focused manager run passed these tests. They retain the existing finite
resolver budgets; neither a transport error nor budget exhaustion proves
unsatisfiability. Native semantics follow the
[pinned npm before definition](https://github.com/npm/cli/blob/v10.9.8/workspaces/config/lib/definitions/definitions.js).

`NativeRevisionCompositionTests` adds real terminal dependency revisions to the
mixed project and a local editable project. It requires useful imports/tests/builds
after each revision, preserved unrelated authority and history, and reject/cancel/EOF
without publication. Focused manager checks passed these composition tests.

`InstalledWheelJourneyTests` runs the same finite journey matrix in a fresh wheel
environment per case. It reuses the release builder's hashed build prerequisite
and runtime lock, verifies exact installed module hashes in foreground and
detached services, checks the actual monitor interpreter and repeats identity
verification after useful work. The driver records source/input/wheel hashes,
failed steps, terminal reviews and physical outputs in new private directories.
Manager checks passed this matrix; final-source integration acceptance remains
pending. Follow the
[source-test installation instructions](README.md#run-the-tests) before running
the approved suite; PYTHONPATH alone cannot establish detached-service identity.

The frozen integration checklist maps to existing suites as follows:

| Requirement | Behavioral checks |
|---|---|
| Common formats, six language cases, mixed repo and workspaces | `NativeJourneyTests`, `InstalledWheelJourneyTests`, native lock and accepted Poetry/Node import suites |
| Preserve reviewed compatible Python runtime | `ProductEcosystemTests`, private/local Python and Poetry runtime regressions |
| Bounded compatible age/CVSS resolution without pin override | `ProductEcosystemTests`, `NativeNpmResolutionTests`, native Poetry/pnpm/Yarn solver tests |
| Confined local/private sources and broker-only credentials | `WorkspaceSourceTests`, `PrivateRegistryTests`, `PrivatePythonTests`, accepted local/Node import suites |
| Explicit dependency and build approval, scope/history and recovery | `DependencyRevisionTests`, `NativeRevisionCompositionTests`, accepted build/terminal regressions |
| Useful physical outputs, rejection, source identity and guides | Both journey matrices, fixture receipts, hash manifest and full regression |

All original guard, ecosystem and regression checks remain mandatory. Focused
passes are development evidence. First-setup timing, resumed Codex, reassessment
and complete product acceptance retain their separate gates.

## Sources and assumptions

The implementation reuses [uv's CLI](https://docs.astral.sh/uv/reference/cli/),
[locked versus frozen export](https://docs.astral.sh/uv/concepts/projects/sync/),
[additive constraints](https://docs.astral.sh/uv/pip/compile/),
[setuptools extension inputs](https://setuptools.pypa.io/en/stable/userguide/ext_modules.html),
[package discovery](https://setuptools.pypa.io/en/latest/userguide/package_discovery.html)
and [PEP 660](https://peps.python.org/pep-0660/). Explicit projected build inputs
address [existence-sensitive includes](https://gcc.gnu.org/onlinedocs/cpp/_005f_005fhas_005finclude.html)
without inferring compiler read sets. The
[Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
and [pinned uv wheel client](https://github.com/astral-sh/uv/blob/0.12.15/crates/uv-client/src/registry_client.rs)
inform the credential-free view. npm uses its documented
[before cutoff](https://docs.npmjs.com/cli/v10/commands/npm-install/) plus independent checks.

The installed identity probe uses upstream systemd documentation for
[detached service execution and waiting](https://github.com/systemd/systemd/blob/v255/man/systemd-run.xml)
and [service environment inheritance](https://github.com/systemd/systemd/blob/v255/man/systemd.exec.xml).
It uses the monitor's normal startup environment and rejects inherited PYTHONPATH
or imports outside the fresh installation, without changing the shared manager.
The [PyPA direct URL specification](https://packaging.python.org/en/latest/specifications/direct-url-data-structure/)
permits an empty `archive_info` object for a wheel. The probe requires that object
and independently compares every installed module digest with the source hashes;
optional archive metadata hashes are not its integrity check.
These interfaces explain the design, not native success. No dependency or general
resolver was added. Tool hashes are recorded per attempt. Host runtimes, operator state,
native clients and the kernel remain trusted. This experimental library does not
claim complete mediation, unknown-vulnerability detection or production assurance.
