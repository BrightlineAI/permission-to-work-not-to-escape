# Dependency implementation status

Reviewed local Python wheel/editable preparation and the private-Python milestone
have passed their focused manager checks. Full ecosystem and product acceptance
remain incomplete. The immutable [product contract](PRODUCT_ACCEPTANCE.json)
is unchanged; broader Poetry integration, Node and product requirements still apply.

## Current formats and approvals

| Input | Current behavior | Remaining boundary |
|---|---|---|
| requirements.in/txt | Confined includes/constraints, hashes, markers and explicit local directory entries | Local entries in constraints, external paths and URL/VCS sources are rejected |
| PEP 621 | Static dependencies, extras and dependency groups; approved dynamic discovery | Dynamic metadata requires backend execution approval before final installation review |
| Local wheel/editable projects | Explicit source resources, isolated builds, validated imports and reviewed rebuilding | No repository-wide grant or automatic missing-dependency approval |
| Multiple local projects | Separate build graphs, local version/extra checks, one shared runtime installation | Local packages in build requirements fail closed |
| uv.lock | Static native locked export; dynamic candidate export followed by approved offline freshness validation | Private-origin locks and unavailable offline metadata fail closed |
| Poetry lock | Native locked export, wheel closure, protected import, Python constraints, group preservation and reviewed revisions with compatible age/CVSS/wheel selection; all 35 manager tests passed without skips | Public wheel-only sources; local/private integration and installed-user acceptance remain separate; see [Poetry setup](POETRY.md) |
| npm v2/v3 lock | Root, workspaces and in-tree file sources; reviewed native revisions | Full Node/TypeScript integration acceptance remains queued |
| Yarn Classic v1 | Explicit migration to npm authority, retaining yarn.lock | Broader native import/workspace acceptance remains queued |
| pnpm v9 lock | Not yet implemented | Required in the queued Node import milestone |

Python uses an explicitly reviewed installed interpreter under `/usr` satisfying
the original runtime requirements. uv resolves compatible candidates with the
approved age cutoff and additive exclusions for confirmed unsafe versions.
Independent advisory, identity and artifact checks still apply. Original exact
pins, hashes and runtime constraints cannot be overridden to obtain a pass.
Resolver work is bounded; unavailable evidence and exhausted budgets are
operational failures, not misconduct. No new general resolver was introduced.

Use the [local preparation guide](ONBOARDING.md#local-python-preparation) for
single/multiple sources, dynamic metadata, hook reviews, native code and lockfiles.
The [interactive guide](INTERACTIVE.md) covers normal protected work. Source code
and registry packages have distinct identities: a local name is never silently
substituted with a public namesake.

## Local Python evidence

The manager's `check-probe-1-20-1.log` in run
`task-9-1789633139555642351` passed **300 tests in 903.195 seconds**, with no
failures or skips. The associated guard and diff checks passed. Test source:
`harness/tests/test_product_python_local.py`, SHA-256
`9d036b02ea9e46577b1563b6ab9e8b9166aa92cdd787e72fed4724777ab1996b`.
This result covers the runtime implementation preceding this documentation-only
consolidation. Final documentation and manifest verification are separate checks.

The suite combines offline validation tests with real native, deterministic
fixtures and operator-terminal flows. Native checks assert:

- Explicit static/dynamic wheel and editable builds, real protected imports,
  selected extras, requirement-hook approvals and import after permitted edits.
- Compiled editable projected inputs unavailable to the backend/compiler;
  wrapper edits remain live, while visible build-input changes deny stale reuse.
  Full-input builds require reviewed rebuilding after any source change.
- Original static and dynamic uv locks, nonempty runtime/build graphs, native
  offline freshness validation, stale-lock rejection and unchanged lock bytes.
- Multiple sources with separate build-tool versions and one runtime graph,
  combined protected imports, per-source dynamic/hook reviews and both static
  and dynamic combined locks.
- Denied/unapproved builds, malformed outputs, traversal, mutation, environment
  injection, missing artifacts, narrower grants, rollback and shared stop.
  Private-file hashes and unrelated-process controls test physical effects.

The combined dynamic-lock fixture drives details/reject/cancel/approval, validates
two original locks in separate assessed build environments, imports both sources,
and denies reuse after a lock change. It uses synthetic advisory/age evidence,
synthetic build tools and a real public idna wheel. Registry-only resolution
populates a fresh uv metadata cache; no ambient cache is copied. These are
deterministic controller/native tests, not model trajectories or a claim about
real advisory completeness. They do not establish fresh-wheel installed-user
journeys, first-setup timing or complete product acceptance.

Earlier failures, corrections, source hashes and checkpoint results are retained
in the [implementation records](DEPENDENCY_IMPLEMENTATION_LOG.md). Original raw
manager receipts remain outside the checkout. In particular, the latest increment
recorded a missing-cvss system-Python attempt and corrected a test that mistakenly
used package-set listing as a freshness validator; the mount boundary now supplies
that oracle. No mandatory positive or negative assertion was waived.

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
package. No real private npm account or complete native npm credential journey
is claimed here; the Node milestone retains that verification requirement.

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

The manager's `check-baseline-1.log` in run `task-8-1789614885942527504`
passed all 17 private-Python tests without skips in 7.515 seconds, with matching
runtime/test hashes and a passing guard. Test-source SHA-256:
`ace0e6eba8b52aebab77b6f58f389ace0ecc8946a989f9202d20554bc2acd1cb`.
The synthetic authenticated fixture resolves, installs and imports an actual wheel.
It verifies 13 denied installs publish no set, retained violation counts,
resolver/build/application credential isolation, mount-path exclusions and
unrelated-process survival. This is retained private-milestone evidence, not a new
private-suite run for the local-Python changes or an external account test.

## Dependency revisions and remaining requirements

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

Poetry local/private integration, pnpm/Yarn completion, full Node
workspace acceptance and end-to-end ecosystem revisions remain required work.
Trusted isolated Poetry/pnpm payloads must be provisioned explicitly; an ambient
shim or automatic Corepack download is not a verified tool installation.
External/VCS sources, repository-selected plugins, arbitrary extra-marker boolean
forms, symlink-based editable trees and uncontrolled build downloads are outside
the bounded adapters. Known limitations do not waive queued ordinary formats.

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

The broader existing driver, `harness/scripts/product_ecosystems_acceptance.py`,
exercises a subset of Python/Node/TypeScript journeys. Its historical evidence
does not replace final-source full product acceptance. First-setup timing,
fresh-install journeys and real Codex behavior remain separate product gates.

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

These previously researched interfaces explain the design, not native success.
This documentation consolidation introduces no tooling API or dependency; further
web research would add nothing to the retained manager results or stable internal
interfaces. Tool hashes are recorded per attempt. Host runtimes, operator state,
native clients and the kernel remain trusted. This experimental library does not
claim complete mediation, unknown-vulnerability detection or production assurance.
