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
- Existing npm lock v2/v3 graph checks, plus manifest/lock agreement checks and
  npm's native age cutoff for newly generated locks. TypeScript shares npm policy.
- Metadata subprocesses see staged metadata, system runtimes and public network
  configuration, with an environment allowlist and isolated home/cache. They do
  not mount the host home or project. They have networking for metadata only;
  this is not an application network capability. Build and application execution
  keep the existing offline supervised boundary.

## Mandatory work still missing

Native uv/Poetry lock consistency/export and revision, pnpm/Yarn imports, npm
workspaces, local/editable source preparation, authenticated private-registry
brokering, npm CVSS candidate filtering, and dependency add/remove/update with
same-project history preservation are not implemented. Existing native locks
that need those adapters are rejected explicitly instead of silently discarded.
These are ordinary required paths, not unusually shaped projects to exclude.

The existing explicit source-build/lifecycle policy remains available for its
previous supported registry artifacts. A separate approved preparation lifecycle
for local or dynamically discovered build dependencies is still required.
The existing `--revise` setup migration is not a dependency revision preserving
one project identity. Do not use it as evidence of that requirement.

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
One test runs the real installed uv resolver over locally generated wheel
metadata with synthetic advisory evidence. It establishes native resolver
compatibility/backtracking behavior, not live registry evidence or application
confinement. PTY tests mock login/monitor startup and make no model calls.

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

During implementation, the existing ecosystem suite reached native cases but
eight failed before their intended assertions: supervised launch did not become
ready, or bubblewrap reported `loopback: Failed to create NETLINK_ROUTE socket:
Operation not permitted`. Native checks must be rerun by the manager outside
the model sandbox. No sandbox bypass was attempted. The manager's suite wrapper
also acquires an environment lock outside the worker's writable scope; its exact
test_product_ecosystems and regression commands remain manager validation.

## Sources and assumptions

The implementation uses native additive uv constraints instead of overrides,
which can replace original compatibility requirements. It retains existing
output versions as preferences. See [official uv compile documentation](https://docs.astral.sh/uv/pip/compile/).
The settings documentation distinguishes project `constraint-dependencies`
from pip constraints; no uv.lock support is claimed here. See
[official uv settings](https://docs.astral.sh/uv/reference/settings/#constraint-dependencies).

npm lock generation uses the documented `--before` cutoff, followed by existing
artifact checks. This does not enforce CVSS during npm candidate selection. See
[npm 10 install documentation](https://docs.npmjs.com/cli/v10/commands/npm-install/).

The worker PATH exposed uv 0.12.1, whereas the manager's resolver notes describe
uv 0.12.15. The local resolver feasibility test used the actual installed binary;
its hash is recorded per attempt. Final manager runs must record their own tool
versions and results. No new dependency or toolchain was installed by this work.
