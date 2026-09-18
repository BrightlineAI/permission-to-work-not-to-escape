# Yarn Classic setup

The adapter uses isolated Yarn Classic 1.22.22, original manifests and
`yarn.lock`, with npm ecosystem security rules. It supports frozen setup,
protected installs, workspace and in-tree directory sources, explicitly approved
builds and reviewed dependency changes. Manager checks covered the existing
suite, including revisions, private registries and graph validation. Regressions
for default public Yarn origins and dependency-ordered builds await native
verification. Full Yarn and overall ecosystem acceptance remain pending.

## Bootstrap

Use the isolated current-source test environment described in
[the harness README](README.md#run-the-tests). Detached native service tests
require an editable installation of this checkout in that environment; setting
PYTHONPATH alone is insufficient. Installed-user acceptance uses a separate
fresh wheel installation without editable source or PYTHONPATH.

On the Linux VPS with system Node 22, provision a new operator-owned directory:

```sh
PTW_YARN_BOOTSTRAP=$(mktemp -d /tmp/ptw-yarn-tools.XXXXXXXX)
python -m ptw.yarn_tool "$PTW_YARN_BOOTSTRAP/tool"
export PTW_YARN_TOOL="$PTW_YARN_BOOTSTRAP/tool"
python -m ptw.yarn_tool --help
```

The bootstrap downloads the exact release and upstream `@yarnpkg/lockfile`
1.1.0 parser over registry TLS and verifies each archive's reported SHA512
integrity. It records the original archives, tool files, Node
hash and `tools.lock`. This is not an independently authenticated signature.
It does not run npm install, Corepack, a global Yarn or lifecycle scripts.
No ambient authentication or proxy configuration is used. For reconstruction:

```sh
PTW_YARN_REBUILD=$(mktemp -d /tmp/ptw-yarn-rebuild.XXXXXXXX)
python -m ptw.yarn_tool "$PTW_YARN_REBUILD/tool" --lock "$PTW_YARN_TOOL/tools.lock"
```

Existing targets are errors. Failed attempts retain `tool.json`; retry in a new
directory. Changes to either payload, archive, lock or Node invalidate the tool.
Provisioning grants no package or build authority.

## Frozen terminal setup

With `PTW_YARN_TOOL` set, run from an existing Classic project:

```sh
ptw codex --editable src,dist --setup-only
```

For workspace or in-tree directory packages, select their source files explicitly,
for example `--files packages/math/index.cjs`. The original manifests and lock
are read-only review inputs. They are not converted to an npm lock. `details`
shows the source scope, package artifacts, commands and build permissions. Type
`yes` to approve the exact review. `reject`, EOF or Ctrl-C leaves setup unpublished.
Then run `ptw codex` for the protected terminal.

Dependency lifecycle scripts need explicit review. Request only exact registry
names, repeating the option when necessary:

```sh
ptw codex --editable src,dist --yarn-build esbuild --setup-only
```

This requests `npm:esbuild` build authority; it does not approve it automatically.
Local/workspace names are source permissions, not registry build grants. Project
build/test commands are separate items in the policy review. Preparation never
runs root or workspace lifecycle hooks. A dependency that requires a build blocks
installation without its reviewed grant.
Approved dependency hooks run in dependency order using verified installed
lookup locations, including hoisted and nested packages. Dependencies without
hooks still contribute ordering edges. Cycles use a deterministic break because
no complete dependency order exists; a hook that needs unavailable cyclic output
fails installation. Approval does not run root or workspace hooks.

The protected install tool takes the reviewed `yarn.lock` resource with
`content=yarn`. Operator automation can use `ptw package-install --state STATE
--session SESSION --event UNIQUE --yarn-lock /project/yarn.lock`. Use the returned
package set for reviewed commands. Source reads are restricted to each session's
grants and each command's inputs, including cached installations and native
directory copies. A narrower command can use permitted registry packages while
excluded local sources are masked.

Stale locks, changed metadata, unsupported configuration or missing evidence fail
closed. Frozen setup does not repair them.

## Reviewed dependency changes

```sh
ptw deps update 'example-package@^1.0.0' --ecosystem npm
ptw deps add 'another-package@^2.0.0' --ecosystem npm
ptw deps remove another-package --ecosystem npm
```

Use real package names from your project. `--source packages/app/package.json`
selects an already reviewed workspace declaration; `--group devDependencies`
selects its development dependencies. Review `details` before typing `yes`.
The staged proposal retains the native Yarn lock and original ranges except
for your explicit declaration edit. Native Yarn chooses compatible versions;
independent policy assessments exclude critical or young candidates and retry
within fixed budgets. Incompatible exact pins and missing evidence fail closed.
Registry metadata must supply SHA512 integrity and the SHA1 field Classic uses
in its resolved URL. Installation checks the actual archive against both.

Default `https://registry.yarnpkg.com` lock URLs remain unchanged, including in
reviewed updates. For this public alias only, the broker binds the exact path to
the `https://registry.npmjs.org` URL in assessed metadata and downloads that
artifact with SHA512 verification. The original lock's SHA1 is checked separately
before native installation. Review artifacts retain the Yarn URL. This is an
explicit public alias, not general mirror trust: changed paths, lookalike hosts
and private-origin substitutions fail. Private routes never receive this alias
mapping. Existing per-package origins guide reviewed updates; ambiguous origins
for a new version fail closed.

Only `yes` publishes the reviewed revision. Reject/cancel/EOF preserves the
current policy and inputs. Approval preserves unrelated package/build grants,
project/task identities, thresholds and violation history. It closes existing
sessions and stops registered work before publication. Restart `ptw codex` and
install the new package set afterward; old sets cannot authorize the new policy.
Concurrent input changes abort publication. Interrupted publication uses the
shared recovery journal to restore the prior policy and metadata; closed sessions
stay closed. If recovery reports a conflict, retain the attempt for operator
inspection instead of overwriting a concurrent edit.

## Private registry

Use `--npm-registry-config /absolute/operator/routes.json` at setup with the
[private npm route contract](DEPENDENCY_STATUS.md#private-npm-setup). The operator
provisions exact package routes and separate private credential references
outside the repository. HTTPS registry metadata and origin-bound advisory
coverage are required for every routed package, including transitive packages.
Yarn rc files and embedded URL credentials are rejected.

Only the broker authenticates upstream. The native resolver receives sanitized
metadata, and offline installs/builds receive assessed artifacts, without the
credential file or header. Wrong credentials or missing evidence block
publication without adding misconduct violations. Native tests use synthetic
credentials and a local HTTPS fixture with explicit certificate trust, not a real
private account. They do not certify an external registry's advisory coverage.

## Behavior and limits

Metadata admission preserves original manifests and Yarn v1 lock bytes. It uses
the existing bounded workspace and in-tree directory discovery, rejects outside
paths and symlinked metadata, competing locks, unsupported manager versions and
unreviewed project configuration. Dependency ranges are not rewritten.

The internal installation call accepts only a frozen install on a disposable stage.
It mounts the verified tool read-only, uses a fresh private cache, disables
ambient rc files, PnP and lifecycle scripts, and has no network or host home
mount. A broker-prepared offline mirror can retain the original lock origins;
Yarn itself creates cache metadata. The primitive checks unchanged inputs and
records source input hashes, tool hash, return code and output hashes. Native
failures and timeouts do not become successful package installations.

Reviewed resolution uses the pinned upstream hook API to omit fetching, linking
and building while Yarn resolves and serializes its own lock. Only admitted
metadata is mounted, and a sanitized broker supplies registry documents without
credentials. This preparation result is a candidate lock, not an installation.
The ordinary frozen installer never uses the hook. Final policy, origin, range
and installed-content checks still apply.

The internal `YarnPlan` uses the upstream data parser to admit exact selectors,
reachability, original ranges, source identities, registry URLs and SHA512
integrity. It checks archive identities, dependency edges and installed bytes,
then verifies actual dependency lookup targets. Native lifecycle calls require
explicit package names and a supplied build supervisor. Post-build verification
rejects changed metadata, dependency shadowing, links and changes outside the
approved packages. Local sources remain metadata placeholders for later
controller-authorized overlays. Controller installation reassesses policy and
input hashes before publishing the package set.

Berry/PnP, plugins and other lock generations are outside this Classic milestone
and fail explicitly.

## Validation

On the VPS, install the current checkout in the isolated source-test environment
above, then run:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_yarn.py -v
```

The native suite needs the documented Linux tools and systemd user session,
registry access for isolated tool provisioning, and `openssl` for its temporary
local HTTPS certificate. Run it through the manager outside the coding sandbox.
The sandbox cannot provide the required sockets, namespaces or detached services.
Do not treat skipped tests or mocked subprocess results as native evidence.

The suite covers original inputs, stale/malformed locks, artifact integrity,
protected imports/builds, narrower sources, critical/young releases, compatible
direct/transitive resolution, exact-pin failure, scoped and hoisted packages,
peer checks, terminal review, revision recovery/revocation, credential confinement
and shared stopping with an unrelated-job control. These deterministic synthetic
fixtures retain unique private directories and source hashes. They are not model
trajectories, installed-user journeys or proof of complete mediation.

## Interface sources

- [Classic install](https://classic.yarnpkg.com/en/docs/cli/install) documents
  frozen, offline and script-suppression flags. These are native mechanisms,
  not substitutes for independent policy and installed-content checks.
- [Pinned CLI](https://github.com/yarnpkg/yarn/blob/v1.22.22/src/cli/index.js)
  and [rc handling](https://github.com/yarnpkg/yarn/blob/v1.22.22/src/rc.js)
  establish explicit rc suppression and the separately supplied trusted config.
- [Pinned tarball fetcher](https://github.com/yarnpkg/yarn/blob/v1.22.22/src/fetchers/tarball-fetcher.js)
  identifies offline mirror naming, integrity checking and native cache creation.
- [Classic workspaces](https://classic.yarnpkg.com/lang/en/docs/workspaces/)
  describes the shared lock and native workspace links tested by this milestone.
- [Upstream lock parser API](https://github.com/yarnpkg/yarn/blob/v1.22.22/packages/lockfile/README.md)
  provides the parser used for graph admission, avoiding a new lockfile grammar.
- [Pinned hook API](https://github.com/yarnpkg/yarn/blob/v1.22.22/src/util/hooks.js)
  and [install pipeline](https://github.com/yarnpkg/yarn/blob/v1.22.22/src/cli/commands/install.js)
  separate native resolution/lock writing from fetch, link and build steps.
  This experimental API is tied to the pinned tool and requires native tests.
- [Pinned registry resolver](https://github.com/yarnpkg/yarn/blob/v1.22.22/src/resolvers/registries/npm-resolver.js)
  rewrites public npm tarball origins to the default Yarn registry and uses the
  registry SHA1 field for the lock URL fragment alongside SHA512 integrity.
- [Pinned lifecycle scheduler](https://github.com/yarnpkg/yarn/blob/v1.22.22/src/package-install-scripts.js)
  waits for dependencies and breaks cycles. The adapter applies dependency order
  to independently verified installed locations while retaining explicit grants,
  supervision and post-build validation.
