# pnpm import

The controller imports reviewed pnpm v9 locks through the existing npm policy.
Native manager checks cover protected workspace, peer and directory-source imports,
approved dependency builds, source confinement, frozen terminal setup, reviewed
updates and shared stopping. The adapter milestone passed manager acceptance,
including setup-build, private-registry, transitive/optional and revision-failure
tests. Combined Node and full product acceptance remain separate.
Provisioning alone does not approve a project or authorize scripts.

## Bootstrap the tool

On the isolated Linux VPS, install the current harness using
[Run the tests](README.md#run-the-tests). Keep Node22 and bubblewrap available.
Detached source tests require that isolated editable installation; PYTHONPATH
alone is insufficient. Installed-user acceptance uses separate fresh wheel installs.

Provision into a new operator directory outside the project:

```sh
PTW_PNPM_PARENT=$(mktemp -d /tmp/ptw-pnpm-tools.XXXXXXXX)
python -m ptw.pnpm_tool "$PTW_PNPM_PARENT/tool"
export PTW_PNPM_TOOL="$PTW_PNPM_PARENT/tool"
```

This downloads pnpm 10.23.0 from the public npm registry, verifies advertised
SHA512 integrity, extracts without scripts and records every payload file, the
archive and the system Node binary. It never invokes Corepack or changes global
tools. Initial provisioning trusts registry TLS and its advertised digest, not
an independent signature. Ambient credentials and proxy configuration are not read.

Keep `tools.lock`, `tool.tgz` and `tool.json` together. To reconstruct the release:

```sh
PTW_PNPM_REBUILD=$(mktemp -d /tmp/ptw-pnpm-rebuild.XXXXXXXX)
python -m ptw.pnpm_tool "$PTW_PNPM_REBUILD/tool" --lock "$PTW_PNPM_TOOL/tools.lock"
```

Existing targets are errors. Failed attempts retain a private `tool.json`; retry
in a new directory. Payload, archive, lock or Node changes invalidate verification.
There is no ambient pnpm fallback. Use `python -m ptw.pnpm_tool --help` for arguments.

## Terminal usage

After bootstrap, run from the project containing `package.json`, a v9
`pnpm-lock.yaml`, and, for workspaces, `pnpm-workspace.yaml`:

```sh
ptw codex --editable src,dist --files packages/math/index.cjs --setup-only
ptw codex
```

Choose actual source paths for your project. Each local package needs its
manifest and explicitly selected source resources. Do not select a containing
tree that overlaps a metadata file. `details` expands the exact input/artifact
bindings and named commands. Only `yes` approves; rejection or EOF leaves the
project unchanged. Frozen setup never repairs or substitutes a forbidden lock.

Inside protected work, the `install` action selects the reviewed
`pnpm-lock.yaml` resource with `content=pnpm`. Every authoritative manifest and
workspace file also needs a read grant. Its receipt supplies the package set for
named build/test commands. For an operator-held session, the equivalent is:

```sh
ptw package-install --state STATE --session SESSION --event pnpm-install-1 --pnpm-lock ./pnpm-lock.yaml
```

Project `build`, `test`, `lint` and `typecheck` scripts become explicit reviewed
commands, executed with npm's existing script runner and automatic pre/post
hooks disabled. The dependency installation itself uses native pnpm. Commands
that invoke an additional package manager or download tools are not supported.
Dependency lifecycle builds separately require the policy's explicit
`npm:NAME` build grant. Request that grant during setup with
`--pnpm-build NAME`, repeated for each exact registry dependency. For example:

```sh
ptw codex --editable src,dist --files packages/math/index.cjs --pnpm-build example --setup-only
```

The name must occur in the reviewed registry graph. Wildcards, local packages and
root hooks cannot acquire this authority. The review lists the requested builds;
only `yes` approves them. Metadata preparation executes no scripts. Actual
dependency builds occur during the protected install. Use `--revise` to change
an existing setup policy, then review its full scope and stop/session effects.

Dependency changes use the existing operator review and npm security policy:

```sh
ptw deps add 'example@^1.0.0' --ecosystem npm
ptw deps update 'example@^1.0.0' --ecosystem npm
ptw deps remove example --ecosystem npm
```

Use `--source packages/math/package.json` for a reviewed workspace declaration,
`--group devDependencies` for that group, and `--root frontend` for a nested Node
project. pnpm resolves the original ranges against broker-supplied metadata and
the minimum age, followed by independent artifact/age/CVSS assessment. Confirmed
forbidden versions are excluded within fixed retry limits. An incompatible exact
pin, missing evidence or exhausted budget fails without weakening policy.

Review `details` before approving the changed manifest and native lock. The
transaction preserves project/task identities, unrelated grants and violation
history, and revokes old sessions and package sets. Restart protected work and
install the new reviewed set. Reject/cancel/EOF keeps the old revision. A
concurrent input change aborts publication; do not edit locks during review.

## Import and build boundary

The internal adapter preserves original manifests, workspace declarations, ranges,
lock bytes, artifact origins and integrity. Native pnpm retains workspace/peer
topology. Frozen inspection may reformat its disposable lock copy; the adapter
checks structural equality and keeps the original bytes for review and install.
Semantic lock changes and any manifest change fail closed.
Broker-assessed tarballs populate a private store through a separate
frozen fetch recipe; native installation consumes the unchanged project lock
offline. No npm lock conversion or store-index repair occurs. Missing content,
forbidden frozen releases, source substitution and stale inputs fail closed.

Lock parsing uses pinned PyYAML 6.0.3 as data, rejecting tags, aliases, duplicate
keys and excessive nesting. It supplies integrity/path checks absent from native
list output, not a dependency solver. Unsupported configuration is rejected.
Workspace links and in-tree `file:` directories contain metadata placeholders;
protected commands overlay only sources authorized by both command and session
grants, including cached reuse. For example, `"math": "file:packages/math"`
requires explicit resources for `packages/math/package.json` and the selected
source files. Local identities never receive invented registry age or advisory
evidence. Native local copies must match the original manifest and contain no
source bytes. Verified graph edges identify every virtual-store copy; commands
overlay or mask those copies together with the original source directory.
pnpm hardlinks directory metadata even when registry imports use copy mode.
Before validation, the adapter replaces only complete, stage-local metadata
hardlink groups with independent copies. Outside aliases, unexpected paths and
changed metadata are rejected; published package sets still reject hardlinks.
Outside paths, symlink escapes and changed local identities fail closed.

Installation disables lifecycle scripts, pnpmfile hooks, automatic tool downloads
and cached build effects separately. Dependency lifecycle builds require explicit
`npm:NAME` entries in the reviewed policy's `build_packages`. Named pnpm rebuilds
run through the existing supervisor in bounded disposable memory without host
source, credentials or network. Export validation rejects escaping links and
changed package metadata; the adapter rechecks original inputs and the graph.
Before builds, every installed registry package's files must match its assessed
archive. Dependency links must resolve to the exact locked versions and peer
contexts, not merely compatible releases. After a build, only explicitly approved
packages may change ordinary output files and directories; their manifests and
all unapproved package contents remain bound to the assessed archives. The
complete exported tree is compared with the verified pre-build tree, including
directories, links and executable-file status. Builds cannot add or change
dependency lookup paths, nested `node_modules`, `.bin` shims, package metadata
or symbolic links, even inside an approved package. This also rejects sibling
files such as `node_modules/example.js` that could shadow a reviewed package.
The pinned tool's addition of empty `ignoredBuilds` bookkeeping is permitted;
other installation metadata must remain structurally unchanged. Native manager
checks cover registry builds, peer contexts and complete-tree shadowing regressions.
Root/local lifecycle hooks remain disabled. The pinned rebuild implementation
does not handle implicit `binding.gyp` builds reliably; those require an explicit
package build script. Build approval is not granted by provisioning the tool.

## Validation boundary

`test_product_pnpm.py` includes socket-free admission/export checks and native
fixtures with physical effects. Native fixtures retain unique private directories
with source/input hashes, tool receipts and hashed outputs. Run them through the
manager outside the coding sandbox with sockets, namespaces and systemd available.
Mocked boundaries do not establish native success.

Private registry setup uses `--npm-registry-config /absolute/operator/routes.json`
and the external route/credential contract in
[dependency status](DEPENDENCY_STATUS.md#private-npm-setup). Keep route and credential
files outside project source and runtime mounts; do not copy an `.npmrc` into the
project. Exact private names require origin-bound complete advisory evidence.
The authenticated local fixture uses synthetic credentials to test native resolution,
protected build/import and wrong-credential denial. It does not establish access
to an external private account. No credentials are supplied to pnpm or build commands.

The supported boundary is the pinned tool, v9 locks, ordinary in-tree workspace
and directory sources, and registry tarballs. Other lock generations, catalogs,
patches, custom linkers, VCS dependencies and project plugins fail explicitly.
This experimental adapter does not promise every package or unknown-vulnerability
protection. See the [combined Node import gate](DEPENDENCY_STATUS.md#node-import-integration)
for integration coverage and remaining product validation.

## Interface sources

- [pnpm list](https://pnpm.io/10.x/cli/list): lockfile-only inspection begins in
  10.23.0, motivating the tool pin.
- [pnpm install](https://pnpm.io/10.x/cli/install) and
  [fetch](https://pnpm.io/10.x/cli/fetch): frozen/offline operations and fetch's
  local-file limitation.
- [pnpm dependency layout](https://pnpm.io/10.x/symlinked-node-modules-structure):
  dependency links explain why verification follows actual resolved paths instead
  of assuming a flat npm tree or guessing virtual-store directory encodings.
- [Pinned local-directory tests](https://github.com/pnpm/pnpm/blob/v10.23.0/pkg-manager/core/test/install/local.ts)
  and [local resolver](https://github.com/pnpm/pnpm/blob/v10.23.0/resolving/local-resolver/src/index.ts):
  directory resolutions and `NAME@file:PATH` identities remain distinct from
  registry releases. These interfaces inform the adapter, not a native success claim.
- [Pinned directory fetcher](https://github.com/pnpm/pnpm/blob/v10.23.0/fetching/directory-fetcher/src/index.ts):
  local directories explicitly select hardlink import, requiring independent
  metadata copies before strict package-set validation.
- [Node 22 module resolution](https://nodejs.org/docs/latest-v22.x/api/modules.html#all-together):
  file lookup precedes directory lookup, requiring protection of sibling paths
  as well as the reviewed package directory.
- [Pinned named rebuild](https://github.com/pnpm/pnpm/blob/v10.23.0/exec/plugin-commands-rebuild/src/implementation/index.ts):
  rebuild writes `ignoredBuilds` in the internal modules manifest. Verification
  permits its empty form without allowing unrelated metadata changes.
- [pnpm settings](https://pnpm.io/10.x/settings): separate hook suppression,
  tool management, cached build effects, minimum release age and inclusion of
  artifact URLs in generated locks. The metadata-only resolver runs in a
  disposable namespace and verifies unchanged manifests after lock generation.
- [Pinned rebuild implementation](https://github.com/pnpm/pnpm/blob/v10.23.0/exec/plugin-commands-rebuild/src/implementation/index.ts):
  named package selection, root hooks in unnamed rebuilds and the implicit
  native-build limitation. Native tests must verify integration with this API.
