# Poetry locked import and reviewed revisions

This adapter uses Poetry 2.2.1 and poetry-plugin-export 1.9.0 in a separate
operator tool directory. Locked import preserves the manifest and lock. Native
add/remove/update resolves a staged proposal and requires explicit operator
approval before publication. A forbidden locked version is rejected during
import; compatible age/CVSS fallback belongs to a reviewed revision.

## Explicit tool setup

Use the isolated editable-source test environment described in [README.md](README.md#run-the-tests)
on the Linux VPS. Keep uv on PATH. Provision into a new directory outside every
protected repository:

```sh
PTW_POETRY_TOOL=$(mktemp -u /tmp/ptw-poetry-tool.XXXXXXXX)
python -m ptw.poetry_tool "$PTW_POETRY_TOOL" --lock harness/poetry-tools.lock
export PTW_POETRY_TOOL
```

Run this from the source checkout. The maintained [tool lock](poetry-tools.lock)
pins the complete environment measured by the manager with system Python on
Linux x86_64. Its SHA256 is
`456756c50662932774961d1fe3ca2c7082ef59fe25d5000c7aade8e2adf18b0f`.
The command copies that lock and installs wheels only into `payload`.
It does not use ambient registry configuration or credentials. `tool.json`
records interpreter, installer, lock and payload hashes. Failed attempts remain
in that directory; choose a new directory for retry. Provisioning writes one
terminal receipt and marks it ready only after the pinned version checks pass.
Provisioning compiles the pinned tools to bytecode using uv's
[`--compile-bytecode`](https://docs.astral.sh/uv/reference/cli/#uv-pip-install--compile-bytecode).
The receipt hashes those files too; changed or missing bytecode fails verification.
Offline processes retain `-B` and the read-only payload, reusing that bytecode
without writing caches. Existing verified tool directories remain usable;
provision a new directory to obtain the startup optimization.
Provisioning requires public PyPI access. Reconstruct the same tool environment
with `python -m ptw.poetry_tool NEW_DIRECTORY --lock
REVIEWED_DIRECTORY/tools.lock`, using the same system Python. Omitting `--lock`
explicitly requests a new bootstrap resolution with the fixed publication
cutoff. Review and retain its generated transitive lock before using it in place
of the maintained lock. Other platform/interpreter combinations are untested.

Export uses an offline namespace, copied manifest/lock inputs and the verified
payload mounted read-only. Python starts with `-I -S -B` and an explicit tool
path. Project plugins, host configuration, user site packages and `.pth` startup
code are excluded. Missing or modified tools fail closed. The operator-owned
tool directory and receipts are trusted, like the application installation;
these hashes do not authenticate a compromised operator account.

Every invocation rehashes all payload files before and after native execution,
including hidden files and bytecode. Directory-entry enumeration avoids repeated
path and file-status work without caching digests or trusting modification times.
Links, special files and inspection failures fail closed. Existing tool receipts
remain compatible; this verification change does not require reprovisioning.

## Positive and negative terminal flow

For an existing small public-registry Poetry project with a current
`pyproject.toml` and `poetry.lock`, put a dependency import in `src/app.py` and run:

```sh
ptw codex --editable src,tests --setup-only
```

Review the proposed Python runtime, packages and source resources. Use `details`
to inspect the review, then explicitly approve to publish setup. Run `ptw codex`
and request the reviewed test command that imports the dependency. The original
manifest and Poetry lock remain authoritative; the derived requirements are not
a migration. Select needed groups/extras through the existing
`--python-groups` and `--python-extras` options. Default groups are present `dev`
and `test` groups plus `main`; other groups require explicit selection.
Group discovery uses Poetry's native parser, including legacy
`tool.poetry.dev-dependencies` and `dependency-groups` arrays. Revisions preserve
the table or array owning each direct dependency, including markers, extras and
group inclusion entries. To edit an included dependency, name its owning group.
Conflicting declarations of the same dependency need a joint manifest review.
Poetry Python constraints such as `^3.11`, `~3.11` and `*` are parsed natively
from the manifest. The reviewed interpreter must satisfy that constraint and
`.python-version`, regardless of the lock's Python metadata. The runtime receipt
records the compatible normalized range; the original manifest remains unchanged.

For the negative flow, use a fresh copy of that project and change a dependency
constraint without regenerating `poetry.lock`. Repeat setup: native freshness
validation must reject it before installation. A fresh project can also be
rejected at the operator review, without publishing setup. URL/VCS/private/local
Poetry sources and dynamic metadata need separate source support and fail closed
here. No backend executes during locked export.
Changing only lock groups or markers cannot add installation authority. Import
requires exactly the packages reachable from active declarations in the selected
manifest groups/extras through checked wheel dependencies. A disconnected extra
package is rejected even with a current manifest hash and valid artifact hashes.
Transitive extras are followed until no new dependencies become active.

For reviewed dependency changes in an activated project, for example adding
`idna` when it is not already declared:

```sh
ptw deps add 'idna>=3.10,<4' --ecosystem pypi --source pyproject.toml
ptw deps update 'idna>=3.10,<4' --ecosystem pypi --source pyproject.toml
ptw deps remove idna --ecosystem pypi --source pyproject.toml
```

Use `details` to inspect versions, input hashes and changed files, then `yes`
to approve the exact proposal. Restart protected work with `ptw codex` after
approval and run the reviewed import/test command. Old sessions are revoked.
Unrelated grants, Python runtime, selected groups/extras, counters and stop
thresholds persist. `--group test` edits that group; `--group extra:feature`
edits the named extra. Editing an unselected group does not select it for install.
Existing dependency markers and extras remain attached when updating its range.

For a negative terminal flow, repeat an update and enter `reject` or `cancel`,
or press Ctrl-D at the review. The manifest, lock and installed policy remain
unchanged. Runtime-active dependencies require a wheel admitted by the reviewed
runtime and wheel policy, including prior lock preferences. Poetry can then
select an older compatible version within the original constraint. Revisions
retain native lock preferences; adding a range does not guarantee the newest
permitted release. An active exact pin with no admitted wheel, or forbidden by
age/CVSS, is unsatisfiable even when an older version would be safe. Registry
and advisory evidence outages abort without misconduct counts.
If inputs change during review, repeat from the new inputs. Interrupted
publication uses the existing recoverable revision journal; rollback never
revives revoked sessions or clears a project stop.

The complete lock retains dependencies inactive on Linux, such as a declaration
with `sys_platform == 'win32'`, and their transitive dependencies. Foreign wheels
provide bounded, hash-checked metadata only; they cannot authorize installation.
Metadata still requires valid publication-age and advisory evidence. A package
also reached through an active dependency must have an admitted runtime wheel.
Original manifest constraints and wheel dependency declarations remain intact.
This supports complete lock maintenance, not execution on other platforms.

## Validation and sources

The suite includes native Python constraint syntax and
legacy/PEP 735 group handling. It covers locked export, protected imports,
add/remove/update, compatible age/CVSS and transitive
fallback, unsatisfiable pins, terminal details/reject/cancel/EOF/approval,
retained grants/counters, revocation and publication recovery. It also checks
missing/conflicting lock entries and actual wheel dependency closure, including
selected extras and runtime markers. These tests use synthetic wheels/advisories
and real Poetry tooling, controller operations and protected execution, without
model calls. Full product and fresh-install acceptance remain separate.

Focused manager checks cover manifest-rooted reachability, native add/update
fallback, incompatible lock preferences, exact pins, evidence outages and
inactive-platform preservation, including a transitive dependency shared with
an active path. Full acceptance of the current changes remains pending; focused
passes do not replace the complete native suite.

After installing this checkout in the [isolated source-test environment](README.md#run-the-tests),
run on the Linux VPS with an active systemd user session and native tools:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_poetry.py -v
```

The fixture provisions the maintained tool lock in a fresh retained directory
and prints its evidence location. It creates the baseline lock with native Poetry
once per suite, then copies its bytes into each test's fresh project directory.
Exports, edits, resolutions and protected operations still run separately for
each scenario. It covers missing/conflicting lock entries,
stale locks, forged hashes, wheel dependency closure, malformed evidence and
tool failure as well as useful work and an unrelated process. No native skips
count as acceptance. Source tests must import the editable current checkout in
detached services; fresh-wheel installed-user acceptance remains separate.

The staged resolver uses Poetry's native solver with an in-memory repository.
Bounded file requests supply checked registry listings and wheel metadata without
network access in the tool namespace, source archives or backend execution.
Original constraints remain intact; forbidden candidates are excluded, including
transitive versions and prior lock preferences. Native solving, lock serialization
and export are followed by independent wheel-graph and artifact checks. Locked
import also checks the actual wheel graph rooted in active manifest declarations,
including requested extras and runtime markers, rather than trusting lock
dependency metadata or exported surplus packages. Work is bounded by
180 seconds, eight policy exclusions and 256 candidate assessments. Exhaustion
aborts without weakening policy. Wheel-only public registry Poetry projects are
the admitted boundary; local/private Poetry preparation remains separate work.

The pinned [Factory API](https://github.com/python-poetry/poetry/blob/2.2.1/src/poetry/factory.py)
supports disabling plugins. The pinned [exporter API](https://github.com/python-poetry/poetry-plugin-export/blob/1.9.0/src/poetry_plugin_export/exporter.py)
supplies group/extra selection and hashed requirements.
[Locker](https://github.com/python-poetry/poetry/blob/2.2.1/src/poetry/packages/locker.py)
supplies native freshness checks. These interfaces informed the implementation;
their documentation is not evidence that the integration passes.
The pinned [export walker](https://github.com/python-poetry/poetry-plugin-export/blob/1.9.0/src/poetry_plugin_export/walker.py)
uses lock group/marker labels; independent manifest-rooted wheel validation
prevents those labels from expanding the selected graph.
The pinned [core Factory](https://github.com/python-poetry/poetry-core/blob/2.2.1/src/poetry/core/factory.py)
owns Python constraint parsing and legacy/PEP 735 group discovery.
Its [version ranges](https://github.com/python-poetry/poetry-core/blob/2.2.1/src/poetry/core/constraints/version/version_range.py)
provide normalized constraints for the existing system-runtime selector.
The pinned [Repository](https://github.com/python-poetry/poetry/blob/2.2.1/src/poetry/repositories/repository.py)
and [Solver](https://github.com/python-poetry/poetry/blob/2.2.1/src/poetry/puzzle/solver.py)
interfaces provide native constraint selection over brokered metadata.
The pinned [Provider](https://github.com/python-poetry/poetry/blob/2.2.1/src/poetry/puzzle/provider.py)
propagates transitive markers and applies marker overrides before supplying
requirements to the solver. Runtime compatibility narrows those native solver
requirements without rewriting package declarations. This avoids depending on
marker-sensitive candidate caching: the pinned
[version solver](https://github.com/python-poetry/poetry/blob/2.2.1/src/poetry/mixology/version_solver.py)
caches candidate lists by identity and filters them by version constraints.
The existing [packaging wheel parser](https://packaging.pypa.io/en/stable/utils.html#packaging.utils.parse_wheel_filename)
supplies wheel tags for candidate filtering, using the reviewed interpreter's
existing tag probe when native wheels are allowed and `py3-none-any` otherwise.
Strict dependency parsing avoids the permissive invalid-marker/requirement
fallback in [PackageInfo](https://github.com/python-poetry/poetry/blob/2.2.1/src/poetry/inspection/info.py).
