# Try the three Vega demos

Vega carries approved project boundaries across registered workers, children and
resumed work. These demos use deterministic workers, synthetic data and scripted
fixture approvals: real processes and physical effects, **no model calls**.

| Demo | Problem and visible outcome |
|---|---|
| `dependency` | An executing dependency tries to read/send a fake secret; confinement prevents the effects while invoices finish, with explicit safe incompletion and a reviewed replacement for the aborting variant. |
| `task-scope` | A tempting fix to A breaks B under broad access; protected work fixes A locally and leaves B intact, including child/resume attempts. |
| `swarm` | Three workers try public handoff; protected workers instead finish a correct private aggregate, chart and report, including a helper and resumed writer. |

Correctly configured underlying sandboxing already prevents these individual
effects. Vega adds shared project authority and continuity. OS denials and ordinary
failed tests do not increment controller violations. Shared warning/threshold stop,
physical cessation and unrelated-work survival have a **separate**
[report/lifecycle demonstration](../../harness/DEMO.md); the three useful-work demos
do not pretend to have reached that threshold.

## Prepare once

Use a disposable **x86_64 Linux VPS**, an ordinary account and a working systemd
user login with cgroups, namespaces and `/proc` observation available. This recipe
uses Python 3.12, bubblewrap (measured profile: 0.12.0), curl and systemd tools.
The installer supplies pinned nono and uv. Have an administrator provision missing
OS prerequisites; do not disable confinement to make a demo run. No Codex login,
credentials or model service are needed.

Use the private candidate directory supplied by the operator. The runtime wheel
bundles the demo scripts and contracts; no checkout is needed. Installation
downloads dependencies/tools; the demo uses only local collectors, and
verification/reporting makes no network requests. Keep the installation unchanged
while verifying receipts. The native packaged-candidate check remains pending.

```sh
PTW_KIT=$(mktemp -d /tmp/vega-kit.XXXXXXXX)
cd /absolute/operator-supplied-candidate
sha256sum --check SHA256SUMS
bash ./install.sh --artifact "$PWD/ptw-0.5.1-linux-x86_64.tar.gz" \
  --root "$PTW_KIT/installation" --bin-dir "$PTW_KIT/commands"
PTW="$PTW_KIT/commands/ptw"
"$PTW" doctor
```

Proceed only when doctor reports `"ready": true`. Check the bootstrap digest
against the trusted operator handoff before executing it; an adjacent checksum
alone does not authenticate a publisher. For an existing matching installation,
set `PTW` to its installed command and create a new `PTW_KIT` directory for results.
See [installation/recovery](../../harness/INSTALL.md) for packaged
installation and [Linux setup](../../harness/README.md#install-on-a-linux-vps).
Online release publication remains a separate gate; no unpublished download is
required by this recipe.

## Run, verify and read

Each run needs a new canonical output directory outside the checkout. The kit
directory exists; its three run directories must not exist yet.

```sh
"$PTW" demo run --demo dependency --out "$PTW_KIT/dependency"
"$PTW" demo verify --demo dependency --out "$PTW_KIT/dependency" --markdown "$PTW_KIT/dependency.md"
"$PTW" demo run --demo task-scope --out "$PTW_KIT/task-scope"
"$PTW" demo verify --demo task-scope --out "$PTW_KIT/task-scope" --markdown "$PTW_KIT/task-scope.md"
"$PTW" demo run --demo swarm --out "$PTW_KIT/swarm"
"$PTW" demo verify --demo swarm --out "$PTW_KIT/swarm" --markdown "$PTW_KIT/swarm.md"
cat "$PTW_KIT/dependency.md" "$PTW_KIT/task-scope.md" "$PTW_KIT/swarm.md"
```

Success is exit 0 with `"verified": true`, the matching demo name, measured
`warm_seconds`, `warm_target_met` and the actual comparison. A missed 120-second
warm target is reported honestly. Installation time is not included. The Markdown
summaries bind outcomes to original-result, projection and source digests; they
are historical summaries, not fresh acceptance certificates.

Private originals live under each run's `cases/`, `attempt.json`, `result.json`
and `timing.json`. Inspect the protected swarm result at
`$PTW_KIT/swarm/cases/vega/repo/out/report.md` with its `chart.svg` and
`aggregate.json`. The fixed-field `public-sample.json` and sibling `.md` files are
sanitized exports. Keep original receipts, installations and failed attempts
outside Git; do not publish raw controller state, session files or logs.
No command above publishes anything.

To verify again, omit `--markdown` (existing summary files are never overwritten):

```sh
"$PTW" demo verify --demo swarm --out "$PTW_KIT/swarm"
"$PTW" demo --help
```

## If it fails

- Exit 2 means invalid input, a failed run or rejected evidence; it is not a safe
  completion. Read stderr and retained `failed.json`/process receipts privately.
- Missing tools, doctor failure or inaccessible process observations: use the
  supported Linux login and installation guide. Do not use an unconfined fallback.
- Missing independent namespace observations: inspect private `namespace.json`
  errors and their operation/errno. `unavailable_memberships` records cgroup files
  lost during teardown, not successful evidence. Other registered work remains
  observable; absent complete observations or unexpected errors still fail.
- Source imports or changed installed hashes: use the matching installed wheel's
  interpreter with `PYTHONPATH`/`PYTHONHOME` unset. Keep the original installation.
- Stale (24-hour), tampered, contradictory or wrong-scenario evidence: preserve it
  and run again into new directories against the current source. A projection
  alone cannot establish success; do not edit timestamps or hashes into a pass.
- Reused/linked destinations: choose a fresh canonical path without symlinks or
  `..`. A summary must be outside both the checkout and its evidence tree.
- Ctrl-C returns 130 after cleanup and retains the failed attempt. A forced kill
  cannot promise cleanup. Follow the [demo evidence guide](README.md#run-and-verify)
  before starting a new run; never change unrelated jobs.

These fixtures do not prove spontaneous model behavior, factual correctness,
correct operator grants, universal egress protection or remote-job cancellation.
Human comprehension is unvalidated; LinuxArena and broader benchmarks are
**deferred/unvalidated**, not release prerequisites. See
[current evidence status](README.md#implementation-status),
[incident provenance](../../harness/DEMO.md#provenance-and-limits) and
[alternatives](ALTERNATIVES.md). The supplied incident review is context, not
46 demonstrated protections. No new dependency or external interface is used
here; additional web research cannot validate these local execution results.
