# First project setup

Use the [installer](INSTALL.md), authenticate your own Codex account, and run
`ptw codex` in an existing canonical project directory, including an empty one.
The [quickstart](INTERACTIVE.md) covers ordinary use. This implementation is an
experimental Linux prototype. Final-source native installer and first-user timing
acceptance are still required; offline PTYs do not establish either.

## Scope and review

Setup detects Python, JavaScript and TypeScript from ordinary root filenames and
bounded configuration. `--editable src,tests` selects top-level directories;
`--files README.md,app.py` selects exact top-level files, including missing files.
Use an empty argument or `-` for no entries of that kind. Root-directory grants,
traversal, hidden/control/credential paths, links and special files are rejected.
Repository descriptions and previous logs never become permission sources.

The goal describes intent; selected typed fields grant authority. Configuration
and generated dependency locks are read only. Default package restrictions are
minimum age 3 days, reject CVSS >=9, evidence maximum age 900 seconds, no native
wheels and no source/install-script builds. These remain enforced by the existing
package controller before use; there is no deferred unchecked execution.
Advanced package-policy edits use the separate explicit policy review workflow.

The concise review shows scope, commands, packages, warn1/stop3 and two tasks.
`details` expands command argv/inputs and generated file contents. `customize`
changes scope/thresholds and creates a fresh review. Only `yes` approves. Both the
policy/inventory and generated-content plan have displayed hashes and a retained
operator approval. Blank/invalid input, rejection, cancellation, EOF and Ctrl-C
leave project files unchanged before publication. Invalid attempts stay in private
state, not the repository.

No model is needed to compile the template. `--model-proposal` explicitly requests
one optional model call to clarify descriptions, subject to exact trusted
authority equality, including every package field. It cannot expand or silently
narrow the reviewed scope. Selected `--history` is evidence only and does not
invoke that option. Invalid model responses are retained and rejected.

## Commands and current layout boundaries

Python templates check selected Python sources without executing them or writing
bytecode. Selected test directories get pytest when present in reviewed pins,
otherwise unittest discovery. Empty discovery fails. Root-only `app.py` works
without fabricated `src/` or `tests/` directories. A syntax check is not a test.

Node templates expose reviewed test/build/lint/typecheck scripts. When no test
script exists, selected test directories use bounded `*.test.js`/`*.spec.js`
discovery (also cjs/mjs); no matching files fails. A selected single root JS file
gets a syntax check. Script exit zero alone does not prove a nonempty test suite;
the native acceptance requires an independent functional oracle.

New TypeScript metadata uses the pinned compiler through normal checked package
installation. Generated tsconfig includes selected paths and publishes to `dist`
only if that directory is selected; otherwise it uses noEmit. Existing reviewed
scripts/configuration determine existing-project commands. Work commands may
publish changes only to editable grants. The `verify` task has read-only grants
and only known no-output syntax commands; arbitrary repository scripts are not
assumed read only. Commands remain bounded by the existing workspace snapshot
limits and 120-second timeout.

Python execution still uses `/usr/bin/python3`; static requirements/pyproject and
npm package locks retain their existing supported-format limits. Mixed projects,
runtime selection, local/workspace/private packages and additional lock formats
belong to the queued ecosystem work. This change does not claim those features.

## Publication and recovery

Metadata resolution, proposals, approval and failure records live under private
operator state outside the project. The installer preserves `PTW_USER_STATE` for
an explicitly chosen location; onboarding validates that it is private, canonical
and separate from project data. Other installer runtime overrides remain filtered.

After approval, a journal records all destinations and old/new identities.
Publication uses same-filesystem staging and no-replace Linux renames. Only the
review copy and private registration may replace previous files, with retained
backups. Ordinary generated destinations cannot overwrite collisions. The
controller activates a pending project, validates live resource identities and
published artifacts, then commits readiness under its lock. Pending projects
cannot register any sessions. Setup-only creates no session.

The next `ptw codex` recovers under the onboarding lock before launching. Before
controller commit, recovery undoes only matching transaction-owned effects and
restores backups. Pending controller records remain stopped as history. After
commit, recovery finishes bookkeeping without activating the identity again.
Approved revisions stop old work; rollback never revives that work or clears its
violation history. A terminal-launch failure after commit closes its session and
leaves the approved setup available for retry.

Concurrent edits are preserved as an explicit recovery conflict. Inspect the
private `setup-journal.json`, attempt directory and affected files before moving
conflicting operator data aside and retrying; do not delete controller history.
A crash in the tiny staging-directory creation window can also require inspection
when ownership could not yet be recorded. Existing-project multi-file changes
are recoverable, not atomically invisible to unrelated filesystem readers.
Filesystem timestamps are not restored by rollback. Host/operator processes are
trusted; the journal is not a defense against malicious same-account state edits.

## Measurement and verification

Thirty seconds means first installer invocation through fresh review and an idle
protected Codex TUI, including downloads, doctor, preparation and scripted human
input delays. The first successful controller receipt and physically verified
useful work are separate timings. Warm reopening is separately labeled.
The target remains unproven for this change. No new-account OAuth/MFA is claimed.

On an isolated VPS, after building an operator-verified release artifact:

    python harness/scripts/product_onboarding_acceptance.py --out /absolute/new-evidence \
      --bootstrap /absolute/release/install.sh --artifact /absolute/release/application.tar.gz \
      --sha256 THE_ARTIFACT_DIGEST --language python

Add `--existing` or select javascript/typescript for other fixture paths. This
manager-only command makes real model calls. It measures one continuous clock,
uses a fresh private installation, unsets inherited PYTHONPATH, checks installed
source hashes, and drives the existing real PTY/physical-oracle acceptance with
the installed interpreter. It records failures and reports a missed 30-second
target as unmet. Retain each failed run when retrying; do not combine a warm
retry with a fresh-install claim. The independent installer lifecycle remains
`python harness/scripts/product_install_acceptance.py --out /absolute/new-install-evidence`.

`harness/tests/test_product_onboarding.py` tests six new/existing template cases,
real terminal input/output with explicitly mocked external integrations,
root-file controller effects, failure rollback, cancellation and process-death
recovery. They are fast offline behavior tests, not real Codex/native acceptance.

## Design sources

- [Linux rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html): RENAME_NOREPLACE prevents destination overwrite; unsupported filesystems fail without a weaker fallback.
- [Node 22 filesystem API](https://nodejs.org/docs/latest-v22.x/api/fs.html#fsreaddirsyncpath-options): recursive readdirSync supports selected test-directory enumeration.

Policy schema, approval hashing, SQLite locking and package enforcement reuse
existing repository interfaces. Additional research adds nothing to those stable
internal interfaces; behavioral tests are the relevant evidence.
