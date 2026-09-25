# Private candidate: harness-v0.5.0

This is an installable test candidate, not a public release or a completed
acceptance certificate. The manager must review fresh final-source evidence,
scan generated assets, install the exact published candidate and check CI before
promotion. Never replace bytes under a previously published version.

## Install and try

Use an ordinary account on a disposable x86_64 Linux VPS with a systemd user
session, cgroups, namespaces, Python 3.11-3.13, Node 22/npm, bubblewrap, curl and
Git. Installation downloads pinned private tools and dependencies. Demos use
only synthetic inputs and local collectors; they make zero model calls.

Verify `SHA256SUMS` against the trusted candidate handoff. From its directory:

```sh
sha256sum --check SHA256SUMS
bash ./install.sh --artifact "$PWD/ptw-0.5.0-linux-x86_64.tar.gz"
~/.local/bin/ptw doctor
PTW_DEMOS=$(mktemp -d /tmp/ptw-demos.XXXXXXXX)
~/.local/bin/ptw demo run --demo dependency --out "$PTW_DEMOS/dependency"
~/.local/bin/ptw demo verify --demo dependency --out "$PTW_DEMOS/dependency" --markdown "$PTW_DEMOS/dependency.md"
~/.local/bin/ptw demo run --demo task-scope --out "$PTW_DEMOS/task-scope"
~/.local/bin/ptw demo verify --demo task-scope --out "$PTW_DEMOS/task-scope" --markdown "$PTW_DEMOS/task-scope.md"
~/.local/bin/ptw demo run --demo swarm --out "$PTW_DEMOS/swarm"
~/.local/bin/ptw demo verify --demo swarm --out "$PTW_DEMOS/swarm" --markdown "$PTW_DEMOS/swarm.md"
```

Proceed only after doctor reports ready. Exit 2 means invalid or failed demo
evidence; Ctrl-C returns 130 after cleanup. Preserve failed attempts and choose
new output directories. Verification rejects stale (24-hour), missing or changed
originals. The Markdown output is a sanitized historical summary. Nothing is
automatically uploaded. Keep raw logs, controller/session state and originals
private. Do not publish credentials or customer data.

If a demo reports missing independent namespace observations, inspect its private
`namespace.json`. Disappearing cgroup membership files are recorded under
`unavailable_memberships`; they are not successful observations. Sampling other
registered work continues. A run still needs complete matching process evidence
and no fatal observer errors. Fatal errors include their operation and errno.
If a process's `mountinfo` read returns `EINVAL` (22), the observer records its
PID, path and sample count in `unavailable_candidates` and continues sampling.
That unavailable sample proves no physical effect. Persistent unavailability
still fails when required process evidence is missing. `EINVAL` from other
inspection operations or receipt persistence remains fatal.
Preserve the failed run and use a fresh directory after resolving the cause;
never remove an error or edit a receipt to make verification pass.
For missing child-process evidence, a row showing the child's PID with its
parent's command line is only a pre-exec observation. Verification still needs
the child's executed command and original output. Current observers retain both
images; earlier receipts cannot supply the missing observation retroactively.

For a task-scope observation failure, inspect the affected private
`*-process.json` receipt. Its `observer_errors` retain the failing operation,
path, session, unit and PID where applicable, numeric errno and up to eight
traceback source locations. Tracebacks omit source text, locals and arguments;
the receipt still contains private paths and process details and must not be
shared as a public demo artifact. `ENOENT` (2) or `ENODEV` (19) while reading
cgroup membership records an unavailable sample and does not interrupt sampling
other workloads. Neither error proves cessation; complete physical observations
and the authorized useful-work control are still required. Errors from other
operations, including receipt persistence, remain fatal. Preserve the original
receipt for diagnosis.

## New, existing and everyday projects

Authenticate your own Codex client using `~/.local/bin/ptw-codex login`. In a new
or existing repository run `~/.local/bin/ptw codex`, review the proposed scope,
packages and warning/stop thresholds, then explicitly approve the exact review.
Existing activity grants no authority. For explicit scope use
`ptw codex --editable src,tests --files README.md,app.py --setup-only`.
At the approval prompt, reject, cancel or blank input exits without activation;
Ctrl-C or EOF cancels with exit 130. Retry the same command for a fresh explicit
review. Run interactive setup in a foreground terminal. If cancellation hangs,
retain the failure and inspect the launcher's signal handling; killing the
process is cleanup, not evidence that Ctrl-C worked. Do not send an approval as
a way to escape an unknown prompt.
Continue through `ptw codex --resume ID`; edits, reviewed builds/tests, dependency
changes and registered delegates retain project controls. Review a dependency
change through `ptw deps add/remove/update`. Never use an unconfined fallback.
An explicit `finish` closes the current work session; use its printed protected
resume command to continue. For checkpoints, wait for delegated work to complete
before preparation. Review the displayed candidate and approve its exact hash.
If relevant history changes afterward, prepare a fresh checkpoint and review it
again; an earlier approval cannot authorize the changed evidence.

Retry the same verified installer after interruptions. Upgrade with a new
version's bootstrap; `ptw-install rollback` selects the retained prior version.
Stop affected projects, quit sessions and remove their monitor registrations
before switching versions. Older runtimes cannot silently downgrade adopted
evidence state. `ptw-install uninstall` conservatively preserves project data,
modified files and unrelated files. If PATH is missing use the absolute commands
above; the installer prints shell-specific integration. See the bundled INSTALL.md
and [full recovery guide](https://github.com/BrightlineAI/permission-to-work-not-to-escape/blob/main/harness/INSTALL.md).

## Evidence and limits

The owner-amended PRODUCT_ACCEPTANCE.json and the unchanged
PROJECT_SAFETY_ACCEPTANCE.json and INCIDENT_SAFETY_ACCEPTANCE.json ship inside
the wheel, alongside the
review/scenario guides and deterministic CLI. The release gate must validate
per-ID evidence. Bundled guides ending in `.md.txt` are byte-identical source
snapshots for provenance; their relative references use the repository layout.
Use this RELEASE.md and the linked maintained web guides for user instructions.
The gate checks original extension/incident records and final installed bytes; an
original-only report is insufficient. All mandatory native checks and the
installer-to-protected-ready <=60-second bound remain required. Demo warm timing
excludes installation and cannot establish that bound. The owner-authorized
startup amendment replaces the earlier 30-second requirement only: about 40
seconds is desired, and exactly 60 seconds passes. Downloads and review stay
inside the full measured interval. Historical receipts and the extension/incident
contracts retain their original text and hashes; their older startup wording is
superseded by this amendment.

Mechanical enforcement is distinct from semantic detection. Optional live
semantic efficacy is unvalidated: zero measured live cases/calls here, unknown
miss/false-alert rates, unchanged eight-case/16-call cap. AT1/AT3 fixture
discrimination is not model efficacy; AT2 requires actual registered-process
cessation and unrelated-work survival, not just counters. Correctly configured
underlying sandboxing already blocks the individual demo effects. Vega adds
shared authority, child/resume continuity and separately demonstrated escalation.

The host, operator, client and supervisor remain trusted. Known-advisory package
checks cannot guarantee absence of unknown vulnerabilities. These synthetic
fixtures do not prove spontaneous behavior, correct prose policies, factual
truth, remote cancellation or universal protection. No historical prevention
rate or market adoption is claimed. Human comprehension/sharing, presentation UI
and LinuxArena are deferred/unvalidated. No optional live-model campaign is part
of this candidate.
