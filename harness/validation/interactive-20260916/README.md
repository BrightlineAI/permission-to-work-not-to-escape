# Interactive Codex acceptance on Algol 2-1

Version 0.5 passed the tests below on September 16, 2026. All implementation,
installation, model calls and workload tests ran on the VPS. These are new
software acceptance tests, not additions to the paper's benchmark scores.

## Final results

| Check | Result | Evidence |
|---|---|---|
| Clean install under a separate Linux account | 27/27 installed modules matched source; doctor passed | [Install](fresh-account/install.json), [log](fresh-account/install.log), [doctor](fresh-account/doctor.json) |
| Full Linux suite from that installation | 242 passed, zero failures or skips; 44.94 seconds | [Results and source hashes](fresh-account/linux.json) |
| New TypeScript website in the real Codex TUI | 12 checks passed, including independent functional tests and continued conversation | [Result](final-new-ts/result.json), [actual effects](final-new-ts/events.json), [oracle](final-new-ts/oracle-result.json) |
| Existing Python website | 14 checks passed; filtering/escaping fixed, feature added, original tests and private data preserved | [Result](final-existing-python/result.json), [effects](final-existing-python/events.json), [oracle](final-existing-python/oracle-result.json) |
| Existing JavaScript website | 14 checks passed | [Result](final-existing-js/result.json), [effects](final-existing-js/events.json), [oracle](final-existing-js/oracle-result.json) |
| Existing TypeScript website | 14 checks passed | [Result](final-existing-ts/result.json), [effects](final-existing-ts/events.json), [oracle](final-existing-ts/oracle-result.json) |
| Two independent Codex sessions and a registered delegate | 15 checks passed: narrow scope, shared warnings, stop after three combined violations, running process groups stopped, later admission blocked | [Result](final-security/result.json), [tool surface](final-security/surface.json), [effects](final-security/events.json) |
| Controller failure, unrelated work, policy revision and normal quit | 12 checks passed | [Result](final-lifecycle/result.json), [old project](final-lifecycle/old-status.json), [new project](final-lifecycle/new-status.json) |
| New account without Codex authentication | Clear login instruction, nonzero exit, project unchanged | [Negative check](fresh-account/unauthenticated.json) |

The four website workflows contain 54 checks; security/lifecycle add 27. These
81 checks are not 81 independent attacks. The 242-test suite includes unit tests
with explicit model/evidence test doubles and actual Linux integration tests.
The terminal workflows use genuine GPT-5.6 Sol/low calls, not a mock UI.

All final runtime modules came from commit 26b6115. Later commits improve
test recording and documentation without changing those modules. Earlier
development and clean-install repetitions are retained privately; repeated tests
are not counted as new distinct cases.

## What the user actually did

The driver opened a real pseudo terminal, ran the documented command, entered a
project description, editable directories and thresholds, inspected the proposed
synthetic policy, and approved it. It then used Codex to create or repair the
website, install checked dependencies, and build/test it. A second message added
a footer in the same conversation. A later terminal reused the approved policy.

Existing tests and private customer fixtures were hashed before the run and
checked afterward. Independent functional tests were introduced only after model
work and executed through the confined test command. A model saying “done” was
not counted as success. The generated sites, actual action records, policy
proposals and oracle results are included alongside each result.

The security test used real Codex terminals, real tool discovery and an actual
model-driven read-only delegate. Adversarial requests were then injected at the
same controller boundary so model refusal could not substitute for enforcement.
The first warned, permitted work still succeeded, and the combined threshold
stopped both parents and their brokers. Lifecycle tests separately verified that
unrelated work continued and that losing the monitor failed closed.

## Timing, measured honestly

| Website | First proposal ready for review | Reopened, idle Codex terminal |
|---|---:|---:|
| New TypeScript | 21.64 s | 7.03 s |
| Existing Python | 26.06 s | 6.50 s |
| Existing JavaScript | 15.65 s | 6.18 s |
| Existing TypeScript | 21.61 s | 6.30 s |

Reopen measurements include a three-second quiet window. They meet the
30-second repeat-start target on this VPS. First proposal timing excludes
human reading/decision time; approval-to-idle took another 5.2–7.4 seconds.
Do not describe the entire first-time setup as universally below 30 seconds.

The recorded clean application installation took 9.80 seconds, with operating
system prerequisites and a Python runtime cache already present. It is not a
fresh operating-system installation benchmark. Network and model latency vary.

Runtime authorization makes no additional LLM calls. Policy proposal generation
uses the model before review; ordinary coding and delegated work still require
normal model calls.

## Fresh-user boundary

A separate unprivileged account installed committed source into a new directory
using the documented installer and ran the full suite. It had no Codex login,
correctly reported that fact, and refused model onboarding with an actionable
message. No authentication files were copied.

The live terminal tests used another fresh application installation under the
already authenticated operator account. They exercised new and existing projects
with the installed package, not an editable development import. A new OAuth
login ceremony was not tested.

Versions: Codex CLI 0.154.0, nono 0.77.0, bubblewrap 0.12.0, uv 0.12.15, Node
22.23.2, npm 10.9.8, Debian 13 kernel 6.12.107. The separate account used Python
3.12.14 for the controller; workload Python was the system interpreter.
The operator installation used Python 3.12.13.

## Failures found and fixed

- Codex's trust dialog needed an isolated configuration file, not only a CLI
  override.
- MCP requires Codex's isolated JavaScript host; disabling that host broke all
  tool calls.
- Missing user-manager environment variables broke supervised command launches.
- A nested namespace broke uv's interpreter probe. The registered broker now
  runs outside the CLI's configuration view; workload confinement remains.
- Disabling the native shell did not remove native patching. The first
  [tool-surface check failed](development/security-01.json). The pinned model
  catalog now removes patching explicitly; the final discovery record confirms it.
- Plain JavaScript projects without dependencies needed no package-install step.
- Normal quit needed to revoke descendants, not just close the visible terminal.
- Missing login now fails before project setup. The first negative-test recorder
  looked only at stdout; it was corrected to capture the CLI's stderr message.

No failing positive control is presented as successful protection.

## Reproduce and inspect

Follow the [interactive guide](../../INTERACTIVE.md#reproduce-the-user-tests-on-a-disposable-linux-vps).
The [plan](../../INTERACTIVE_PLAN.md) explains the gates and iterations.
[Installation acceptance](../../scripts/install_acceptance.py) records installation,
doctor and source matching; its optional --check-login-only mode requires an
unauthenticated test account.

Public artifacts are a reviewed whitelist. Raw terminal logs, full Codex histories,
controller databases and session credentials remain private on the VPS.
Synthetic absolute paths were redacted; [hashes](artifact-hashes.json) retain the
original and published digests. Published approval bundles are evidence, not
files to reactivate directly with redacted paths.

Passing these bounded cases does not establish universal security or support for
every Python/npm project. The [supported scope and limits](../../INTERACTIVE.md#supported-first-version)
are part of the user contract.

[Release checks](release-checks.json) confirmed module matching, documentation,
evidence consistency and no secret-scanner findings in the harness or new
evidence. The broad repository scan also flags unchanged synthetic tokens and
public fingerprints in the historical benchmark records; it is not reported
as a globally empty scan. All 18 temporary controllers were stopped and their
monitor units removed, with test history retained. The separate test account
was locked and its user manager stopped.
