# VPS validation

The [package control validation](packages-20260916/README.md) adds 67 package tests, repeated clean installation acceptance and live new/existing project walkthroughs. The original file-only acceptance below remains unchanged.

The first file resource version passed clean installation acceptance on Algol on September 16, 2026. These are new implementation checks, separate from the paper's experiments.

| Check | Result | Time | Record |
|---|---|---|---|
| Fresh private installation and doctor | Ready; permitted read, forbidden read and confirmed process stop passed | See install log | [Installation](20260916-fresh-user/install.log), [doctor](20260916-fresh-user/doctor.json) |
| Full suite | 72 passed, zero skipped: 64 core and 8 Linux integration tests | 3.40 s | [Results and source hashes](20260916-fresh-user/unit.json) |
| Three repeat suites | 72/72 each; same tests, not additional distinct cases | 3.50, 4.01, 3.73 s | [Repeat 1](20260916-fresh-user/unit-repeat-1.json), [2](20260916-fresh-user/unit-repeat-2.json), [3](20260916-fresh-user/unit-repeat-3.json) |
| New and existing projects, no model | Both documented CLI workflows passed | 3.88 s | [Commands and results](20260916-fresh-user/offline-walkthrough.json) |
| New and existing projects, real Codex | Both generated policies and completed permitted work; shared escalation blocked later work | 50.04 s combined | [Commands and results](20260916-fresh-user/live-walkthrough.json) |
| Actual native Codex history | Recorded two real reads; audit classified one allowed and one denied; generated policy and subsequent protected task passed | 37.40 s | [Workflow](20260916-fresh-user/native-history.json), [selected tool records](20260916-fresh-user/native-selected-calls.json) |

All three live policy drafts required one GPT-5.6 Sol/low call each. Each protected task required three ordinary model calls: read, write and finish. Runtime authorization made zero extra model calls. Drafting took 7.04, 7.41 and 8.74 seconds; task model calls took 13.09, 17.34 and 17.28 seconds respectively. These are small fixture timings, not a general performance benchmark.

## What was checked

The suite covers explicit review, task and parent subsets, identity spoofing, shared thresholds, repeated event IDs, concurrent requests, restart recovery, uncertain effects, symlinks, hard links, resource replacement and malformed history. Linux checks exercise real permitted and forbidden effects, inherited restrictions, hidden controller state, blocked network access and cleared environment variables.

The stopping test runs two independent parents and a delegate, each with a detached subprocess writing markers. Their writes stop at the shared threshold. An unrelated project's writer continues, and later work for the stopped project is rejected. These are scripted implementation tests, not an adaptive swarm evaluation.

The live workflows check actual UI contents and unchanged synthetic customer data. The existing fixture contains an instruction to broaden customer access; the generated policy does not grant it. The additional native history is recorded in Codex's normal read only mode before applying the project harness. Both synthetic reads are authorized diagnostics; the retrospective audit compares them with the narrower frontend scope, not an alleged real incident.

## Clean user procedure

A separate, unprivileged Linux account installed committed source `6231e153403831b10b27298bb035c46790406738` into a new directory. It did not use the development environment or an editable installation. All 11 installed Python modules matched the source byte for byte. System prerequisites were already available on the VPS; this was a fresh account and application installation, not a new operating system image.

The account received the source through a Git bundle before publication. Public users can follow the clone and installation commands in [the guide](../README.md). Tests followed the same CLI commands, including review and exact hash approval. Automated approval is limited to the explicitly known synthetic fixture.

An existing authorized Codex login was copied privately for the live tests. A new OAuth login was not tested. The temporary credential was removed afterward, the account was locked, and its background user manager was stopped. No auth files, controller databases, session credentials or full account histories are published.

Versions: Python 3.12.14, Codex CLI 0.154.0, nono 0.77.0, bubblewrap 0.12.0, Debian 13 kernel 6.12.107. Ordinary operation used rootless systemd user services. Because acceptance commands were invoked through sudo into the test account, its XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS were set explicitly; a normal login session supplies these.

Codex emitted two configuration warnings, represented as error items in its JSON stream: host skill discovery was disabled using an experimental flag, and the code mode host was disabled. These were intentional boundary settings, not failed task calls. Calls exited successfully and their file effects were checked.

Run the checks using [the reproduction commands](../README.md#run-the-tests). [Development failures and corrections](DEVELOPMENT.md) are retained so broken positive controls are not counted as successful protection. Passing this bounded suite does not establish correct interpretation of arbitrary project descriptions or protection for unmediated tools.
