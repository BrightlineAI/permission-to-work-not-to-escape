# Package control acceptance on Algol

Implementation version 0.2.0 was built and tested on Algol on September 16, 2026. This is new prototype validation, not a change to the paper or its benchmark results.

## Results

| Check | Result | Time | Evidence |
|---|---|---|---|
| Fresh private installation | Pinned tools and hash checked dependencies installed; no Codex or model credentials required | See log | [Install log](install.log) |
| Full suite on installed code | 139 passed, zero skipped: 64 original core, 8 original Linux, 53 package core and 14 package Linux checks | 8.77 s | [Run 1](unit-1.json) |
| Repeated full suites | 139/139 in each repeat; not additional distinct tests | 7.81 s, 7.81 s | [Run 2](unit-2.json), [run 3](unit-3.json) |
| New and existing projects using documented CLI | All 16 checks passed with real PyPI, OSV and downloaded wheels | 9.97 s | [Walkthrough 1](walkthrough-1.json) |
| Repeated live walkthrough | All 16 checks passed again | 9.71 s | [Walkthrough 2](walkthrough-2.json) |
| Original file workflow regression | New and existing project CLI workflows passed without model calls | 4.33 s | [Original walkthrough](original-walkthrough.json) |
| Public GitHub clone and another fresh installation | 139/139 tests and all 16 live workflow checks passed | 8.45 s suite; 13.70 s walkthrough | [Public installation](public-install.log), [suite](public-unit.json), [walkthrough](public-walkthrough.json) |

The final installed source was commit cb958c8. All 14 installed Python modules matched that source byte for byte. Subsequent publication changes concern documentation and retained results. Python 3.12.14 runs the controller; Python 3.13.5 runs package workloads. Tools were uv 0.12.15, nono 0.77.0 and bubblewrap 0.12.0 on Debian 13, kernel 6.12.107.

## Actual effects checked

- idna==3.11 was downloaded, hash checked, installed and imported in a confined workload. The expected encoded hostname appeared in the permitted file.
- Django==3.2.0 was rejected for live critical advisories before wheel download. The walkthrough verified no second package set was published.
- A deliberately strict 100-year age policy rejected the otherwise permitted idna artifact. This is not a claim that the artifact was newly released. Synthetic tests separately cover the normal three-day boundary and disabling the age rule.
- A parent, its child and an independent agent contributed violations to one project stop. Running package work terminated; unrelated project admission continued.
- An existing version 1 project received a reviewed version 2 draft. File grants, escalation and existing files were preserved; the old project remained stopped with its history retained.
- Linux tests exercised actual uv installation, imports, immutable mounts, blocked network, concurrent publication, dependency closure, stale evidence and stopping during preparation.

Three full runs are repeated engineering checks, not 417 independent security cases. The live service tests are small examples, not a package ecosystem benchmark. All package decisions required zero LLM calls.

After publishing b200da2, the test account cloned the public GitHub repository and followed the installation instructions again into a new directory. Both the full suite and the live walkthrough passed on that installed copy. GitHub CI also passed. This additional repetition checks publication and installation, not additional distinct security cases.

## Clean user procedure

A separate ordinary Linux account installed committed source into fresh private directories. It did not use the developer's editable environment, authentication, package fixtures or alternate evidence servers. The account followed the commands in [the package guide](../../PACKAGES.md), exercised by the retained walkthrough script. Automated approval applies only to explicitly known synthetic projects.

System prerequisites were already present: this was a fresh account and application installation, not a fresh operating system. The initial source was transferred from the committed tree before public release. Because commands entered the account through sudo, XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS were set for its systemd user manager; ordinary login sessions normally provide these.

Only logs and reports are published. Private controller databases, session credentials and installation environments are excluded. Reproduce with the [documented validation commands](../../PACKAGES.md#verify-it-yourself).

Credential scanning found no leaks in the harness or its new commits. The paper and frozen experiment trees were unchanged. After acceptance, the temporary account was locked, its shell disabled and its background user manager stopped; no model authentication had been given to it.

## Bugs found and corrected

1. The first 115-test integration run had two failures: nono scrubbed PYTHONPATH, causing the system package to be imported. Setting the fixed package path after entering the sandbox fixed both. Tests inspect actual imported contents.
2. Live Django metadata mixed scored and unscored advisories. Evaluation now preserves a confirmed critical denial instead of letting missing severity obscure its cause. Otherwise uncertain severity blocks without counting misconduct.
3. Review found implementation_version still described the controller's Python even after python_version had been corrected. All interpreter-dependent marker fields now come from the actual confined interpreter; a regression test requires its conditional dependency.
4. Further review added rejection of duplicate/nonfinite evidence, malformed service responses, foreign wheel metadata and nonfinite policy thresholds. Missing data never silently becomes a clean scan.
5. Publication error handling originally depended on the next controller restart. It now immediately stops the current instance's project on an uncertain publication, without counting it as misconduct.

The suite also covers source/URL install rejection, canonical names, task and delegate narrowing, shared file/package counters, withdrawn advisories, OSV pagination, archive traversal and links, dependency collisions, hash mismatches, request replay and interrupted publication.

Passing these checks does not certify packages as harmless or cover unmediated installation tools. See the [explicit product limits](../../PACKAGES.md#limits).
