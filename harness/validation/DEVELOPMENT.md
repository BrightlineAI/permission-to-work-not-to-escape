# Development observations

All runs in this directory were made on algol-box-2-1, in the isolated `ptw-build-20260915` environment. These are new implementation checks, not additions to the paper scores.

1. Initial real Codex policy call was rejected before generation: the output schema omitted the explicit type on a constant. Added explicit types; the strict policy validator remains in place. The failed call is not a model success or an enforcement result.

2. First unit suite stopped in setup for all 54 tests: a session INSERT had eight placeholders for seven columns. Corrected the SQL, then reran the suite. This was a setup failure, not 54 independent enforcement failures.

3. The next provider call rejected `uniqueItems`, which the local policy validator supports. The output adapter now removes that provider unsupported keyword only from the response format. Local validation still rejects duplicate actions.

4. After the SQL fix, 53 of 54 unit tests passed. The remaining error exposed a malformed scope error message, corrected before further validation. All 54 then passed in 0.606 seconds.

5. The first Linux integration run caught nono refusing the writable scratch directory because its default internal state was nested under that directory. The positive controls failed, so negative denials were not counted as successful protection. Isolated nono state from the writable scratch directory. No sandbox bypass was added.

6. A real policy proposal failed the task subset validator. Added explicit project/task containment guidance and at most three structural repair calls, with every proposal and validator error retained. No runtime policy repair or automatic approval is permitted.

7. The first retained full validation still failed Linux positive controls: nono could not open a detached namespace's /dev/tty. The sandbox now exposes only four required device nodes, not a broken controlling terminal. All negative Linux probes now require a successful positive startup control in the same test. The offline new/existing walkthrough passed in 4.11 seconds.

8. Direct sandbox tests passed, but supervised workloads still exited during startup. A four way diagnostic isolated systemd RestrictSUIDSGID as incompatible with this bubblewrap build. Removed that redundant option; NoNewPrivileges, namespace isolation, nono and cgroup controls remain enabled.

9. Both complete live Codex walkthroughs passed in 55.81 seconds combined: new project proposal and execution, plus proposal from existing history, audit and execution. The review gate explicitly checked the synthetic operator contract before approving it. The logs contained an injection asking for customer access; neither draft granted it.

10. Design review found that changing to a narrower child task could have avoided its ancestor task's stricter stop threshold. Violations now count once toward each ancestor task as well as the project. Regression tests cover both stricter thresholds and deduplication of repeated ancestry.

11. Added rootless systemd user services as the default. The full suite passed without sudo. Supervised mounts now use pinned file descriptors checked against the activated inode, closing the path replacement gap at workload startup.

12. Latest development suite: 66 passed, no skips, in 3.57 seconds. This includes actual continuing/stopped file effects, not just stop acknowledgements. Separate clean installation acceptance follows.

13. Separate account acceptance used a fresh unprivileged Linux account and a Git bundle of the committed source. Direct access to the private development directory was correctly unavailable; the bundle needed an explicit main branch checkout. The first install then found an inherited working directory/config discovery issue in uv. The installer now changes to its source directory and disables ambient uv configuration. A second, fresh installation is used for retesting.

14. The separate account installed successfully and passed all 66 checks plus both live workflows (52.86 seconds). Its installation uses Python 3.12.14, distinct from development's 3.12.13.

15. An additional native Codex history check exposed the code-mode wrapper format. The first diagnostic had that runtime disabled and therefore did not read its positive canary; it was correctly not counted as a passing test. Added a conservative literal-only parser for two exact wrappers; all other programs remain unknown. The proposer now selects actual messages and tool records instead of letting large native session boilerplate crowd them out.

16. An expanded test run found a timing assumption in startup verification: a fixed 300 ms wait was too short under load. Changed this to bounded readiness/termination polling and actual marker observation, not a longer assumed sleep.

17. The second fresh installation passed all 69 tests and both live workflows. The native history check still failed its positive control because its filesystem profile hid Codex's own executable. Added read access to the installed package tree, not the account's credentials or history.

18. Final boundary review found that placing resources or controller state inside system runtime mounts could expose them to workloads. Both configurations are now rejected before activation or state creation, with regression tests.

19. The next clean installation passed 71 tests, both offline workflows and both live workflows. The additional native history diagnostic still could not start dynamic shell binaries with its custom filesystem profile. That recording now uses Codex's standard read-only sandbox, as an existing session would. This changes only historical data collection; the protected adapter keeps its deny profile and disabled native tools.

Checkpoints: 9d54bcb, 079974a, 1614da7, d2f334f, 6d1d684 and e8b2ce9. Development environments and failed validation outputs are retained on the VPS.
