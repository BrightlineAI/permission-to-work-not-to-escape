# Development observations

All runs in this directory were made on algol-box-2-1, in the isolated `ptw-build-20260915` environment. These are new implementation checks, not additions to the paper scores.

1. Initial real Codex policy call was rejected before generation: the output schema omitted the explicit type on a constant. Added explicit types; the strict policy validator remains in place. The failed call is not a model success or an enforcement result.

2. First unit suite stopped in setup for all 54 tests: a session INSERT had eight placeholders for seven columns. Corrected the SQL, then reran the suite. This was a setup failure, not 54 independent enforcement failures.

3. The next provider call rejected `uniqueItems`, which the local policy validator supports. The output adapter now removes that provider unsupported keyword only from the response format. Local validation still rejects duplicate actions.

4. After the SQL fix, 53 of 54 unit tests passed. The remaining error exposed a malformed scope error message, corrected before further validation. All 54 then passed in 0.606 seconds.

5. The first Linux integration run caught nono refusing the writable scratch directory because its default internal state was nested under that directory. The positive controls failed, so negative denials were not counted as successful protection. Isolated nono state from the writable scratch directory. No sandbox bypass was added.

6. A real policy proposal failed the task subset validator. Added explicit project/task containment guidance and at most three structural repair calls, with every proposal and validator error retained. No runtime policy repair or automatic approval is permitted.

7. The first retained full validation still failed Linux positive controls: nono could not open a detached namespace's /dev/tty. The sandbox now exposes only four required device nodes, not a broken controlling terminal. All negative Linux probes now require a successful positive startup control in the same test. The offline new/existing walkthrough passed in 4.11 seconds.

Further test outcomes and corrections are recorded below as development proceeds.
