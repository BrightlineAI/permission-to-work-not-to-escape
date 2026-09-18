# Dependency journey fixtures

These small projects are inputs for `product_ecosystems_acceptance.py`. Python
imports a checked public wheel, Node imports an npm package, and TypeScript
compiles and executes a typed addition function. The mixed fixture is assembled
from the Python and TypeScript directories under `backend` and `frontend` in a
fresh output directory. No fixture grants access to the repository root.

The executable driver and `test_product_ecosystems.NativeJourneyTests` use the
real CLI in a PTY for six new/existing language cases, the mixed project and an
npm workspace control. Answers are scripted operator actions for these synthetic
projects only. The login prerequisite is replaced; dependency resolution,
publication, services, installation and commands use the normal implementation.
No model is called and this is not a live Codex conversation. The mixed case
exercises details, reject, cancel and EOF before approval and checks that
unapproved attempts leave project files unchanged.

New cases begin with declarations and create application sources through the
broker after approval. Existing cases preserve their manifests. The driver
checks protected edits, actual nonempty Python tests, Node imports, emitted and
executed TypeScript, workspace ESM/CommonJS imports, denied private-file access
and an unrelated process surviving project stop. The callable driver's default
input fixture remains available for the existing Node integration regression;
use `terminal=True` for PTY review.

Install the current source in the [isolated test environment](../../README.md#run-the-tests)
before native checks. Detached systemd services must import that installation;
PYTHONPATH alone is insufficient. Native checks need Linux namespaces, user
systemd, sockets and public registry/advisory access outside the coding sandbox.
The suite retains source hashes, terminal attempts, failure records and output
hashes under fresh private temporary directories announced as
`ECOSYSTEM_EVIDENCE`. Use a new `--out` directory for every standalone driver run.
Do not interpret skipped native tests or a successful syntax check as acceptance.

Focused manager checks passed the source journey matrix and the mixed/local
revision tests. Lock adapters, authenticated private registries and local Python
builds have additional tests in the approved ecosystem/regression suites.
`NativeRevisionCompositionTests` uses the same terminal helper to
revise both mixed-project ecosystems and add/update/remove registry dependencies
while retaining an approved editable Python source. Approval rebuilds that source
under confinement; the test requires protected imports after every revision.
Refusal checks preserve repository bytes, and
successful revisions preserve unrelated authority and violation history.

`InstalledWheelJourneyTests` repeats all eight cases with a fresh wheel
installation per case and no PYTHONPATH. It builds the current source using the
release builder's hashed setuptools prerequisite, installs the hashed runtime
lock, compares installed module hashes with current source in foreground and
detached services, and checks the real project monitor's interpreter. It repeats
identity verification after useful work. These native tests await successful
manager validation. They use provisioned native tools and do not measure cold
product installation, make model calls or test an external private account.

Run the approved ecosystem suite from the isolated source-test environment:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_ecosystems.py -v
```

The standalone driver accepts `--out NEW_DIRECTORY` and optional repeated `--case`
selections. It runs source journeys and support probes; the unittest suite adds
wheel installations, revision composition and failure regressions. Final
acceptance always includes the full ecosystem and regression checks.
