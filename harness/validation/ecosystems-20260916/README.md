# Python and npm validation on Algol

Validated implementation: 96c48ae, harness 0.3.0. All development, builds, tests and interactive user checks ran on algol-box-2-1. These are prototype engineering tests, not new paper benchmark results.

| Check | Result | Record |
|---|---|---|
| Development regression | 176/176, zero skips; 27.6 seconds | [Tests](development-tests.json) |
| Fresh ordinary account, installed package | 176/176, zero skips; 26.9 seconds | [Tests](fresh-tests.json) |
| Live ecosystem walkthrough | 15/15 checks; 57.1 seconds | [Commands, receipts and effects](fresh-live.json) |
| Legacy new/existing Python workflow | 16/16 checks; 16.2 seconds | [Commands, receipts and effects](fresh-legacy.json) |
| Interactive documentation | Native Python, TypeScript and existing-project migration passed | Details below |

The suite retains all 139 previous checks and adds 37 ecosystem checks. It includes real offline npm installation, lifecycle effects, scope inheritance, shared Python/npm/file escalation, stopping an active build, unsafe links, malformed locks, dependency mismatches, extras and wheel data. Tests use synthetic attacks; the walkthrough uses live PyPI, npm and OSV without fixture substitution.

## Real packages and effects

- NumPy 2.2.6 imported a native extension and computed 1 + 2 + 3 = 6.
- stopit 1.1.2 built from source offline using separately checked setuptools, wheel and packaging. The receipt retained source and built-wheel hashes.
- requests[socks] 2.34.2 installed with all six exact dependency pins and imported successfully.
- TypeScript 5.8.3 compiled typed code; the resulting JavaScript returned 42.
- esbuild 0.28.2 completed its authorized offline install script and executed its platform-specific compiler.
- CommonJS, ESM and the tsc executable worked.
- lodash 4.17.11 was denied for a known critical advisory before installation.
- The legacy walkthrough separately denied vulnerable Django, verified a strict age rule and stopped work after combined violations from a parent, child and independent agent.

The installed environment used Python 3.12.14 for the controller, system Python 3.13.5 for workloads, Node 22.23.2, npm 10.9.8, uv 0.12.15, nono 0.77.0 and bubblewrap 0.12.0. No Codex installation, model call or API credential was needed.

## Failed checks retained and fixed

The [initial age-blocked walkthrough](development-age-block.json) correctly rejected urllib3 2.8.0, uploaded less than three days earlier. The positive fixture moved to 2.7.0 without weakening policy.

The [initial esbuild walkthrough](development-hardlink-block.json) exposed legitimate hard links in esbuild's output. The exporter now emits independent file contents, while still rejecting external symbolic links and link-based traversal. A regression test covers this.

Earlier synthetic tests also exposed npm's conflicting empty configuration paths and its reliance on a lockfile install-script flag. Both were corrected before acceptance. The [review log](../../ECOSYSTEM_PLAN.md#review-and-correction-log) records the sequence.

## Interactive user check

A fresh, unprivileged account ran the complete installer from an exported copy of the committed source, following the [user guide](../../ECOSYSTEMS.md) in an interactive terminal. Doctor reported ready, with Codex not installed.

The operator reviewed each displayed policy, pasted its review hash into approval, activated it, registered a session, installed the packages and checked actual output:

| Workflow | Observed result |
|---|---|
| New Python project | resources/ui.txt contained 6 after a real NumPy call |
| Existing Python project | Old project stopped; new reviewed identity installed successfully; output stayed 6 and old installation history remained |
| New npm/TypeScript project | resources/ui.txt contained var answer = 42; after transpiling a typed declaration |
| Cleanup | Project stops confirmed registered build and workload processes were stopped |

The private terminal transcript is retained on the VPS with SHA256 2df1ec7e1415c88f0788947c8c0efed27c7e4ff93987474cd1b363333c6d9d72. Published reports contain synthetic policy data and receipts, not session tokens, environment credentials or controller databases. Credential scans of the changes and selected evidence found no leaks.

## Reproduce

Follow the installation section of the [current guide](../../ECOSYSTEMS.md), then run its three verification commands from a fresh checkout with new output directories. They exit nonzero on assertion failure and retain reports. Network failures, new advisories or newer artifact dates can legitimately change the result.

These results establish the listed workflows on this Linux host, not compatibility with every library or proof that unreported malicious packages are safe. Source builds needing missing toolchains, private registries, workspace/Git/local dependency adapters and other package ecosystems have explicit next steps in the guide.
