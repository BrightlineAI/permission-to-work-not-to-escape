# Package control implementation plan

## Goal

Add a practical first Python package control to the existing project harness. One reviewed policy controls file permissions, package permissions, release age, vulnerability threshold and shared escalation. No separate package-manager setting may silently weaken it. Build and test on Algol only; preserve the paper and frozen experiments.

## Smallest safe first release

- Accept exact Python package pins, including all dependencies, from an operator-selected requirements file. No ranges, URLs, editable installs, extras, source builds or global installation.
- Fetch metadata from PyPI and vulnerability records from OSV. Select pure Python wheels for the system Python interpreter. Check the actual wheel metadata and full active dependency closure before installing.
- Enforce the minimum artifact age and CVSS threshold deterministically. Missing, stale, malformed or incomplete required evidence blocks without counting as agent misconduct.
- Download exact SHA256-verified artifacts into private staging. Reuse uv to install them offline, without dependencies or builds, inside bubblewrap. Never run package code in the controller.
- Publish an immutable project package set only after rechecking policy, session authority and project stop state. Confined workloads may mount an authorized set read only. Agents never receive controller files or installer network access.
- Reuse the existing SQLite identity, ancestry, event deduplication, denial counters and process stopping. No second escalation engine.

Version 2 of the policy adds package rules and task package-name subsets. Version 1 file policies continue to work with no package authority. Delegates cannot acquire package names absent from their parent. Rule changes require review and a new project version, rather than editing active state.

## Why this shape

The earlier package project supplies useful exact-artifact and fail-closed design patterns. Its fixtures and host-specific shims are not proof that this adapter works. Reuse the concepts and established tools, not its unqualified support claims.

Using a complete pinned set avoids implementing a dependency solver or allowing a resolver to fetch arbitrary URLs or execute build backends. The initial scope is deliberately pure Python wheels. Users can prepare their pins with existing tools; this gate validates them independently. Other ecosystems can later supply the same evidence and installation interface.

The policy evaluator, not uv configuration, owns age and severity. uv only installs already checked local artifacts. Bubblewrap enforces no network and limited writable staging; the runtime nono/bubblewrap controls expose only approved package sets. These layers therefore cannot disagree about which packages were authorized.

## Review challenges and revisions

1. A shell alias is bypassable. Keep native install routes unavailable in the bounded agent adapter, and network blocked in optional confined workloads. Do not claim to prevent arbitrary vendoring in an unrestricted shell.
2. The package's original creation date is irrelevant. Check the upload timestamp of the selected wheel, against the trusted clock and approved age.
3. Checking only roots misses vulnerable dependencies. Require and inspect the entire active dependency closure, including markers for the actual runtime Python.
4. A vulnerability with no usable severity is unknown, not clean. A scanner outage is an operational block, not a policy violation.
5. A benign filename does not prove safe bytes. Bind metadata, digest, wheel identity and installed files; reject archive traversal, links and duplicate paths.
6. Do not hold the project lock during network requests. Prepare privately, then atomically recheck admission and publish. Stopping can reject an installation prepared concurrently.
7. A cached successful request must not repeat an effect. Reuse the existing event identity and uncertain-effect recovery.
8. A child cannot regain package scope or erase violation history. All denied installs share the existing ancestry counters with file denials.
9. Installation scripts and automatic imports are different risks. Wheels require no build execution; package code runs only later inside the confined workload.
10. No fixture provider switch in production CLI. Tests inject a trusted test backend through Python; the user-facing path uses real PyPI/OSV.

## Validation gates

1. Pure policy tests: old and new schemas, subset widening, threshold and age changes, canonical package identity, malformed pins, missing data, severity vectors and exact age boundary.
2. Component tests: dependency closure, archive identity, hashes, traversal, metadata mismatch, replay, mixed file/package escalation, multiple parents and delegates, unrelated project, stop during preparation and crash recovery.
3. Linux effects: permitted wheel actually installs and imports; denied wheel is absent; no installer side effect on denial; installed set cannot be changed by workloads; public network and controller remain inaccessible.
4. Real service checks: permitted public package, known vulnerable version denied, configured age restriction denied. Retain responses and clearly distinguish changing live data from deterministic fixtures.
5. Fresh ordinary Linux account: install committed code, follow documentation, exercise new and existing project policies, verify positive and negative effects. Repeat after fixes.
6. Rerun all existing tests, scan publication artifacts for credentials, commit code and evidence, update release integrity inventory and publish. Record failures as well as passes.

## Sources

- [uv installation controls](https://docs.astral.sh/uv/reference/cli/)
- [uv dependency cooldown semantics](https://docs.astral.sh/uv/concepts/resolution/#dependency-cooldowns)
- [PyPI exact-version metadata](https://docs.pypi.org/api/json/)
- [OSV API](https://google.github.io/osv.dev/api/)
- [CVSS scoring library](https://github.com/RedHatProductSecurity/cvss)

These controls cover known advisory information, not every malicious or undiscovered package. The initial product is an opt-in single-host prototype, not a machine-wide package firewall.
