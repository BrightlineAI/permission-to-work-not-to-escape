# Security

This is an experimental control and verification toolkit. Do not place production credentials or private data in benchmark fixtures.

The trusted boundary includes the operator, policy configuration, host, registries, observers and execution adapter. An agent must not be able to edit these or select its own authoritative job identity.

Known limitations: constrained prose validation, incomplete mediation outside tested adapters, synthetic canary tracking, DTAP lexical-path/symlink/TOCTOU gaps, in-memory single-host escalation state, and no rollback of completed remote actions. See [architecture](docs/architecture.md).

Run tests in a disposable Linux VPS environment. Use unique run directories and resource names; never reuse or stop another contributor's containers or services. Native runs intentionally exercise permission boundaries with synthetic data.

Do not post live credentials or exploit details affecting an unpatched third-party system in a public issue. Use GitHub private vulnerability reporting once enabled on the published repository. Until then, contact the maintainer privately through an established channel; no private-report endpoint is configured by this local package.
