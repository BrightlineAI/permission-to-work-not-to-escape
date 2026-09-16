# Extending package coverage

## Aim and support boundary

Extend the Python prototype to compatible compiled wheels and npm lockfiles. Keep one approved policy, identity store, admission lock and escalation engine. Build, review and test on Algol; preserve the paper and previous evidence.

This cannot safely mean every package or arbitrary code. Source builds and lifecycle scripts execute package code during installation. A separate, resource limited build service with reviewed build dependencies would be needed for those. This release must explicitly reject them and test the rejection, not count an incomplete installation as success.

## Design

1. Add version 3 policies with ecosystem-qualified package identities (pypi:name and npm:name), an explicit native-wheel switch, and a false-only installation-script setting. Keep version 1/2 meanings unchanged. Project, task and delegate subsets still use the same identity lists and counters.
2. Use packaging.tags from the workload interpreter to select compatible Python wheels, including ABI/platform tags when explicitly enabled. uv remains the offline wheel installer. Reject unsupported wheels, source/editable/URL installs and startup hooks. No hand-written platform resolver.
3. Accept npm package-lock version 3, including nested dependencies and scoped names. Require fixed registry artifacts and integrity hashes. Check every locked package against real registry timestamps and OSV, including transitive, peer and optional entries. Do not trust lockfile declarations as evidence of package identity or dependencies.
4. Compare archive package.json dependencies with the lock and validate closure using npm's existing semver implementation. Reject aliases, git/file/URL dependencies, workspaces, links, bundled dependencies and lifecycle builds. Use npm to populate an isolated cache from checked local tarballs and run offline npm ci with scripts disabled. Do not reimplement npm extraction or resolution.
5. Stage privately and publish only after rechecking scope, freshness and stopping. Mount approved npm sets read only. Check both CommonJS and ESM imports. Existing file/Python behavior must continue to pass.

## Review questions

- Can an identically named npm package borrow Python permission? Qualified identities must prevent this.
- Can a malicious lock hide a vulnerable dependency, package alias, nested version or install hook? Validate the actual archive and the dependency graph, not only lock flags.
- Can npm download unreviewed bytes or read an ambient .npmrc/token? Install offline with no network namespace, fresh cache and explicit null config files.
- Can platform selection accidentally use controller Python rather than workload Python? Query the actual interpreter and validate the installed native extension.
- Can adding support widen existing approved policies? Version 2 remains universal-wheel only; version 3 requires review.
- Does the installed package actually run? Test physical Python and Node imports, not just successful installation exit codes.
- Does the user guide actually work? Perform fresh installation and interactive terminal workflows under an ordinary account on the VPS, then repeat from public GitHub.

## Acceptance

- Preserve all original 139 checks; add positive/negative policy, registry, integrity, archive, dependency, compatibility and shared-stop tests.
- Exercise nested npm versions, scoped names, incompatible peers and engines, malicious links/paths, lifecycle scripts and missing cache/dependencies.
- Use live registries for representative pure Python, compiled Python and npm packages, plus known vulnerable versions and age rejection.
- Fresh account: follow docs interactively for a new and an existing project. Record commands and observed effects without session credentials. Debug failures and repeat.
- Commit progress, retain sanitized results and reproduction instructions, scan for credentials, and publish only after checks pass.

## Primary references

- https://packaging.pypa.io/en/stable/tags.html
- https://packaging.python.org/en/latest/specifications/binary-distribution-format/
- https://docs.npmjs.com/cli/v10/commands/npm-ci
- https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
- https://docs.npmjs.com/cli/v10/using-npm/scripts
- https://github.com/npm/node-semver
- https://google.github.io/osv.dev/api/
