# Extending package coverage

## Aim and support boundary

Extend the Python prototype to compatible compiled wheels and npm lockfiles. Keep one approved policy, identity store, admission lock and escalation engine. Build, review and test on Algol; preserve the paper and previous evidence.

This cannot safely mean every package or arbitrary code. Following user review, do not stop at rejecting build steps: add an explicit build-package allowlist and a registered, resource limited, offline build stage. Build dependencies must pass the same package checks. No package code runs in the controller. Unsupported cases must fail clearly rather than count incomplete installations as success.

## Design

1. Add version 3 policies with ecosystem-qualified package identities (pypi:name and npm:name), an explicit native-wheel switch, and a build-package allowlist. Keep version 1/2 meanings unchanged. Project, task and delegate subsets still use the same identity lists and counters.
2. Use packaging.tags from the workload interpreter to select compatible Python wheels, including ABI/platform tags when explicitly enabled. uv remains the offline wheel installer. Support extras and ordinary wheel data. Source distributions require explicit build authority and supplied, checked build dependencies. Keep arbitrary URL/editable routes out of registry installation; no hand-written platform resolver.
3. Accept npm package-lock version 3, including nested dependencies and scoped names. Require fixed registry artifacts and integrity hashes. Check every locked package against real registry timestamps and OSV, including transitive, peer and optional entries. Do not trust lockfile declarations as evidence of package identity or dependencies.
4. Compare archive package.json dependencies with the lock and validate closure using npm's existing semver implementation. Handle nested versions and scoped packages. Use npm to populate an isolated cache from checked local tarballs and run offline npm ci with scripts disabled; separately run explicitly authorized lifecycle builds within the same confined registered stage. Do not reimplement npm extraction or resolution.
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

## Iteration gates after user review

Work through up to 20 review/fix cycles as needed, recording actual failures and corrections: compatibility and policy migration; native Python imports; Python extras and wheel layout; real npm/TypeScript compilation; nested/peer/optional dependency validation; source builds; lifecycle builds; shared stopping during builds; metadata/integrity attacks; fresh interactive installation; existing-project migration; public-clone reproduction. Reuse a single build supervisor and package admission path, not independent policy engines.

Prepare a support matrix and concrete next steps for remaining limits. Do not claim that one sample proves compatibility with every library, operating system, private registry or application.

## Primary references

- https://packaging.pypa.io/en/stable/tags.html
- https://packaging.python.org/en/latest/specifications/binary-distribution-format/
- https://docs.npmjs.com/cli/v10/commands/npm-ci
- https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
- https://docs.npmjs.com/cli/v10/using-npm/scripts
- https://github.com/npm/node-semver
- https://google.github.io/osv.dev/api/
