# Retained VPS evidence

`final-01/` is the audited 56-execution run from the clean VPS checkout pinned to
implementation commit `33b8f9c32ec1a0b887588b9a5d6be64f80b63517`.
`development/` preserves the failed first unit-test attempt, corrected test log,
and the development audit. The development audit's only reported error is the
intentional rejection of a development-labelled run as final evidence.

The repository copy retains every raw execution record and scored artifact. It
does not duplicate the 30 MiB nono executable or mutable runtime fixture/app
directories. The run manifest records the executable SHA-256
`920bf9cbc2c8ae7a35fb8cf549ff49067889c0a92bab20eef251987267cad5c9`,
the image ID/digest, fixture hashes and source hashes; the final audit verified
them in the original isolated run directory before export.

Before export, the tree was checked for non-regular file types and scanned as text
for provider-key assignments, bearer tokens, Codex auth paths and common API-key
patterns. No provider credential or host secret was found. Fixture values beginning
with `PD-PERMITTED-` and `PD-FORBIDDEN-` are randomly generated synthetic canaries.
