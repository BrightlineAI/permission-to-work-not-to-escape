# Publication review, September 14, 2026

The release was compared with the supplied final PDF, not an earlier Markdown draft. Its main result counts were recalculated from retained records. No new model runs were performed for publication.

## Checks

- Core A/B/C/D counts and matched replay identities agree with Table 1.
- Direct E and final F/G physical results agree with Table 2, with their different splits stated explicitly.
- Native shared-warning timestamps agree with the retained measurement windows and audits.
- Supporting permission records and DTAP judge files pass the evidence verifier. Negative results remain included.
- The ten offline tool workflow unit tests pass. Prior VPS packaging checks are separately labeled in `validation/`.
- Maintained documentation links resolve. The final PDF is included byte for byte; its appendix export omissions are documented separately.

## Credential review

Gitleaks 8.18.4 scanned the curated files without using Git history or suppressing inline findings. All 7,191 detections were reviewed as these non-credential values:

| Finding | Count | Why it is retained |
|---|---:|---|
| Native heartbeat markers | 6,670 | Random identifiers correlate timestamp effects; they do not authenticate access. |
| Core synthetic canaries | 196 | Values match the synthetic canaries defined in the case fixtures. |
| Container public GPG fingerprint | 140 | Public image metadata, not a private key. |
| Scripted effect markers | 120 | Generated `EP_EFFECT_` labels identify observed effects. |
| DTAP AWS example identifiers | 54 | Explicit `EXAMPLE` values in synthetic benchmark files. |
| Source file digests | 11 | Recorded SHA-256 checksums, not API keys. |

No scanner findings remain unresolved. This is a reviewed scan, not a guarantee that a scanner can detect every possible secret. Private review reports are not published. The five included `.env` files are synthetic test fixtures, not account configuration; private-key-shaped fixture blocks in two historical DTAP traces were already explicitly redacted by the recorded export.

The public repository starts with a fresh initial commit. The author's original Git history, authentication files, full private native sessions, unrelated project trees and superseded manuscripts are not copied. Historical experiment source snapshots and revision identifiers remain for reproducibility; they are not the original Git commit history.

The [publication script](publication.md) and [evidence guide](evidence.md) describe the scope and checks. `scripts/review_secret_scan.py` classifies these reviewed scanner findings without printing their values and fails on unrecognized findings. It is not a general security allowlist.
