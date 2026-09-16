# Practical repository acceptance, September 16, 2026

Implementation revision: 19bc037. Version: 0.4.0. All builds, package downloads,
model calls and tests ran on Algol 2-1, not the author's laptop. Later commits
add documentation, evidence and inventory hashes without changing this tested
runtime. The paper and its frozen experiments were not changed.

## Results

| Check | Result | Time |
|---|---|---|
| Final developer regression, including Linux integration | 221/221, zero skips | 38.4 seconds |
| Separate account, fresh installed environment | 221/221, zero skips | 37.1 seconds |
| Documented Python and TypeScript CLI workflows | 37/37 checks | 32.3 seconds |
| Description → generated policy → review → real model work | 58/58 checks | 301.2 seconds |
| Existing ecosystem acceptance, including native/source Python and npm builds | 15/15 checks | 51.9 seconds |
| Fresh installation from the published GitHub repository | 221/221, zero skips | 37.2 seconds |
| Published installation, documented CLI workflows | 37/37 checks | 38.6 seconds |
| Published installation including Codex, real Python/TypeScript agents | 46/46 checks | 266.4 seconds |

The live run generated one policy per language and reviewed it against the
explicit synthetic operator intent before activation. Each project used two
independent parent sessions, an operator-registered child, and a further child
requested by the model. The Python and TypeScript implementation agents installed
checked dependencies, fixed actual source, created and renamed a file, and ran
tests. TypeScript also compiled to an actual output file. Independent verification
agents created separate review files; both kinds of child ran the real tests.

Python used 19 runtime model calls and TypeScript 21, plus two policy-generation
calls total. The model was GPT-5.6 Sol, low effort, through authenticated Codex
CLI 0.154.0. Runtime authorization used zero additional model calls. Traces
retain usage and timing metadata. Native item metadata includes agent messages
and runtime error items; no native command-execution items were reported.
Physical results, not model statements, determined acceptance.

Security probes were scripted, not model attacks. Forbidden reads by a parent,
another independent parent and a child accumulated one shared count and stopped
the project on the third violation. Later work was rejected. Tests also verified
that three actually running parent/child commands and their subprocesses stopped
while an unrelated command completed. Other checks cover both rename endpoints,
directory moves, stale edits, hidden host resources, network isolation, forbidden
output with no publication, package scope, replay and interrupted publication.

The monitor was actually killed with SIGKILL and restarted without a manual
watch/restart command. Recovery preserved stop state and violation history.
A separately reviewed policy revision worked, while the old sessions stayed
stopped and their history remained.

## Fresh user verification

A new ordinary account, ptw-practical-user (UID 10006), installed from a clone of
the committed source using install-vps.sh --no-codex. It did not reuse the
developer environment or receive copied model credentials. Its final environment
ran the entire Linux suite and the documented CLI workflow for both languages.
Real model runs used the existing authenticated operator account on the same VPS.

After publication, the separate account cloned GitHub revision afc1622 and repeated
the full installation, Linux suite and CLI walkthrough in new directories. All 23
installed Python modules matched the published source byte for byte. The account
was then locked, its user manager stopped and lingering disabled; private evidence
was retained. System prerequisites were already installed on the VPS.

A second fresh GitHub clone and isolated installation used the full installer,
including pinned Codex 0.154.0, under the authenticated operator account. All 23
installed Python modules matched that source too. Its real agent walkthrough
passed all 46 checks using the supplied reviewed sample policies, including
independent parents and model-requested delegates in both languages. This
separately verifies the published installation; the 58-check run above also
verifies policy generation. Neither installation copied authentication files.

An additional interactive terminal session followed review, exact-hash approval,
activation, registration, checked installation, read/write, passing Python test,
forbidden-read warning, status, stop and monitor removal. The private terminal
record has SHA-256:

    2e714baca58cc99b98ad842c73e71c3f81e632411c9475536a3fe7d0123eb9ec

Test accounts and private runtime artifacts are not distributed. Published
receipts contain synthetic files, package evidence and content-free session
identifiers, not session credentials or model authentication.

## Development failures and changes

- Proposal attempt 1 failed physical acceptance. "Edit" was interpreted as
  excluding creation/deletion; one model also claimed a file was created without
  an actual create request. The sample now explicitly states lifecycle authority,
  and the generic runner prompt distinguishes final requests from imagined
  actions. Model finish remains explicitly unverified.
- Attempt 2 failed semantic review before activating the TypeScript proposal:
  it included package-manifest read access not covered by the original fixture.
  The intended sample scope now explicitly includes that read-only manifest.
  Private data remained excluded; no runtime policy was silently widened.
- An earlier live development walkthrough passed, but source changed during that
  run. It is not the release acceptance evidence. Final runs record hashes and
  reject source changes during execution.
- Review added destination-before-source ordering for rename, checks for implicit
  parent directories in command snapshots, and counted unsafe exports/foreign
  package-set requests as scope violations. Repeated inherited unit tests were
  removed so final counts are not inflated by duplicate execution.

The two failed proposal reports are retained alongside the successful final run.
These small projects demonstrate working integration, not automatic correctness
of policies for arbitrary projects or a production security certification.

## Reproduce

Follow [PRACTICAL.md](../../PRACTICAL.md) from a fresh Linux user installation.
From the repository root, using fresh output directories:

    python harness/scripts/validate.py --linux --out /outside/unit
    python harness/scripts/repository_walkthrough.py --out /outside/cli
    python harness/scripts/repository_walkthrough.py --live --out /outside/installed-live
    python harness/scripts/repository_walkthrough.py --live --propose --out /outside/live
    python harness/scripts/ecosystem_walkthrough.py --out /outside/ecosystems

The live command makes real model calls and requires your own Codex login.
Its automatic approval is restricted to the fully specified synthetic fixture
and checks its scope; normal projects require your review. Reports retain commands,
failures, physical checks, source hashes and timings. Private full run directories
remain under /home/loon/benchmarks/ptw-practical-20260916.3p5I5Z and the temporary
acceptance account on Algol. No unit test substitutes a mocked model trajectory
for live model evidence.
