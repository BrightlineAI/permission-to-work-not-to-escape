# Recoverable Linux installation

These instructions target the pending 0.5.1 candidate. The existing 0.5.0
prerelease remains unchanged; it does not contain the later runtime fixes.
The paper repository and benchmark history are not part of the application artifact.

Use an ordinary x86_64 Linux account with Python 3.11 to 3.13, Node 22/npm,
bubblewrap, and a working systemd user session on PATH. The previously measured
runtime profile used Python 3.12 and bubblewrap 0.12.0. Other accepted Python
versions still require available wheels for every pinned dependency and a passing
doctor. Ask your administrator to supply missing OS prerequisites. Installation
never runs sudo or changes global packages. Keep the selected host Python and Node
available after installation; Python is never downloaded automatically.

## One entry command

For a built local release directory supplied by your operator:

```sh
bash /absolute/release/install.sh --artifact /absolute/release/ptw-0.5.1-linux-x86_64.tar.gz
```

Verify the bootstrap's SHA-256 against your trusted release announcement before
executing it. The bootstrap embeds the archive's expected SHA-256 and versioned
download URL. Its default online URL will work only after the manager publishes
the matching assets. Checksums establish integrity relative to that trusted digest;
downloading an adjacent checksum is not independent publisher authentication.

The following is an **unpublished template**, not a working online quickstart.
The publisher must substitute the reviewed digest and matching version:

```sh
PTW_BOOTSTRAP_SHA256=REPLACE_WITH_TRUSTED_RELEASE_DIGEST
PTW_DOWNLOAD_DIR=$(mktemp -d)
curl --fail --location --proto '=https' --proto-redir '=https' --max-time 60 \
  https://github.com/BrightlineAI/permission-to-work-not-to-escape/releases/download/harness-v0.5.1/install.sh \
  -o "$PTW_DOWNLOAD_DIR/install.sh" &&
printf '%s  %s\n' "$PTW_BOOTSTRAP_SHA256" "$PTW_DOWNLOAD_DIR/install.sh" | sha256sum --check - &&
bash "$PTW_DOWNLOAD_DIR/install.sh"
```

There is no `latest` or mutable branch URL. The manager must never replace bytes
under an existing release version. A previously recorded version with different
archive bytes is rejected, including after a failed install or uninstall.

Installation automatically runs real doctor probes before activation. A failing
doctor or tool health check leaves the previous release selected. Failed command
diagnostics name the command and exit status without copying dependency logs.
Run the candidate's absolute `venv/bin/ptw doctor` with its private `bin` on PATH
for private troubleshooting, or retry from a normal login session with an active
systemd user manager. No failure enables an unconfined execution fallback.

Fresh installation prints `PTW_INSTALL_STAGE` records to stderr with fixed stage
names, elapsed seconds and completion status. These distinguish tool downloads,
Python/Codex preparation, health probes and payload integrity checks without
printing command output, configuration or credentials. A failed or interrupted
stage reports `completed: false` and still fails installation. Retain stderr when
diagnosing slow setup. These partial stage timings do not replace the full
installer-to-protected-ready measurement or its 60-second acceptance bound.
After native tools pass checksum and version checks, Python and Codex prepare
concurrently in separate environments and private caches. Their stage durations
overlap and must not be summed. Both must finish successfully before health
checks, payload verification or activation. On failure or interruption, the
installer waits for the in-progress bounded preparation before returning, so
retry/cleanup cannot race a writer. A failure still preserves the current release.
Payload verification reports content/entry checks and membership enumeration
separately. Each recorded file is hashed once per verification; the membership
pass checks metadata without following links or rereading file contents. Added
entries, changed contents or link targets, special files and unreadable inventory
still prevent activation. These phases are nested inside `payload-verification`
on fresh installation; do not add them to its duration.

Health checks use a private temporary directory beside the release payload for
temporary files and tool caches, including the
[Node compile cache](https://nodejs.org/download/release/v22.13.1/docs/api/module.html#module-compile-cache)
when enabled by tooling. They remove it on normal success or failure;
an interrupted check can leave that directory for inspection. The immutable
payload still requires exact file-set and hash equality before and after health.
Python service imports and isolated identity probes use explicit `-B`: isolated
Python ignores environment bytecode settings. See the
[Python command-line reference](https://docs.python.org/3.12/using/cmdline.html).
This preserves the earlier bytecode fix and keeps later runtime cache writes
outside the receipt, without accepting extra installed files. Native final-source
installer lifecycle verification remains required; source tests alone do not
certify installation.

Each archive download attempt has a 30-second wall-clock deadline covering DNS,
redirects, headers and body reads, with at most two attempts. On Linux the installer
uses a main-thread real-time signal timer to interrupt blocked reads, including a
peer that continuously sends small amounts of data. The timer and previous signal
handler are restored on success or failure; embedding callers with an active timer
are rejected instead of having their timer replaced.

Commands are installed in `~/.local/bin`: `ptw`, `ptw-install`, and `ptw-codex`.
An unrelated command with one of those names causes a safe collision error.
Open a fresh login terminal and run `ptw doctor`. On systems that do not discover
the user bin directory, the installer prints the exact shell integration line
and absolute command paths. It never edits startup files or removes PATH entries.
Use the instructions for the shell your terminal actually launches; `SHELL` alone
does not establish that. Keep existing startup configuration and PATH entries:

- sh login shells: add the printed export line to `~/.profile`.
- Bash login shells: add it to the first readable file in this order:
  `~/.bash_profile`, `~/.bash_login`, `~/.profile`. Create `~/.profile` if none
  exists. Interactive non-login terminals read `~/.bashrc`; add the line there
  too unless that file already configures this PATH. A login profile may source
  `~/.bashrc`, but Bash does not do that automatically.
- zsh login shells: use `$ZDOTDIR/.zprofile`. Interactive terminals read
  `$ZDOTDIR/.zshrc`. Use HOME in place of ZDOTDIR when ZDOTDIR is unset, including
  when choosing the files to edit. zsh does not read `~/.profile`.
- fish: run the printed `fish_add_path` command once interactively. It persists
  through fish's universal variables. If your config defines a global
  `fish_user_paths`, put the command in that config after the definition instead.
  A repeated command can return status 1 when the path is already present;
  verify with `ptw --version` in a fresh terminal.

Then open the corresponding fresh terminal and run `ptw --version` and
`ptw-install status`. The printed absolute commands work immediately even before
shell integration. The installer does not edit these startup files on retry,
upgrade or uninstall either; remove any integration you added yourself if desired.
Use `--root /absolute/private/install --bin-dir /absolute/commands` for isolated
test installations. Do not place project files inside installation storage.

For model tasks, use `ptw-codex login` and `ptw-codex login status` with your own
account, then `ptw codex` in your project. Login is an external prerequisite,
separate from confinement readiness. The installer never initiates login, reads
authentication files, copies credentials, or calls a model. Doctor invokes only
Codex's login status interface; its output is reduced to a boolean. `ptw-codex`
exposes the pinned client for operator login, not a protected coding entry point.
The live model remains GPT-5.6 Sol with low effort.

## Retry, upgrade, rollback and removal

Repeat the same entry command after a failed download or interrupted installation.
An identical completed release is integrity checked and doctored again. A new
version builds at its final absolute path before selection, keeping the previous
good release for `ptw-install rollback`. Use the new release's verified bootstrap
to upgrade; `ptw-install install --artifact PATH --sha256 TRUSTED_SHA256` is also
available. `ptw-install status` reports selection and retained releases.
Retry and upgrade preserve existing launchers after checking their recorded
hashes, even when the bootstrap runs through a different Python environment.
Keep the original launcher interpreter available as well as each retained
release's host interpreter. Modified or unrelated launchers remain collisions.

Installed Python source is kept free of runtime bytecode writes. Launchers supply
the bytecode setting, and workers, monitors, MCP relays/brokers and isolated
acceptance probes use explicit `-B` interpreter options so they do not depend on
environment inheritance. Receipt checks still reject every unexpected file,
including bytecode, and run before and after health checks on retry and rollback.
Exact monitor units from the previous format remain removable after projects
stop; modified units are still refused.

Before switching or removing an installation used by a project monitor, stop its
projects using the existing operator controls and run `ptw monitor remove --state
/absolute/controller`. Quit running sessions too. The installer checks monitor
references and running executable/argument paths and refuses a transition while
they refer to installation storage. It never stops projects or edits services.
Stopped monitor units also block transitions, including paths containing quotes,
backslashes, dollar signs or percent signs.
This conservative check is not a defense against a hostile same-account process
racing the installer. The host and operator remain trusted.

`ptw-install uninstall` removes unchanged files listed in the ownership receipt,
including its own launchers. Project policies, state, history and unrelated files
are preserved. Modified files, unexpected files, and unknown remnants from a hard
kill are retained and reported for operator inspection. Empty installation
directories are removed where possible; `.lock` and `state.json` remain for
idempotent retry and version history. To repeat uninstall after the launcher has
been removed, use `bash /absolute/release/install.sh uninstall`. Normal failed
attempts record their owned files for later cleanup; hard-killed attempts with no
completed receipt are never recursively deleted. The transaction record is local
operator metadata, not tamper-proof evidence.

## Build and validate without publishing

From this checkout, on the isolated Linux VPS:

```sh
python3 harness/scripts/prepare_product_release.py --out /absolute/new-release
PYTHONPATH=harness python3 -m unittest discover -s harness/tests -p test_product_install.py -v
python3 harness/scripts/product_install_acceptance.py --out /absolute/new-install-evidence
```

The release wrapper emits `release.json` with the candidate tag, asset paths and
SHA-256 digests, plus [concise owner commands and limits](RELEASE.md). Its
`private-candidate-unvalidated` status requires fresh native acceptance; it is
not publication approval. The manager alone publishes and promotes. Only the
listed assets are public candidates; `build.json` and original test receipts
remain private. The wheel includes the three deterministic demos through
`ptw demo`, unchanged pinned contracts and maintained safety guides. The builder
rejects stale bundled document copies. No raw histories or measured historical
sample is relabeled as this candidate's evidence.

The builder refuses existing outputs, stages an explicit allowlist, builds one
wheel using hashed setuptools 82.0.1 in an isolated environment, and includes
licenses, source hashes, installer support and existing Python dependency hashes.
It resolves only the exact Codex 0.154.0 release and its exact platform aliases
over the official registry's TLS endpoint. Review the generated `package-lock.json`
and `build.json` before publication. Installations use that authenticated lock
with `npm ci --ignore-scripts`, strong integrity values and a required Linux
platform binary. No unlocked dependency resolution happens on user installation.
uv 0.12.15 and nono 0.77.0 retain the legacy installer's exact archive digests.
Build and installation require external downloads; private caches do not import
user npm settings or registry credentials. Python installation permits wheels only.

The setuptools pin satisfies the existing backend requirement. Its documented
Unicode source-distribution exclusion issue does not apply to this Linux wheel
build from an explicit ASCII allowlist; no source distribution or exclusion-based
file collection is published. Build dependencies are not installed for users.

The acceptance script records each phase, installed import paths and source
hashes with PYTHONPATH/PYTHONHOME unset, real doctor, fresh terminal commands,
local HTTP success/failures, retry, a clearly labeled fixture upgrade, rollback,
missing-login status using an empty configuration, and uninstall preservation.
It makes no model calls. It fails if native checks fail; unit-test doctor doubles
are not installed-user evidence. Every output directory is new and outside the
checkout. Do not publish private diagnostic output without review.

Shell validation additionally requires Bash, zsh and fish on the validation host;
ordinary installation only needs the user's chosen shell. Missing validation
shells fail explicitly. The PTYs use isolated fixture homes with normal startup
discovery, not alternate rcfile options. They execute the integration printed by
the built bootstrap and check command resolution and unchanged installed receipts.
Unit coverage also exercises Bash login-profile precedence, zsh with unset and
custom ZDOTDIR, fish persistence/retry, quoted paths, PATH preservation and the
Debian/Ubuntu default `/etc/skel/.profile` user-bin discovery behavior. The latter
test requires that distribution template; other OS profiles need the documented
integration fallback. No operator dotfiles are read or edited by these fixtures.

## Timing and evidence limits

The initial sandbox revision on 2026-09-16 passed 39 of 41 focused tests using the
manager-provided Python/dependencies, including real Python imports through
captured worker, monitor and MCP commands, unchanged receipts, and fixture PTYs.
The two real HTTP tests, including slow-drip cancellation, failed at socket
creation with sandbox `EPERM`; neither was skipped or replaced by a mock pass.
The blocked-read timer test passed, but does not replace real network validation.
Real release acceptance again stopped at the uv download because outbound DNS
was unavailable. The public-state fixture now explicitly establishes and checks
0755 permissions independently of umask, and its security assertion passes.
That sandbox also denied the systemd user bus and writes to the user service
directory, preventing full native regression there.

The subsequent manager run on 2026-09-16 passed all 41 installer tests and all
283 regression tests without skips. Its retained private evidence directory
`installer-1789595239851830516` records all 15 native acceptance phases passing:
automatic doctor, installed-source identity, fresh-terminal integration fallback,
download failures, retry, missing-login rejection, fixture upgrade, rollback and
conservative uninstall. Installation through doctor took 11.252 seconds with new
private dependency caches, preinstalled host prerequisites and existing operator
login. This is a measured installation interval, not complete first-project setup.

That successful run predates the launcher-interpreter and escaped-monitor-path
fixes. Their regression tests exercise two Python paths, interrupted launcher
publication, actual command execution, and stopped monitor units blocking
upgrade, rollback and uninstall without changing selection or installed files.
The follow-up sandbox run passed 42 of 44 installer tests, including all three
new regression tests; both HTTP tests again failed at socket creation with
`EPERM`. Full regression ran 286 tests with 30 failures and eight errors under
the same socket, user-bus and service-directory restrictions, without skips.
Fresh release acceptance stopped during build at the uv download with unavailable
DNS. Guard, documentation, evidence consistency and manifest checks passed.
The later manager run `installer-1789595900511237381` passed all 15 native phases
against the launcher-interpreter and escaped-monitor-path fixes, with all 44
installer tests and 286 regression tests passing without skips. Installation
through doctor measured 10.012 seconds under the recorded prerequisite/cache
profile. Its terminal phase used an explicit Bash rcfile, so it did not establish
correct login-profile guidance. This historical run predates the shell guidance
and normal-startup PTY changes described above; fresh final-source manager
acceptance is still required. No online release or complete first-project timing
target is established by these runs.

The shell-guidance revision passed 29 focused lifecycle/terminal tests locally,
including real Bash, sh, zsh 5.9 and fish 4.0.2 fixture PTYs. Fish's no-change
status is asserted explicitly along with persistence and duplicate prevention.
These use small executable installation fixtures, not native doctor evidence.
The initial system-Python attempt lacked MCP and validation shells; a subsequent
manager-Python run exposed and corrected the fish retry-status test assumption.
All attempts were retained outside the checkout. Native HTTP, systemd and release
download validation still needs the manager environment: the sandbox denies
socket creation and user-bus/service access, and outbound DNS is unavailable.

Measure from the first installer invocation through automatic doctor, including
downloads, failed attempts and retries. Declare OS prerequisites, network, Python,
Node, caches and existing login. Each installation has private empty dependency
caches; a second identical invocation verifies an existing installation and is a
warm retry, not a cold install. The complete first-setup absolute maximum is 60 seconds
through project review and protected readiness. Installation-only measurements
cannot establish that target. Human review, first useful action and browser/MFA
login must also be reported. New-account OAuth is not tested here.

The [onboarding measurement driver](ONBOARDING.md#measurement-and-verification)
keeps the full installer elapsed time inside a continuous first-setup clock and
verifies installed source identity before the real terminal journey. It needs
manager-side native execution; offline test fixtures are not installation evidence.

The legacy `bash harness/scripts/install-vps.sh [--no-codex] /absolute/new/path`
remains compatible for source workflows. It rejects existing directories and
requires its documented manual PATH/doctor steps. Prefer the release installer
for recoverable user installation; legacy installation is not substituted as
evidence for the new path.

## Design sources

- [Bash startup files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files): first-readable login-profile precedence and separate interactive startup.
- [zsh startup files](https://zsh.sourceforge.io/Doc/Release/Files.html): ZDOTDIR, HOME fallback and separate login/interactive files.
- [fish_add_path](https://fishshell.com/docs/current/cmds/fish_add_path.html): persistence, duplicate handling and global-variable behavior.
- [fish 4.0.2 function source](https://github.com/fish-shell/fish-shell/blob/4.0.2/share/functions/fish_add_path.fish): status 1 when no path needs adding.
- [Python tarfile extraction guidance](https://docs.python.org/3/library/tarfile.html#extraction-filters): filters alone do not provide all resource and path checks. The installer validates all members and writes only regular files.
- [uv command reference](https://docs.astral.sh/uv/reference/cli/): explicit interpreter selection, disabled interpreter downloads, hashes and wheel-only dependency installation.
- [uv HTTP authentication](https://docs.astral.sh/uv/concepts/authentication/http/): dependency subprocesses use an empty netrc and private credential-store path, with keyring lookup disabled.
- [npm ci](https://docs.npmjs.com/cli/v11/commands/npm-ci/): frozen lock installation and lifecycle-script suppression.
- [Pinned Codex launcher source](https://github.com/openai/codex/blob/rust-v0.154.0/codex-cli/bin/codex.js): platform package selection and `vendor/TARGET/bin/codex` layout.
- [Pinned Codex package builder](https://github.com/openai/codex/blob/rust-v0.154.0/codex-cli/scripts/build_npm_package.py): exact platform alias versions used to validate the generated npm lock.
- [Python virtual environments](https://docs.python.org/3/library/venv.html#how-venvs-work): environments embed absolute paths, so candidates are never moved after creation.
- [Python interpreter options](https://docs.python.org/3/using/cmdline.html#cmdoption-B): `-B` disables bytecode writes explicitly, while `-I` ignores Python environment settings.
- [Python signal timers](https://docs.python.org/3/library/signal.html#signal.setitimer): a real-time alarm interrupts blocked download operations; signal handlers run in the main thread.
- [Python executor shutdown](https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.Executor.shutdown): the context waits for its worker on exit; result retrieval propagates worker failures. Native tool downloads stay on the main thread.
- [Pinned build backend metadata](https://pypi.org/pypi/setuptools/82.0.1/json): wheel digest and declared backend compatibility.

These sources establish interfaces, not successful local acceptance. Stable
filesystem ownership and atomic selection logic need behavioral tests rather
than additional web research. This remains an experimental Linux harness, not
production assurance or complete mediation of arbitrary agents.
