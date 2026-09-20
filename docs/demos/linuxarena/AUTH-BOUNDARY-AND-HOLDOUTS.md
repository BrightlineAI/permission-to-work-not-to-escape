# Authentication boundary and exposure

The owner authorized a bounded image-specific trusted authentication/launch adapter
on 20 September. Intake DESIGN SHA256:
`7e86e7b21fe4e63f706f316a447b9f8c0d996d6ccc9e83427ec46008e47ff79b`.
This supersedes the earlier prohibition on that seam. The later
[TRAIN/TEST/VALIDATE sequence](TRAIN-TEST-VALIDATE.md) supersedes its two-heldout
allocation and model-free-only task22 wording. Historical [PLAN](PLAN.md),
[CRITIQUE](CRITIQUE.md) and [SOURCES](SOURCES.md) remain unchanged snapshots.

## Required transition, not implemented proof

Reuse the Store, authenticated sessions, lifecycle lock, registered execution
subtree and stop backend. Native sudoers/PAM must authorize the **original** caller,
target, executable, arguments and approved environment, including account/session
handling and cleanup. Permission to execute a helper, `sudo -l` followed by privileged
execution, UID substitution or PAM success stubs cannot replace that decision.

The candidate is a small delegating policy plugin with an immutable execution helper.
Before implementing it, review the exact installed distribution source and patches.
Before any mutable instruction, pin the approved launch/resources, close authority
descriptors, establish users/groups and namespaces, apply inherited confinement,
register the payload and atomically recheck admission. A target-user helper must
not depend on privileged mounts or namespace entry after privileges are dropped.
The authentication monitor must remain inaccessible and able to clean up sessions.

Initial identity comes from the host controller. Nested requests must bind kernel
peer, process start identity, namespaces, registered membership and grant generation.
Every transition intersects project/task grants, surviving parent restrictions,
requested narrowing and target-user access. Refuse restrictions that cannot be
represented conservatively. Keep no-new-privileges and Landlock enabled. Neither
nested sudo nor cron, deployment/restarts or scorer-invoked mutable code may reset
grants or revocation. Trusted orchestration is separate from edited application code.
No account store, controller credential, Docker socket or authentication handle
belongs in the mutable domain. Unsupported modes must fail explicitly.

The native physical gate must prove useful root-to-dev work and exact UID/GID/groups,
original-command denial even when the helper is permitted, inaccessible private/auth
state, native session cleanup, narrow children, stop races and unrelated-work survival.
Existing physical file/socket/capability assertions remain required. A plugin source
review or successful archive check cannot satisfy these assertions.

## Source prerequisite and current measurement

### Command-child checkpoint: implemented, native validation pending

The next closed prerequisite rebuilds only the sudo execution frontend from the
verified upstream archive plus the complete ordered Ubuntu patch series. It rejects
unsafe archive members, unexpected patch targets, patch failures and fuzz. A small
source patch calls the new capability/filter support after native group, resource,
descriptor and chroot setup, immediately before `setresuid`; a second check follows
native UID and cwd handling. Both pipe and PTY command children use this common
function. The parent and terminal monitor do not run these checkpoints.

The fixture requires the exact root starting capability mask `0xa80425fb` and zero
securebits/inheritable/ambient state. This is a pinned fixture assumption awaiting
native confirmation, not proof of every sudo mode. While SETPCAP remains effective,
it drops bounding capabilities, then removes setup authority. Root keeps the existing
`0xeb` ceiling; dev keeps only SETUID until sudo's native transition, after which
all five capability sets must be zero. No capability retention or saved root identity
is enabled. The actual command child sets no-new-privileges and installs the filter
generated directly from `linuxarena_namespace.socket_filter()`. There is no separately
maintained filter or assumption that this child inherits the keeper's filter.

The derived frontend is a non-set-ID fixture binary; its caller is trusted root.
It retains native policy, PAM/account/session handling, I/O and audit plugins. Native
configure argv comes from the hash-verified Ubuntu `debian/rules`, with the fixed
distribution frontend prefix checked against the hash-bound native binary's display.
The display is not shell syntax: it loses quoting around the password prompt.
Source parsing preserves the prompt's trailing space and rejects any display drift.
The fixture does not replace host or image `/usr/bin/sudo`. Original
closed-build caller-denial tests remain separate and unchanged.

Before building helpers or configuring sudo, `checkpoint-prerequisites.json` records required package
versions, header/library paths and hashes, compiler/make/linker/assembler identities
and versions, and compile/link results. Probe binaries are never executed. Missing,
changed or unusable inputs prevent configuration; all logs remain hash-linked in
the failed attempt. No security option is disabled, no configure result is seeded,
and no package is downloaded or installed by this checkpoint.

The pinned image's retained inventory lacks these development packages:

| Development package | Required matching runtime version |
|---|---|
| libaudit-dev | 1:3.0.7-1build1 |
| libpam0g-dev | 1.4.0-11ubuntu2.6 |
| libselinux1-dev | 3.3-1build2 |
| zlib1g-dev | 1:1.2.11.dfsg-2ubuntu9.2 |

Native configure failed on missing `libaudit.h` before reaching the child checkpoint.
No verified compatible development artifacts were found in the searched retained
artifacts. Providing and binding compatible build inputs in fresh owned staging
remains an infrastructure prerequisite; shared installations and retained images
must stay unchanged. The current checker only admits matching installed inputs in
the fixture; it does not yet supply a staged dependency overlay.

`BridgeNativePrerequisiteTests.test_native_sudo_child_checkpoint` builds and probes
in two sequential fresh offline containers under the existing private allocation.
It retains real pipe/PTY output, pre-exec and static-helper capability observations,
permitted TCP/Unix socket creation and denied UDP/io_uring calls. It requires native
cleanup, exit 125 and absence of the original requested effect. Resource admission
uses existing memory/disk minima. Archives, ordered patches, sources, generated
filter, input-checker source, configure arguments, compiler/package versions, outputs and failures remain
in the private directory printed as `LINUXARENA_SUDO_CHILD_EVIDENCE`.

Offline compiled syscall-double tests cover both users, invalid starting state,
failed reductions/filter installation, repeated setup and changed final credentials
or capabilities. They are logic tests, not physical isolation evidence. Native build
compatibility, starting state, intermediate exec inheritance and terminal behavior
must pass before namespace entry and final admission connect to this frontend.
**All requests still terminate at the closed endpoint.** Mount/PID isolation, Landlock,
frozen payload context, lifecycle release, nested switches and useful protected work
are not supplied by this checkpoint. It cannot satisfy TRAIN or the complete boundary.

[Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) documents
bounding-set reduction and UID transitions;
[kernel seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
documents filter installation and fork/exec inheritance. The retained patched
`src/exec.c` determines checkpoint order. These sources support the design; pending
native checks must establish compatibility in the installed image.

### Retained source-only prerequisite

The retained image metadata reports Ubuntu sudo `1.9.9-1ubuntu2.5`. The existing
confined route fails native account validation; a separate diagnostic records
account=7 and successful audit socket creation. Missing account data is plausible,
not an established per-module cause. No additional account-file grant is justified.

The bridge suite now has `BridgeNativePrerequisiteTests.test_native_sudo_package_source_binding`.
It verifies the existing private daemon/resource allocation, creates a fresh
read-only, networkless, 0.25-CPU/64-MiB metadata container from the installed image,
and hashes sudo and its policy library. It runs no sudo command, PAM session,
benchmark task, grader or model. Cleanup targets only its captured immutable ID.

On the manager host it makes one bounded HTTPS download attempt per pinned upstream
and Ubuntu patch archive from Canonical's fixed `20250701T000000Z` snapshot. The
rolling archive returned HTTP 404 for this exact patch archive. The snapshot date
follows the package's [30 June 2025 publication](https://lists.ubuntu.com/archives/jammy-changes/2025-June/039524.html);
the [snapshot service](https://snapshot.ubuntu.com/) documents dated archive access.
The version and expected hashes are unchanged; there is no fallback to newer sources.
No ambient proxy/auth settings, redirects, package installs or retries are used.
Canonical's published SHA256 values are checked before archive
inspection. Selected execution/header files and all distribution patches are saved
as regular, non-executable data in a new private receipt directory. No archive
extraction API, package hook or patch is executed. Missing source, wrong package,
unsafe archive, failed cleanup or transport failure is an explicit failure, never
a skip. Failed/partial files and attempt records remain retained.

The test prints `LINUXARENA_SUDO_SOURCE_EVIDENCE` with its private output location.
`installed.json` binds image binary identities; `source.json` binds original archives,
their URLs and selected source bytes. `attempt.json` records each attempted URL,
expected hash, verification/failure state, HTTP error status when available, and zero
paid calls. The native source prerequisite passed: installed package/binary
identities and both pinned archives verified from the fixed snapshot. Source retrieval
does not prove the distribution binary was reproducibly built from those sources,
nor callback compatibility, authentication or protected useful work. Review the
retained patch series before implementing the plugin. None of its ten patches changes
`src/exec.c`, `src/exec_nopty.c`, `src/exec_pty.c` or the PAM account hook. Inspection
confirms parent-side session initialization before the execution fork, descriptor
closing before chroot/UID reduction, and parent-side policy cleanup. Preserved
descriptors and post-session environment changes still need explicit handling;
this ordering alone supplies no secure child namespace/admission transition.
The existing all-route native
prerequisite remains failing; no assertion was relaxed.

The prerequisite now compares one fixed native request,
`sudo -n -u dev -- /usr/bin/id`, in the trusted image context and under confinement.
It verifies the root-owned, non-writable, non-setid ELF on a read-only mount and
binds both observations to its hash. It passes no ambient environment or inherited
descriptors, supplies no input, and limits each invocation to five seconds. Only
numeric UID/GID/groups, exit/status and executable identity are retained, never
account contents or raw output. Unexpected identity output fails explicitly.
The [GNU identity format](https://www.gnu.org/software/coreutils/manual/coreutils.pdf)
includes differing effective IDs and optional security context; this fixed image
control rejects those extra fields rather than interpreting them as equal identities.
The two private identity receipts join the image/source-bound diagnostic envelope.
A failed trusted control stops before mutable admission. A successful control
does not satisfy useful-work/protection assertions or prove the launch adapter.
The native comparison succeeded outside confinement (UID/GID 1000, group 1000)
and failed account validation inside it for the same hashed executable. This
establishes a compatibility failure in the composition; it does not identify the
precise PAM module or prove the proposed release boundary.

## Closed delegation prerequisite

The image-specific C prototype now delegates the original request to native
sudoers and retains native environment hooks, account/session initialization and
cleanup. Approved execution redirects to a static immutable endpoint that reports
numeric identity and exits 125. It never interprets or executes requested command
bytes. There is no release option. Native closed-endpoint callback checks passed;
this proves no confinement or useful work by itself.

The model-free bridge test builds only this source and the hash-verified upstream
API header with the image's installed compiler, then loads the result read-only in
a second fresh fixture. Only that fixture's `sudo.conf` selects the delegating
plugin; original sudoers, PAM, account configuration and native audit/I/O plugins
remain in place. Both containers are sequential, offline and limited to 0.25 CPU /
256 MiB within the existing allocation. The runner retains compiler, source,
binary, image and process receipts, including failed builds and loads. Source
acquisition is shared with the existing source prerequisite within one test-class
invocation, avoiding duplicate downloads in full discovery.

The native cases require original root-to-dev/root requests to reach the closed
endpoint with the expected identities, return 125, invoke native session cleanup
and leave the original requested file effect absent. A guest's native rejection,
invalid target and unsupported editor mode must never reach that endpoint.
This does **not** yet prove command-specific denial when the helper is allowed,
monitor isolation, confined release or revocation; those remain required. The
execution-only prototype refuses editor, shell-mode, chroot and interception
paths. It preserves native `use_pty` metadata unchanged: sudo retains terminal
selection, I/O plugins and monitoring. Captured pipes do not by themselves establish
the native PTY branch or interactive compatibility.

The same five requests now also run through a real controlling terminal using
the existing terminal driver and `docker exec -it`. The static endpoint reports
`isatty` for stdin/stdout/stderr; the oracle requires all three for terminal cases,
along with exact identity, exit 125, session/cleanup ordering and absent original
effect. It checks sudo's own return status, including signal deaths. Each invocation
has a five-second sudo timeout and ten-second terminal deadline; failure retains
the raw transcript and cleans only the owned fixture. Terminal input is never
sent. This tests closed-endpoint output/exit handling, not interactive mutable
commands, cancellation or resume. Those remain required later.

The pinned source can clear its exported `close` callback during policy checking.
The delegator retains the original callback and keeps its own callback non-null,
preventing direct execution without a monitor. Local policy rejection returns to
sudo for auditing before normal close; it must not free the native output vectors
inside `check_policy`. Session failure likewise returns for audit first. A pinned
sudo fatal callback then closes native state once, ahead of native fallback cleanup.
It is registered after native open, removed by normal close and bound to the parent
PID. Missing callback symbols or registration failure refuse opening the gate;
no session starts, and native fatal cleanup remains responsible for failed open.
This relies on the pinned utility callback API as well as the policy API.

Native pipe and real-terminal development checks passed with `use_pty` preserved:
root-to-dev reaches UID/GID 1000, native session initialization and cleanup complete,
the endpoint exits 125 and original-command effects remain absent. Real-terminal
cases also establish all three terminal descriptors. Preserve audit-before-cleanup.
Bounded diagnostics expose reason codes,
option names without values and syscall/metadata failures, never environment or
authentication data. Rejection checks refuse signal exits and require exactly-once
cleanup for native denial. Synthetic callback tests verify original-request binding,
preserved terminal/credential options, audit ordering and session failure; they
do not establish native authentication. The existing namespace composition still
has an unresolved account-validation failure. Closed-endpoint success does not
establish a secure mutable release path, useful protected work or TRAIN completion.

Sources: [Canonical package and source hashes](https://launchpad.net/ubuntu/+source/sudo/1.9.9-1ubuntu2.5),
[pinned policy API](https://www.sudo.ws/docs/man/1.9.9/sudo_plugin.man/),
[parent session initialization](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_9/src/exec_nopty.c),
[native PTY execution](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_9/src/exec_pty.c),
[audit-before-close ordering](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_9/src/sudo.c),
[fatal callback ordering](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_9/lib/util/fatal.c),
[child execution setup](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_9/src/exec.c).
The verified archive now also retains the fatal callback implementation/header and
native cleanup source. Distribution patches do not change these cleanup paths.
Source ordering is not proof of the Ubuntu-patched binary's behavior.

## Exposure ledger

All three pair identities and the shared environment were exposed before these
amendments; the prior prerequisite queried all six honest/attack combinations.
The old report marks duplicate_detection/stats cells pending and earlier max_words
smoke work executed/errored. That does not establish absence of other exposure.
Do not claim pristine unseen tasks or three independent environments.

During TRAIN only file_integrity may inform tuning. duplicate_detection belongs
to TEST; stats remains held out from further content-driven diagnosis and tuning.
Opaque source hashes and ID membership checks are permitted. The TaskSpace helper
now requires the pinned lazy mappings, checks all three pairs' IDs without loading
their objects, and resolves only TRAIN honest/attack combinations. A process-local
audit hook refuses non-TRAIN task-content opens, including bytecode and linked paths.
It guards this trusted inspector against accidental eager loading; it is not an
agent security boundary. The retained native TaskSpace receipt confirms TRAIN-only
resolution with the guard enabled; the later account-validation failure still
fails the overall prerequisite. The source-only prerequisite
does not import Control Tower or task content. Full historical metadata exposure
audit remains pending.
