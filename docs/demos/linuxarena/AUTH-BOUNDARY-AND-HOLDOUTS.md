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

The closed prerequisite rebuilds only the sudo execution frontend from the
verified upstream archive plus the complete ordered Ubuntu patch series. It rejects
unsafe archive members, unexpected patch targets, patch failures and fuzz. A small
source patch calls the new capability/filter support after native group, resource,
descriptor and chroot setup, immediately before `setresuid`; a second check follows
native UID and cwd handling. Both pipe and PTY command children use this common
function. The parent and terminal monitor do not run these checkpoints.

The fixture requires the exact root starting capability mask `0xa80425fb` and zero
securebits/inheritable/ambient state. Native closed pipe/PTY checks confirmed this pinned fixture state; it is
not proof of every sudo mode. While SETPCAP remains effective,
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
and no package is installed by this checkpoint. The host acquisition stage now
downloads a bounded set of development inputs before starting the offline build.

The pinned image's retained inventory lacks these development packages:

| Development package | Required matching runtime version |
|---|---|
| libaudit-dev | 1:3.0.7-1build1 |
| libpam0g-dev | 1.4.0-11ubuntu2.6 |
| libselinux1-dev | 3.3-1build2 |
| zlib1g-dev | 1:1.2.11.dfsg-2ubuntu9.2 |

The checkpoint obtains these four exact amd64 packages from the same fixed
`20250701T000000Z` Ubuntu snapshot as its sudo sources. Native checks authenticated
both indexes and all four archives, passed the header/link probes and completed
configure and the frontend build. Native pipe/PTY checks passed the capability
reduction, static-helper exec, syscall assertions and native session cleanup. The
explicit child-object rule preserves native compile/hardening flags and header
dependencies in the separate build directory. Native checks also passed the
same-namespace fork barrier and post-exec descriptor rejection described below.

The existing native checkpoint test performs acquisition automatically, without
model calls. It copies only the pinned image's public Ubuntu archive keyring,
uses host `gpgv` to authenticate jammy and jammy-updates InRelease metadata against
the pinned 2018 archive signer, then verifies index and package sizes/SHA256 hashes.
No ambient proxy or authentication configuration, redirect or retry is used.
`development-inputs/freeze.json` fixes the four artifacts before extraction.
Signatures, indexes, packages, failed/partial downloads and extraction diagnostics
remain in that private run. Missing tools, signatures, versions or downloads stop
before compilation and retain the failed attempt. A later run requires a fresh
directory; it does not silently reuse an incomplete download.
Member rejections record bounded package/archive identity, member name (plus its
full-name hash), type, mode and reason, without member contents.

Bounded `dpkg-deb` decompression executes no installation or maintainer scripts.
The stager rejects traversal, duplicate/conflicting paths, special files, unsafe
links and executable build/runtime payloads. It copies only regular headers. Package linker
links are inspected, never extracted: generated linker scripts refer to exact
installed native runtime libraries whose package versions and bytes are recorded.
Relative documentation aliases must stay within their respective `usr/share/doc`
or `usr/share/man` tree and are discarded without following them. Validated files
under the exact package's `usr/share/doc/PACKAGE/` directory, including executable
PAM examples, are discarded without extraction or execution. All path, link,
special-mode and conflict checks still apply. Executable headers, executable
payloads elsewhere and escaping documentation links remain rejected.
Static libraries, pkg-config files and transitive static-link dependencies are not
staged; the real header/link probes and unchanged configure must establish the
selected dynamic build's sufficiency. Additional required inputs remain explicit
failures, never fabricated headers or disabled features.

The checker records staged package provenance separately from real dpkg inventory;
it never claims the development packages are installed. Header hashes are checked
before any probe. `CPPFLAGS`/`LDFLAGS` select the new inputs; no runtime library,
RPATH, loader environment, sudoers/PAM policy or account configuration is replaced.
The header mount is read-only and belongs only to the build container. A physical
probe checks its absence in the subsequent runtime fixture. Shared installations
and retained images remain unchanged.

This method follows [Ubuntu archive verification](https://documentation.ubuntu.com/security/software-integrity/archive-verification/)
and the [timestamped snapshot interface](https://snapshot.ubuntu.com/).
The required [PAM publication](https://lists.ubuntu.com/archives/jammy-changes/2025-June/039168.html)
predates that snapshot. The archive signer's fingerprint is documented in
[Ubuntu's keyring record](https://lists.ubuntu.com/archives/foundations-bugs/2020-May/422926.html).
These sources support provenance, not native build readiness.

`BridgeNativePrerequisiteTests.test_native_sudo_child_checkpoint` builds and probes
in two sequential fresh offline containers under the existing private allocation.
It retains real pipe/PTY output, pre-exec and static-helper capability observations,
permitted TCP/Unix socket creation and denied UDP/io_uring calls. It requires native
cleanup, exit 125 and absence of the original requested effect. Resource admission
uses existing memory/disk minima. Archives, ordered patches, sources, generated
filter, input-checker source, configure arguments, compiler/package versions, outputs and failures remain
in the private directory printed as `LINUXARENA_SUDO_CHILD_EVIDENCE`.

The frontend now guards the two actual command forks: `exec_nopty.c` for pipes
and `exec_monitor.c` for PTYs. It retains sudo's native debug-fork routine and
signal handling. A close-on-exec pipe holds the child until the parent confirms
unchanged mount/PID/user namespace identity. EOF or observation failure refuses
child setup; parent failure kills and reaps only that unreleased child. Direct or
repeated entry into the credential checkpoint without this fork context fails.
Bounded numeric records bind preparation, parent acknowledgement, command child,
UID transition and closed exec to native session initialization/cleanup. This
same-namespace barrier is **not** controller admission, revocation or secure release.

After exec, the static endpoint enumerates actual descriptors and refuses any
beyond stdin/stdout/stderr. Both pipe and terminal invocations intentionally inherit
a synthetic `/tmp` directory descriptor into sudo to test native closure. No account
store is opened for this test. The offline tests also inject a high-numbered file
and directory descriptor, fork/observation failure and changed child placement.
Native pipe/PTY checks passed this same-namespace composition. Monitor loss after
this barrier is not a proven revocation result.

Offline compiled syscall-double tests cover both users, invalid starting state,
failed reductions/filter installation, repeated setup and changed final credentials
or capabilities. They are logic tests, not physical isolation evidence.
**All requests still terminate at the closed endpoint.** The standalone checkpoint
does not supply Landlock. The placement variant below now adds that prerequisite,
with native closed pipe/PTY validation passed. Frozen payload context, requested release, nested
switches and useful requested work remain unfinished. Neither variant satisfies TRAIN.

### Authenticated child namespace placement and Landlock

The separate `test_native_sudo_namespace_checkpoint` uses the existing bubblewrap
mount construction, copied installed tools and a fixed sleeping holder in a fresh
synthetic mount/PID domain. A read-only, root-owned file outside that domain binds
the holder's PID and namespace inodes. No request selects namespace handles.

**Measured placement:** native root/dev pipe and real-PTY branches passed after
descriptors were pinned after original-command approval and before native
group/session setup. The command child enters the prepared mount/PID domain;
the monitor retains its original namespaces and restores PID-for-children selection.
Native credentials, session cleanup, capability/filter reduction, stdio-only
closure and four independently observed synthetic tmp writes passed. The original
requested commands stayed unexecuted with exit 125. This is closed-fixture evidence,
not controller-bound release or TRAIN success. The older namespace fixture still
fails account validation because it invokes sudo after confinement.

**Pipe and real-PTY continuation measured:** the placed static endpoint continues
through the same pinned nono/Landlock invocation as the existing namespace launcher.
The argv generator is shared; no second policy implementation is introduced.
The same generated specification binds cwd to the already granted `/probe`.
After native target-user setup, the endpoint restores this cwd before nono and
checks it again after nono, before effects. Bounded stage records require both
observations in order in pipe and real-PTY cases. Missing/inaccessible cwd,
failed observation or an unexpected path stops the endpoint; it never grants `/`
or adds `--allow-cwd` to accommodate an inherited directory.
The closed endpoint creates a fresh mode-0700 state directory as the native target
UID under `/ptw-native-state`. The placement fixture creates that scratch mount
with sticky mode 1777 inside its disposable namespace; existing permissions,
host directories and resource grants are unchanged. The endpoint verifies directory
type, owner and mode, then supplies only fixed PATH/locale and the new HOME and
XDG_STATE_HOME through `execve`. Caller environment cannot select nono state or
loader settings. After nono, the endpoint requires EACCES when opening its state
directory before producing useful effects. Missing state, malformed environment
or a readable state directory fails closed. These state records are synthetic
fixture data, not account stores or controller authority.

The pinned nono [session implementation](https://github.com/nolabs-ai/nono/blob/v0.77.0/crates/nono-cli/src/session.rs)
and [state-path implementation](https://github.com/nolabs-ai/nono/blob/v0.77.0/crates/nono-cli/src/state_paths.rs)
require writable private session storage owned by the executing user. Explicit
fixture state passed native root/dev pipe checks, including state/canary denial
and independently observed permitted writes.

The shared namespace builder now uses pinned bubblewrap's
[`--dev` implementation](https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c),
which creates a fresh device tmpfs and devpts instance with a `pts/ptmx` link.
Its fixed devices are null, zero, full, random, urandom and tty, with standard
stdio/fd links; when stdout is a terminal, it also exposes that already inherited
terminal as console. No surrounding device directory or devpts tree is bound.
Capabilities, syscall restrictions and resource/network grants remain unchanged.
The fixed placement holder starts with redirected streams, so it has no console
binding. Before publishing readiness, it retains device types, modes, ownership,
filesystem device/inode identities and the multiplexer link in
`probe/keeper-devices.json`. Missing or malformed devices prevent child placement.
Trusted discovery independently checks the live holder's devpts identity and
rejects an instance shared with the surrounding container. Setup failure retains
private diagnostics; the existing owned-container cleanup removes its namespaces.
These checks do not allocate a PTY themselves. With isolated devices the native
dev terminal endpoint reaches the state/canary denials, useful write and exit 125.
Nono's terminal-reset bytes lack a final newline, so the following native cleanup
record must begin on a fresh line. The delegator now supplies that boundary;
the decoder retains every raw byte and still requires exactly one ordered cleanup
record with the expected status. Root/dev pipe and real-PTY continuation
passed native development checks.
Only the fixed static fixture can run after nono, never requested command text.
The generated header, copied static endpoint, loader, nono and policy source are
hash-bound. The endpoint checks native credentials/capabilities and descriptor
closure again after nono. A synthetic file present in the mount domain must be
readable before nono and return EACCES afterward; ENOENT or another error cannot
stand in for protection. Only then are the four useful tmp effects produced.
An independent observer checks their actual final PIDs, owners and contents,
unchanged canaries, and absence of original requested effects. Existing pipe/PTY,
socket and native cleanup assertions remain required.

Fresh public tool directories, synthetic control inputs and the closed endpoint
use target-readable/traversable creation modes in a bounded child process.
The manager's umask, enclosing private evidence directory and existing permissions
are unchanged. Private canaries, namespace bindings and receipts retain private
creation modes. Existing destinations and links are refused. Native checks established fixture
access, cwd restoration, private state and terminal continuation under dev credentials.

The fixture grants TCP port 32001, matching the existing synthetic namespace
policy, so the original allowed-TCP/denied-UDP syscall assertions remain meaningful.
It establishes no service-connectivity result; the separate physical collector
fixture remains mandatory. Input, cancellation and job control beyond the closed
endpoint, mutable release, inherited grant intersection, gate failure and controller
revocation of the placed command child are still unproved. The endpoint is not a
nested-sudo compatibility client and does not repair the old fixture by itself.

Offline tests cover strict placement metadata, descriptor ownership, acquisition
and fork failures, credential/filter drift, and generated nono argv. Compiled
syscall-double tests exercise cwd setup/verification, private state creation and
identity, exact exec environment, malformed state paths, missing/incorrect denial,
isolated device metadata and rejection before namespace binding,
loader failure, leaked
descriptors, invalid continuation arguments and failure before effects. Both static
variants are compiled without executing them. These tests cannot establish native
nono compatibility after target-user setup by themselves. The existing native
placement test now also requires the controller admission checkpoint below.

Private source/tool hashes, target binding, transcripts, effects and failed attempts
remain under `LINUXARENA_SUDO_PLACEMENT_EVIDENCE`. Diagnostics contain bounded stage,
errno and kernel identity fields, without account contents or environment values.
Repeated pinning fails closed; setup/fork/exit cleanup closes all namespace/root
handles, including the PTY parent's copies.

Pinned distribution source establishes sudo callback/fork order. Existing
[kernel Landlock documentation](https://www.kernel.org/doc/html/v6.6/userspace-api/landlock.html)
and [setns documentation](https://man7.org/linux/man-pages/man2/setns.2.html)
explain the mechanisms; compatibility of this composed path requires native
measurement. The current change reuses verified local APIs and adds no dependency;
a repeated literature review would not establish runtime readiness.

### Controller admission checkpoint

Native pipe/PTY development checks passed. The placement test compiles a bounded
controller connection into the existing closed frontend. After the command fork,
the child stops and waits on its private pipe. The trusted monitor consumes that
stop before sudo's job-control loop and contacts a socket outside the prepared
mount/PID domain. Only the monitor opens this socket, after the fork; no controller
descriptor or session token enters the child. SIGCONT alone cannot cross the pipe.

The host obtains the monitor from kernel `SO_PEERCRED`, checks its live start and
namespace identity, and resolves its one actual child at the monitor's PID-namespace
depth. Under the existing controller lock, admission verifies monitor/child frontend
hashes, ancestry, source and authority generation, prepared holder identity and the
child's distinct PID namespace. Ordinary launcher checks remain unchanged. A durable
launch intent precedes cgroup registration and resume; only then can the monitor
open the private barrier. Native credentials, mount entry and nono/Landlock still
precede the closed endpoint. Missing/invalid replies kill and reap the unreleased
child. Lost acknowledgements or receipt errors revoke the owned execution subtree.
Controller reconstruction cannot replay an attempted child admission.

A second continuation check passed native pipe and real-PTY development checks
after correcting the foreground ordering. After
native UID/group/cwd and request-environment checks, the child stops again. Its
monitor requests continuation through the same authenticated socket. The existing
lifecycle lock verifies the sealed original admission, current session/grants,
unchanged process/start identity, registered cgroup and prepared mount namespace.
A durable one-use continuation intent precedes pidfd-based resume; this operation
cannot move a process or repeat initial admission. Stop, replay, missing/changed
admission, storage failure or lost acknowledgement fail closed. Native `closefrom`
preserves only the private read pipe until that check; the child consumes a distinct
second token and closes it before exec. No account or controller descriptor enters
the endpoint. Early exits stay unreaped until owned-child cleanup, avoiding a
recycled PID target.

Initial admission still occurs inside the command-fork wrapper. The pipe parent
also completes continuation there. The PTY wrapper instead retains its private
write end and exact pending child identity until the native monitor has assigned
the foreground process group. It then consumes the second stop and checks
continuation before restoring the signal mask or entering native event dispatch.
Cleanup kills and reaps only that pending child; successful continuation clears
the pending identity so replay cannot address a released or recycled PID.

Offline tests cover real pipe/stop/continue ordering with transport doubles and a
child that requires parent foreground notification before its second stop,
failed native-request verification, continuation failures, descriptor closure,
forged/stale membership, journal tampering, storage failure and stop serialization.
Native root/dev pipe/PTY checks established this ordering and process visibility
after credential changes. Further changes must preserve both. A permission error reading the
child's kernel identity must remain a failure; the adapter does not relax process
isolation to make that observation succeed. This is still continuation to immutable
confinement code, not requested-command release or a complete revocation proof.

This is a closed fixture with fixed synthetic scope, **not** a nested request API
or authorization of mutable command bytes. Original-request retention is now
implemented as described below. The file-authority binding is described next;
controller binding of command release, representation of inherited kernel restrictions,
requested execution and routing the combined user-switch fixture remain unfinished. The original fixture still
fails account validation; none of its useful-work, file/socket or stopping
assertions has been replaced. Raw admissions, failures, cgroup stop
observations and source hashes stay in the fresh private placement receipt.

Offline tests cover forged/stale identities, changed ancestry/executable/namespace,
closed sessions, duplicate admission, persistence failure and lost acknowledgement.
A compiled test uses real forks, stop/continue and pipes with transport doubles:
premature SIGCONT, EOF, wrong/extra replies and syscall failures produce no endpoint
effect and leave no unreaped child. It does not establish native socket behavior.
The Linux manuals document [kernel peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html)
and [stopped-child observation](https://man7.org/linux/man-pages/man2/waitpid.2.html);
these support the mechanism, not a general mediation claim.

### Checkpoint file authority

The controller checkpoint compiles its file permissions from an approved synthetic
version-4 policy in the existing Store. A parent owns `work` and `other`; its child
owns only `work`. The generated nono header grants `/probe/work`, with cwd there,
and leaves `/probe/other` ungranted. The snapshot binds exact resource IDs,
container paths, original device/inode identities and the full active session
ancestry. It contains no bearer credential.

Initial admission and post-credential continuation recompute the intersection of
project, task, session and surviving parent file grants under the existing lock.
Changed/closed/missing parents, cycles, stale policy or resource identity, forged
snapshots and broader mappings stop admission. Writable trees require every
read/write/append/create/delete grant; append-only or partial tree authority is
refused rather than widened. The compiled header and source receipt must match
the frozen snapshot. Native target-user access checks remain in force.

The fixed endpoint requires both synthetic files readable before nono, then the
child's file readable and the parent-only file denied with EACCES afterward.
Root/dev pipe and real-PTY scope checks passed native development validation.
Existing capability, descriptor, private-state, useful-write and stopping assertions
remain required. These synthetic checks do not authorize requested-command bytes,
network services, nested user switching or a recreated sibling sandbox. TCP port
32001 remains the existing fixed fixture control, not a project-derived service grant.
Native account validation in the original combined route is still unresolved.

### Native-approved request retention

The closed delegator now retains independent copies of native-approved command
metadata and arguments before redirecting execution. It pins the original
immutable executable and cwd, checks any native `execfd` against that executable,
and rejects changed executable/cwd identity or altered native command metadata
at session completion. The final environment is copied **after** native
`init_session`, which may update it. Original native storage remains available
for audit and exactly-once cleanup, including a failed binding after PAM succeeds.
Repeated session callbacks fail before calling PAM again.

Each vector is limited to 256 entries and 131,072 bytes including terminators.
Empty argument values and embedded whitespace remain data. Duplicate or malformed
metadata/environment keys, missing command/argv/environment, relative executable
paths, unavailable cwd, mismatched descriptors, allocation failures and substituted
executables fail closed. This prerequisite requires a regular, root-owned,
read-only executable without a final-component symlink; mutable executables and
broader path resolution are not admitted by this implementation. Additional owned
descriptors are closed before returning from session setup, before native
`closefrom` could recycle them. The unchanged closed endpoint still requires
stdio-only descriptors.

The pipe/PTY fixture compares numeric executable/cwd identities with independent
image observations and checks retention/session/cleanup ordering. Request and
environment contents are not logged. Compiled offline tests cover byte retention,
final environment replacement, bounds, allocation and binding failures. Native
retention/session checks passed. These copies are private
trusted-plugin state, not a serialized request, a controller grant, final-release
pinning or a useful-work result. The endpoint still returns 125 without executing
the requested command; the original namespace-first account failure remains.

The derived frontend now resolves a versioned callback from the **already loaded**
fixed policy object (`RTLD_NOLOAD`); missing binding fails before the command fork.
After the monitor's admission barrier, the actual command child claims the
snapshot once, before entering the target mount/root. It rechecks original
executable/cwd identity and approved metadata/argv. After native credential setup,
it verifies the final environment byte-for-byte, target UID/effective UID and
claiming PID/namespace. Changed files, environment, process identity, replay or
missing session fail closed; no callback returns request contents over IPC.

The fixture requires numeric claim/verification records bound to the observed
child between admission and closed exec, for both pipe and real PTY paths.
Offline tests cover substitutions, replay, a forked process attempting to reuse a
claim, failed admission and descriptor closure. Native pipe/PTY checks passed.
This still returns 125 through the closed endpoint: it does not dispatch the
requested command, represent an issuing-task grant, or fix the combined
nested-switch route. Those remain required before mutable execution or TRAIN.

This uses the retained distribution source and the pinned
[sudo 1.9.9 plugin API](https://www.sudo.ws/docs/man/1.9.9/sudo_plugin.man/),
particularly `check_policy` and `init_session`. No new dependency is introduced.

### Requested execution prerequisite

The separate `test_native_sudo_requested_release` fixture builds the retained
frontend with requested release enabled; closed builds still have no release
option. Native root/dev pipe and real-PTY requested-work checks passed. They
establish synthetic useful work, not a benchmark task, honest agent trajectory
or TRAIN success.

The actual command child populates a bounded argv handoff only after final
credential/environment verification and the second controller acknowledgement.
It carries the native-approved executable, argv, cwd identity and final session
environment. It carries no authentication, namespace, controller or old-root
descriptor. The retained `sudo.c` assigns the plugin's argv pointer directly;
the normal native exec/error and monitor/session-cleanup paths remain in use.

The first static stage checks the immutable executable and cwd, then invokes the
existing pinned nono command with a fixed safe environment. Original environment
entries remain inert argv data until the second static stage confirms confinement,
checks descriptors/capabilities and reopens the same immutable ELF inode. It uses
`fexecve` with CLOEXEC and the original argv/environment; it does not execute a
shell to decode the handoff. Native-approved environment variables cannot load
code into the earlier static stages or nono. Oversized/invalid frames, replacement
identities, repeated child release and failed exec stop explicitly.

This bounded path accepts only immutable ELF executable files and the compiled
grant's cwd. Scripts require an explicit native-approved interpreter command.
NOEXEC, preserved descriptors, SELinux execution transitions and background mode
are rejected. The pinned `src/exec_common.c` applies NOEXEC through loader
injection after the session snapshot; silently dropping it across static stages
would lose native enforcement. Existing unsupported sudo modes remain rejected.

The native fixture requests root/dev bash work in both pipe and real-PTY branches,
checks literal arguments, environment, cwd, groups, file denials, useful output,
exit status and native cleanup, and independently inspects the resulting files.
It retains the closed checkpoint's physical capability/socket/descriptor checks.
The same four requests now additionally require literal input and EOF; PTY
cases require foreground ownership, terminal Ctrl-C delivery, native stop
propagation and continuation before useful output. The trusted wrapper observes
the stop of its own sudo child and resumes only that child. Inputs and raw
transcripts are retained, with bounded waits and failure cleanup. Extended
root/dev pipe checks pass; the root PTY reaches input, Ctrl-C and EOF but stalls
before stop/continue completes. Retained authenticated snapshots establish that
nono's supervised command child sleeps while its descendant payload stops in a
separate process group. Sudo therefore has no direct-child stop to propagate.

The requested-release build now uses pinned nono 0.77.0 `wrap` at the authenticated
continuation, preserving the command-child PID through direct exec. Closed
checkpoints and ordinary launches keep `run`. Both modes use the same file/port
grant construction. Wrap rejects the run-only `--sandbox-policy`, `--no-rollback`
and `--no-audit` flags; its automatic backend adds static seccomp alongside
Landlock. External resource ceilings, controller admission/revocation and the
physical capability/socket/descriptor checks remain required. A backend rejection
fails the attempt with its original transcript; no fallback or extra grant is
inferred. This composition still needs native compatibility proof.

Admission requires the trusted invocation's boolean release mode to match the
build receipt and regenerates the exact header with that mode and frozen file
scope. Missing, malformed or mismatched modes and altered scope/header fail before
controller registration or listener creation. Receipt metadata cannot authorize
release. Offline constructor tests cover both modes and these rejections. The
latest native attempt stopped at the former mode-binding mismatch before payload
execution; direct-exec terminal compatibility remains unmeasured.

The release oracle now requires the final confined helper to retain the native
command-child identity and, for PTYs, foreground ownership. Input, Ctrl-C, EOF,
stop/continue, exit 37, useful files and native cleanup remain mandatory. Bounded
numeric process snapshots and non-consuming wait diagnostics remain hash-linked,
including on failure; they expose no arguments, environment or account contents.
The wrapper retains its 15-second deadline inside the 20-second host budget.
No new signal relay or timeout adjustment is used.

Pinned primary sources describe [direct wrap execution](https://raw.githubusercontent.com/nolabs-ai/nono/v0.77.0/crates/nono-cli/src/command_runtime.rs)
and [launch configuration](https://raw.githubusercontent.com/nolabs-ai/nono/v0.77.0/crates/nono-cli/src/launch_runtime.rs).
They support the selected mechanism, not a measured terminal fix.
Nonroot command-specific release
denial, authenticated nested callers and the combined fixture still require
integration and native proof. The synthetic controller actor is not production caller authority. Source
review and offline callback/parser tests do not establish these native properties.

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
