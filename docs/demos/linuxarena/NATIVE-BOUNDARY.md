# Native execution boundary

The controller lifecycle has passed native development checks. The new
`linuxarena_namespace` launcher is a confinement seam with unresolved native user switching,
not a completed LinuxArena adapter. Use the prerequisite command in the
[bridge guide](README.md); it makes no model calls.

The trusted launcher accepts a fixed resource/command specification, pins each
resource component without following links, then stops itself. The external
controller must durably admit that exact stopped process before it resumes.
Bubblewrap binds those descriptors into a fresh mount/PID/IPC/cgroup namespace;
writable files remain live in the original container. Missing roots, overlapping
grants and attempts to mount control/runtime paths fail. No missing exact file
is accommodated by granting its parent directory.

The container's Unix-user mapping is retained for native root-to-user execution.
Mount administration is available only to the trusted launcher in its newly
created rootless fixture. After bubblewrap, a fixed trusted launcher step reduces
all capability sets to SETUID, SETGID, DAC_OVERRIDE, CHOWN, FOWNER and KILL before
nono or mutable execution. These support ordinary native user/file/process
operations. Trusted control and observation remain
outside the resulting process and mount namespaces. Installed nono supplies
inherited filesystem and TCP-port restrictions, combined with the fixed socket
filter described below. These are trusted integration inputs,
not model tools; production binding to the approved task policy is unfinished.

The pinned [bubblewrap implementation](https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c)
only trims the bounding set on its user-namespace paths; this integration keeps
the existing user mapping. The fixed reduction step therefore retains SETPCAP
from the existing container solely during trusted setup, drops every bounding
bit outside the six-capability ceiling, then removes SETPCAP from active,
inheritable and ambient sets with `capset`. No container capability is added.
The [kernel capability implementation](https://github.com/torvalds/linux/blob/v6.8/security/commoncap.c)
defines these operations. Missing privileges, syscall errors, unexpected setup
or unverifiable final masks stop execution. Before/after masks go to private
stderr; root, child and sudo-dev probes independently check the same ceiling.
Native root/child receipts retain all capability sets at `0xeb` and completed
socket probes. Sudo still fails account validation before useful dev-user work;
sudo-dev inheritance, later permitted network effects and final namespace
stopping remain unproven.

Nono's private home/state directory is separate from writable `/tmp`; no resource
grant may overlap it. A trusted outer waiter retains the payload exit status so
initialization failures identify the private stderr receipt instead of waiting
for a physical-effect timeout. Native compatibility remains unresolved.

The prerequisite retains bounded private sudo loader diagnostics before asserting
user switching: image paths, symlinks, owner/mode, hashes, ELF interpreter,
dependencies and search paths; then the same path-open observations under full
confinement, native loader `--list`/`LD_DEBUG=libs` output and the actual sudo
exit/stdout/stderr. Missing files, access errors, diagnostic timeouts and output
truncation are explicit. `namespace-diagnostics.json` binds present and missing
receipts to the image, container, specification and staged tool hashes even on
failure. It reads selected runtime metadata, not ambient environment or credentials.
The image loader inventory is carried separately from the controller's resource
inventory; the saved specification records exactly which paths were inspected.
The loader listing never enters the application; explicit loader invocation can
differ from setuid execution and is not evidence of successful user switching.
Only the unchanged useful-dev-work and denied-private-read assertions qualify.
No runtime grant or library substitution is inferred from these diagnostics.

The fixed sudo reads are its image library/plugin under `/usr/libexec/sudo`,
`/etc/sudoers`, `/etc/sudoers.d` and `/etc/pam.d`, all mounted read-only. These
address demonstrated native denials; resource arguments cannot override them.
There is no broad `/etc` grant or extra capability. The synthetic namespace
creates `/etc` with mode `0755` and its private `/tmp` with mode `1777` for
ordinary user traversal and temporary files. No host directory mode changes.
PAM/sudoers write attempts and forged includes remain required denial probes.

The inventory follows trusted PAM includes within `/etc/pam.d` (at most 32 files,
64 KiB per file and 1,024 logical lines), recording metadata, hashes, include
identities and selected modules without emitting options or configuration text.
It retains malformed/missing/denied entries and limits. Selected module
`DT_NEEDED` candidates are inspected recursively in the pinned Debian x86_64
library directories (32 module entries per configuration, 256 library paths).
Links outside `/usr/lib` and `/lib` are rejected before opening. This is bounded
candidate discovery, not dynamic-loader emulation or account-hook execution.
Package identities (including `libaudit1`) and hostname/NSS/resolver metadata are recorded separately;
there are no DNS probes. Full metadata stays in private receipts; only the
complete path list and interpreter enter the bounded launch argument.

The retained native check found all seven PAM configuration files, eight present
sudo runtime files and 46 present PAM module/library candidates readable under
confinement with matching image hashes. Sudo nevertheless failed during account
management, before useful dev-user work. These observations do not justify
another library grant. Hostname/audit warnings are separate observations.

For either `PAM account management error` or `account validation failure, is your
account locked?`, the fixture runs one separate five-second PAM diagnostic inside
the unchanged confinement. Unrelated loader/configuration/password errors do not
trigger it. The latter message corresponds to `PAM_AUTH_ERR` in
[upstream sudo](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_9/plugins/sudoers/auth/pam.c);
it does not establish that the account is locked. The hook uses the public
`pam_acct_mgmt` API with the image's `sudo` account stack, a `root` handle and
`PAM_SILENT`, matching sudo's account-call flag. It refuses every conversation
without reading messages or supplying responses, and refuses to load PAM unless
the confined `/etc/shadow` path is absent. No account store is copied, synthesized,
mounted or granted. The configured modules remain subject to the existing ceiling.

The private `pam-account-hook.json` retains numeric start/account/end returns,
account-call errno, conversation count, missing prerequisites, timeout, crash and
bounded output. Immediately flushed stage markers preserve completed returns and
errno before cleanup can replace them. A last marker locates progress, not the
cause of a stall. The evidence envelope binds the receipt to source and image.
This is not full sudo equivalence: it does not reproduce all sudo PAM items,
authentication or session setup. Only the original useful-dev-work and
private-read-denial assertions qualify; diagnostic success cannot satisfy them.

The current native receipt records start=0, account=7 (`PAM_AUTH_ERR`) with
errno=0, end=0, no conversations and no timeout. Its `audit_open` returns a
descriptor with errno=0, which is closed successfully. The earlier audit-open
failure is resolved in this probe; native account validation is not. The image's
account configuration includes `pam_unix`, `pam_deny` and `pam_permit`, and its
configuration/library hashes match the confined observations.

The namespace intentionally omits `/etc/shadow`. Upstream PAM's
[account lookup](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.4.0/modules/pam_unix/passverify.c)
requires shadow information for shadow-backed Unix accounts;
[account verification](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.4.0/modules/pam_unix/support.c)
propagates unavailable information unless configured otherwise.
Missing account data is therefore a source-supported explanation, not an observed
per-module trace of the Ubuntu-patched stack. The receipt establishes neither a
locked account nor success with the original account store. No credential store
was inspected to investigate this failure.

This blocks adapter expansion under the reviewed composition. Granting the store
to the root payload would also expose it to mutable code under the same inherited
filesystem policy. Synthetic account data, relaxed PAM checks or direct UID
substitution would change the required native semantics. None is implemented.
A reviewed integration must preserve native account validation while keeping
credential access outside mutable-code authority; no such integration is proven
by the installed composition. Repeating the unchanged prerequisite cannot resolve
that design requirement. Required user-switch and physical assertions remain intact.

Before the socket correction, the retained public-API diagnostic completed: start=0, account=4 with errno=1,
end=0, no conversations or timeout. The same child measured `audit_open=-1`,
errno=1 (EPERM). The image identifies `libaudit1` as `1:3.0.7-1build1`, PAM as
`1.4.0-11ubuntu2.6` and sudo as `1.9.9-1ubuntu2.5`. This does not establish an
account-stack failure or success:
[PAM auditing](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.4.0/libpam/pam_audit.c)
can replace that result when opening its audit connection fails.
After preserving the account result and attempting PAM cleanup, the same guarded
child observes one image `libaudit.so.1` `audit_open` call, recording its return
and errno immediately and closing any returned descriptor, including zero.
Close errors and missing libraries/symbols remain explicit. The observation uses
the existing five-second deadline and flushed markers, sends no audit requests,
reads no audit records and changes no audit configuration or capabilities.
[Upstream audit_open](https://raw.githubusercontent.com/linux-audit/audit-userspace/v3.0.7/lib/netlink.c)
opens a NETLINK_AUDIT socket; the image library hash is already in the runtime
inventory. Earlier direct-module-call diagnostics were invalid because they
bypassed public PAM dispatch; their timeouts do not establish the cause.

The installed binary reports nono 0.77.0. Its published
[TCP-only static filter](https://github.com/nolabs-ai/nono/blob/v0.77.0/crates/nono/src/sandbox/linux.rs)
rejects netlink with EPERM in the selected `auto` policy. This explains the
observed audit-open denial, although the receipt is not a syscall trace of the
installed binary. PAM converts that audit-open failure to a system error;
[sudo also treats it as an audit failure](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_9/plugins/sudoers/linux_audit.c).
The compatibility correction composes installed tools: bubblewrap installs a
fixed cBPF socket filter before starting nono in `landlock` mode. The filter
permits AF_UNIX and TCP streams, denies other socket families/types/protocols,
non-Unix socketpairs and io_uring_setup, and rejects non-x86_64 and x32 syscall
ABIs. Its sole additional valid socket form is
`AF_NETLINK/SOCK_RAW/NETLINK_AUDIT`, including CLOEXEC/NONBLOCK flags.
Nono still enforces the original filesystem/process and TCP-port restrictions;
its [landlock mode](https://github.com/nolabs-ai/nono/blob/v0.77.0/crates/nono-cli/src/cli.rs)
refuses unsupported network enforcement. There is no fallback to unfiltered
execution or errno translation, no extra capability, and no PAM/library change.

The launcher constructs this fixed program, seals its anonymous descriptor
against writes/resizing, and passes it to
[bubblewrap 0.12.0](https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c)
through `--seccomp`. Preparation failures close descriptors before admission;
bubblewrap consumes the descriptor and refuses a failed filter installation.
The Linux UAPI seal values are explicit because the installed test Python omits
their symbolic names. Unsupported architectures fail before descriptor creation.
Filter bytes, launcher, staged probe and tool copies are bound to the private
diagnostic receipt. Old `auto` receipts cannot qualify this changed boundary.

Complete native validation remains mandatory. The socket probe runs as root,
in a child and through the original `sudo -u dev` route. It requires actual
audit-socket creation while verifying denial of audit status/configuration,
user-message submission, multicast subscription and peer delivery. The
configuration probe has a zero update mask; it changes no audit setting.
Audit payloads are never retained. It also requires denied UDP/raw/SCTP/other
netlink sockets, non-Unix socketpairs, io_uring and x32 calls; allowed Unix IPC;
forbidden TCP-port denial; absent admin/audit capabilities; and no leaked filter
descriptor. Unsupported kernel features, timeout and malformed acknowledgements
fail these checks. The unchanged useful-dev-work/private-read assertions and
independent TCP collector controls remain required.

The [kernel audit implementation](https://github.com/torvalds/linux/blob/v6.8/kernel/audit.c)
rejects requests from noninitial user namespaces and protects audit administration,
submission and multicast with capabilities absent here. This source explains the
expected boundary; it is not a measurement of the installed kernel. The probe
retains the kernel's returned error, including ECONNREFUSED for a rootless user
namespace. Compatibility and security must both pass before adapter expansion.

Host bubblewrap requires a newer libc than the pinned image. The fixture therefore
copies the already installed bubblewrap/nono binaries and their resolved shared
libraries into its new private directory. Every copy is byte-verified against
its original, checked not to be a hardlink, mounted read-only and checked again
after execution. An explicit loader/library path applies only to those tools;
the native application keeps its image libraries. There is no download, native
image replacement, change to a shared daemon or automatic sandbox fallback.

The fixture checks useful root/child work, root-to-dev user switching, denied
private and symlink reads, denied writes to private/read-only/tool/control paths,
and allowed TCP and filesystem Unix-socket exchanges with an independent local
observer. It checks a forbidden TCP port before an observer reachability control.
A background child must stop producing effects after controller revocation while
the observer survives. Native failures are required failures, never skips; raw
stdout/stderr and incomplete attempts remain in the private output directory.

TCP ports are not destination authorization. The fixture has only a new loopback
network; the eventual native adapter still requires the exact approved episode
service network. DNS, deployment, cron, persistent application restarts, editor
APIs and unchanged graders are not established by this fixture. Its resource
specification is synthetic compatibility data, not the main-task policy freeze.
Separate assessment execution and supported conversation resume remain unfinished.

The implementation reuses installed tools, with no new dependency. The narrow
primary-source checks were [bubblewrap's implementation](https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c)
and [kernel Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html).
Those documents explain the mechanisms; only the native checks can establish
compatibility of the actual pinned image and installed tools.
The diagnostic decoder uses the [ELF dynamic linking specification](https://www.sco.com/developers/gabi/latest/ch5.dynamic.html)
and [glibc loader invocation](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Invocation.html).
It supports only this pinned x86_64 ELF layout; malformed or unsupported metadata
is recorded as a diagnostic error, never interpreted as an enforcement denial.
