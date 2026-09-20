# Native execution boundary

The controller lifecycle has passed native development checks. The new
`linuxarena_namespace` launcher is a confinement seam with a failing native user-switch check,
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
created rootless fixture. Bubblewrap drops capabilities before mutable execution,
retaining only SETUID, SETGID, DAC_OVERRIDE, CHOWN, FOWNER and KILL for ordinary
native user/file/process operations. Trusted control and observation remain
outside the resulting process and mount namespaces. Installed nono supplies
inherited filesystem/network restrictions. These are trusted integration inputs,
not model tools; production binding to the approved task policy is unfinished.

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

After that specific sudo failure, the fixture runs one separate five-second
PAM diagnostic inside the unchanged confinement. It uses the public
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

The retained public-API diagnostic completed: start=0, account=4 with errno=1,
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
The installed CLI exposes no audit-protocol exception. Its `landlock` and
`external` modes are not equivalent replacements for this static network filter.

The required native root-to-dev route is therefore **unsupported by the current
adapter**. No admissible correction has been established within the pinned
confinement interface. Removing network filtering, granting audit/admin
capabilities, changing PAM, or translating EPERM into an unsupported-protocol
error to avoid PAM's failure is not an accepted fix. The latter would change
audit failure handling even while denying the socket. No such workaround is
implemented. A reviewed confinement integration that preserves required native
authentication and network denial is needed before further adapter work. Keep
the useful-dev-work and private-read assertions mandatory; do not replace native
sudo/cron behavior with a successful diagnostic or trusted preselected UID.

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
primary-source checks were [bubblewrap's implementation](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c)
and [kernel Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html).
Those documents explain the mechanisms; only the native checks can establish
compatibility of the actual pinned image and installed tools.
The diagnostic decoder uses the [ELF dynamic linking specification](https://www.sco.com/developers/gabi/latest/ch5.dynamic.html)
and [glibc loader invocation](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Invocation.html).
It supports only this pinned x86_64 ELF layout; malformed or unsupported metadata
is recorded as a diagnostic error, never interpreted as an enforcement denial.
