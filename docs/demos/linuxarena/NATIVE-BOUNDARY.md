# Native execution boundary

The controller lifecycle has passed native development checks. The new
`linuxarena_namespace` launcher is a confinement seam awaiting native validation,
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
for a physical-effect timeout. Native compatibility remains pending.

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

The fixed sudo runtime reads are `/usr/libexec/sudo/libsudo_util.so.0.0.0`,
`/usr/libexec/sudo/sudoers.so` and `/etc/sudoers` (nono `--read-file`), plus
`/etc/sudoers.d` (`--read`), all within existing read-only mounts. Sudo must
enumerate and read its [include directory](https://raw.githubusercontent.com/sudo-project/sudo/main/docs/sudoers.man.in);
the retained native failure reached that directory after reading the main
configuration. The [pinned nono options](https://raw.githubusercontent.com/nolabs-ai/nono/v0.77.0/crates/nono-cli/src/cli.rs)
provide these file/directory reads. No `/etc` grant, runtime write or added
capability is required by this change. Resource arguments cannot select or
override these trusted paths.

Image and confined diagnostics inspect plugin/configuration metadata and a bounded
include-directory listing with explicit access errors; configuration contents are
never emitted. Native validation must still establish useful dev-user work,
denied private access and rejected configuration writes/forged include files.
The mapping alone does not establish complete sudo compatibility.

PAM diagnostics compare `/etc/pam.d/sudo`, `/etc/pam.d/other` and their
trusted-image includes against the same confined paths, including paths whose
parent configuration was denied. Discovery supports `@include`, `include` and
`substack` within `pam.d`, bounded to 32 files, 64 KiB per file and 1,024 logical
lines. Missing/denied files, malformed includes, links outside that directory and
limits remain explicit; this is not a full PAM policy validator. Only metadata,
hashes and include identities are recorded, never configuration contents.
The image receipt also records selected sudo/PAM package identities from the
local Debian package database. These identify package records, not proof that
an upstream source version matches every installed binary.

Hostname, hosts, NSS and resolver files receive separate metadata observations
without DNS or network probes. Diagnostics themselves add no permissions
or mounts. A PAM initialization error remains a failed compatibility check;
it cannot satisfy the useful-user-work/private-read-denial assertions. The
[sudo PAM implementation](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_15p5/plugins/sudoers/auth/pam.c)
and [Linux-PAM initialization](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.4.0/libpam/pam_start.c)
explain that failure stage; [PAM include loading](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.4.0/libpam/pam_handlers.c)
motivates inspecting the configuration graph.

The runtime now grants read access to the existing read-only `/etc/pam.d` mount:
native diagnostics found all seven image configuration/include files readable
outside confinement and denied inside it. PAM writes and forged includes remain
explicit denial probes. The synthetic namespace creates `/etc` with mode `0755`
before mounting individual runtime files, and its private `/tmp` with mode `1777`.
This preserves traversal and temporary-file creation after switching Unix user;
it changes no host directory or image configuration. Bubblewrap's
[directory and tmpfs options](https://raw.githubusercontent.com/containers/bubblewrap/v0.12.0/bubblewrap.c)
define these modes. The native fixture asserts both modes, a dev-owned useful
file, readable account metadata and denied private access. Full sudo/PAM
compatibility still requires that fixture to pass; hostname warnings are
recorded separately and do not justify broader runtime grants.

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
