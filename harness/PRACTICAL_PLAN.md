# Practical repository workflow, version 0.4

This extension implements three requested steps: ordinary repository operations,
one reviewed agent workflow, and automatic operation/recovery. It does not revise
the paper or its frozen evidence. All development and acceptance run on Algol 2-1.

## Design reviewed before implementation

Reuse the existing policy compiler, SQLite controller, package evidence/admission,
nono, bubblewrap, systemd and Codex JSON adapter. Do not add a policy server,
container daemon, agent framework or another package scanner.

1. Version 4 policies add named directory resources and named commands. Resource
   grants describe read, write, create and delete authority. Task and delegated
   grants, package scope and command lists must be subsets of their parents.
   Exact file policies (versions 1 to 3) retain their original behavior.
2. The trusted broker supports listing, reading, creating, atomic replacement,
   deletion, directory operations and rename. Paths are relative, links and
   traversal are rejected, and updates have content preconditions. Rename checks
   both endpoints. Concurrent edits fail as conflicts, not misconduct.
3. Commands run only in disposable copies of readable resources, with no host
   project/state/credentials/network mounts. Package sets are read only. The
   controller validates all changed outputs against grants and starting hashes
   before publishing. A forbidden output publishes nothing and counts once.
   Crash uncertainty stops the project rather than silently repeating effects.
4. One agent adapter dispatches repository actions, checked package installs,
   named commands and registered delegation. Independent parents share project
   identity and history. Models never receive operator credentials or tokens.
   Native unrestricted tools remain disabled.
5. Activate starts a persistent systemd user monitor. It restarts after failure,
   reconciles stops automatically and reports health. Admission requires healthy
   monitoring. Policy changes remain explicit drafts, reviewed by hash. Replacing
   a project stops its old registered work first; it never silently clears history.

## Risks and design questions

- Direct writable repository mounts would allow shell effects to bypass the
  broker and introduce races. Use disposable command copies and checked publish.
- Read access is also disclosure to the model/command. Do not copy denied files
  merely because they are in the same repository. Inventory is not permission.
- An approved command can run repository code. Command names are not a sandbox;
  Linux isolation and validated output provide the actual effect boundary.
- Do not punish tool failures, edit conflicts, unavailable evidence or recovery
  uncertainty as attacks. Count confirmed scope violations across all actors.
- Preserve old experiments and compatibility tests; no test is replaced by a
  weaker one to make a new workflow pass. Retain failed acceptance attempts.
- Human review cannot be replaced by successful schema validation. Existing
  project/history inputs never automatically authorize previously used access.

## Acceptance gates

Run each gate on the VPS and retain revision, versions, timings and outcomes.

- Unit/adversarial: traversal, symlink/hardlink, malformed requests, both rename
  endpoints, content conflicts, forbidden outputs, task/delegate subsets,
  replay, interrupted publication, monitor restart and replacement ordering.
- Linux integration: actual file effects, confined Python/TypeScript build/test,
  forbidden host/state/network access, package admission and project stop.
- Real projects: two independent parents and a delegate perform useful Python
  and TypeScript work; install, edit, create, build and test. Verify real results,
  unchanged protected files and an unrelated project, not completion messages.
- Real model workflow: record genuine Codex proposals/requests separately from
  scripted security probes. No fabricated trajectories or model substitutions.
- Fresh user: complete installation and documented new/existing project steps,
  interactive review/approval, denial explanation, reviewed policy revision,
  automatic monitoring, restart/recovery and cleanup. Do not reuse developer env.
- Full legacy suite, documentation links, public evidence/credential review,
  incremental commits, final reproducible instructions and explicit boundaries.

## Iteration log

- Initial review: keep a single policy and shared counter path; reject a general
  writable shell mount. Use the existing bounded export design for execution.
- Setup attempt: an assumed uv path was absent; use the installed executable
  discovered on PATH. No project or test effect occurred.
