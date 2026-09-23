# Installed dependency reassessment

Protected commands, previews and the legacy operator launch API check installed
sets before reuse. Python, npm, pnpm and Yarn imports share the approved
`project.packages.evidence_max_age_seconds` policy (60 to 86400 seconds, normally
900). There is no separate ecosystem policy or polling downloader.

Installations retain exact direct/transitive identities, artifact digests, origin,
publication times and advisory records. Local Python installations also retain
assessed build dependencies, including combined-source preparation. Local source
identities remain governed by reviewed source receipts, not public registry queries.

Complete cached evidence permits reuse through the inclusive freshness boundary.
Every use still checks session scope, reviewed inputs, policy/runtime bindings and
installed-file integrity. Expired evidence triggers exact-version advisory requests
through the existing public or approved private client. Refresh uses up to eight
concurrent requests with a shared 30-second request budget, existing per-request
timeouts, response limits and bounded pagination. It does not resolve versions,
download artifacts or execute package code. Each record retains its collection
timestamp; completing a batch does not extend freshness.

## Outcomes and running work

* **Current:** complete fresh evidence permits reuse, including offline reuse.
* **Blocked:** expired, absent, malformed, incomplete or unavailable evidence
  prevents unsafe reuse with an operational reason and no misconduct count.
  Failed batches do not renew cached timestamps. A later use retries the approved
  route. Legacy sets without sufficient provenance require installation again.
* **Quarantined:** fresh evidence confirms a dependency forbidden by the existing
  evaluator. All sets containing the exact ecosystem/origin/name/version within
  that project become unusable, including sets with otherwise fresh caches.
  A confirmed finding remains actionable when another record is uncertain.
  Old IDs and replayed installation receipts cannot restore authorization.
  An installation already in progress cannot publish clean evidence collected
  before that finding. It must retry with newly collected evidence, including
  local Python runtime and build dependencies.

Advisory changes are not agent misconduct. Ordinary out-of-scope file/package
requests retain shared escalation. `ptw status` reports assessment state/reason
separately from violation counts and physical termination receipts.

Quarantine terminates registered commands and previews using affected sets through
the existing supervisor. Unconfirmed termination stays visible for reconciliation
retry. Other sets, sessions and projects are not stopped by that quarantine.
Previously completed effects cannot be rolled back.

Required assessment-capture or quota failure also blocks new affected work and
requests termination through the existing supervisor, without misconduct counts.
This capture failure stops the affected project, including when a quarantine
batch cannot retain all its receipts. Partial batch receipts are rolled back;
restrictive quarantine is retained where storage permits. A failed stop-state
write permits best-effort physical termination, not a claim of durable closure.

Freshness expiry alone does not terminate already-admitted bounded work. A
confirmed finding discovered on a later use does. Commands revalidate before
publishing outputs; expiry or quarantine during execution prevents publication.
Preview status requests report process state without querying advisories. Without
another use there is no continuous discovery guarantee. The normal project monitor
reconciles termination and never downloads packages or advisory data.

## Recovery

Read `ptw status --state STATE --project PROJECT`. For operational failure, restore
the approved evidence service and retry with a new command event ID. Fresh complete
evidence clears the block. There is no offline bypass. Do not edit the database,
cached timestamps or package files.

If required capture failed, restore storage capacity through the exact operator
evidence review. This permits recording termination confirmation but does not
reopen the stopped project or clear quarantine. Missing assessments stay missing.

For quarantine, use the existing reviewed dependency flow, such as `ptw deps update`,
to select an allowed dependency and install a freshly assessed replacement. A
corrected or withdrawn advisory may permit a new installation of the same version;
it never revives the old ID. Local preparations use the existing source/build
review flow. Recovery never resets violation history or a stopped project.

## Admission and validation

Requests run outside the controller lock. Before recording results, the controller
rechecks session, scope, integrity and policy bindings. Assessment generations
prevent older clean results from overwriting newer quarantine. Refreshed evidence,
eligibility, generation and the required assessment commit atomically. Admission
includes changed package-row size and the full serialized assessment row, including
identity, timestamps and escaped detail. This applies before direct operator
launch as well as command/preview reuse. A crash before that commit leaves the
previous evidence; it cannot silently renew freshness. Quarantine of all
matching sets is transactional. Append-only assessment attempts record installation,
refresh, operational failures and discarded concurrent results. Trusted command
bindings are checked under the launch lock, registered with workloads and checked
again at command output publication. Native builds/install scripts remain confined.

`test_product_reassessment.py` uses deterministic transitions, controlled failures
and concurrency fixtures. Native cases exercise useful imports, terminal refusal,
preview/command termination and unrelated work. Native validation is pending manager
checks on an isolated Linux VPS. Local mocked tests do not demonstrate physical
termination or an LLM trajectory. Native fixtures retain source hashes, attempts
and final state in new private `REASSESSMENT_EVIDENCE` directories outside checkout.

The concurrent command/preview test chooses distinct operation lease slots so
the on-demand reassessment can run while the command is active. Colliding slots
still serialize, as verified separately by the audit tests. Its private
`stop.json` records the selected events/slots, exact active units, physical states,
quarantine termination records and monotonic interval. Both units must have
confirmed quarantine termination records, and stopping must precede the command's
unchanged 60-second payload completion. Eventual inactivity or missing output
alone cannot pass. Offline negative tests reject natural completion, missing,
wrong-target, stale or unconfirmed receipts and absent physical stopping.

Before native source tests, install this exact checkout in a new isolated editable
environment with hashed dependencies following the
[developer instructions](README.md#run-the-tests). `PYTHONPATH` alone does not reach
detached systemd services. Installed-user journeys use separate fresh wheel
installations with no editable source or `PYTHONPATH`.

Design sources: the official [OSV query documentation](https://google.github.io/osv.dev/post-v1-query/)
requires complete pagination, including token-only pages. The
[OSV schema](https://ossf.github.io/osv-schema/) defines severity and withdrawal.
These support retaining the existing complete-response client and failing safely
on unusable severity. No new dependencies or APIs were introduced; research into
stable SQLite transactions and existing supervisor calls adds nothing.

This experimental mechanism checks known advisories within the approved freshness
window. It does not detect unknown malware, certify arbitrary package behavior,
protect against a compromised host/operator or establish complete mediation.
