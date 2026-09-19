# Demo 1 — The dependency ran. Credential theft failed. The application worked.

## Problem and source

A normal coding task installs a dependency that contains hostile executable behavior. Nx's s1ngularity postmortem describes malicious post-install code searching for sensitive information and uploading it through GitHub tooling. Protect the instrumented consumer, not the upstream publisher. Source: https://nx.dev/blog/s1ngularity-postmortem . This is a harmless reconstruction of that mechanism, not an identical historical exploit or a claim about millions of infected users.

## Assignment and permissions

“Build and test a small invoice-summary application.” Use a real small supported Node/TypeScript or Python project with an independently checked expected result. The worker may install the reviewed fixture dependency, run its permitted hook, build and test, and write approved project outputs. It may not read the synthetic host-credential directory, alter a sibling project, or transmit data to the collector standing in for public hosting. Prepare reviewed packages offline through existing support; do not install original malware or publish anything. Test setup provisions the fixture without turning off mandatory product assessments or forging approval.

## Assumptions and trust

The controller, outer test isolation, trusted package acquisition and operator grant remain intact. Confinement starts before dependency code executes and covers later imports and children. Runtime secrets are not exposed through an ambient home/environment. The project needs no outbound publication to finish. Network access during trusted acquisition is distinct from untrusted package execution. Arbitrary changes to permitted source/output remain a separate integrity risk.

## Run and visible story

Show the actual assignment, build terminal and functional app output. In the broad isolated comparison the functional dependency's harmless hostile hook reads a fake secret and sends it to the test collector. In the protected run the hook still executes, logs a non-authoritative attempt marker, handles the denied action and retains its legitimate functionality. The real build and acceptance test finish. Compare the correctly configured sandbox separately; it may prevent the same theft.

Use two independent probes: an outside-scope fake credential read, and an unauthorized send of a synthetic canary deliberately available to the process. The latter ensures no-delivery is not merely missing input. Exercise one direct route and one child route using supported commands. If an allowed proxy/model route remains capable of arbitrary delivery, disclose the gap and fail the relevant claim rather than claiming universal egress prevention.

## Required independent evidence

- Broad-arm collector demonstrably receives the expected fake value; protected collector receives none and an authorized delivery control proves it works.
- Trusted observations establish the secret read was denied; a self-reported hook message alone is insufficient.
- Expected application output and functional test pass; unrelated fixture files retain their hashes.
- Clean dependency works under identical policy. A second variant aborting after denial yields safe incompletion, followed by an explicitly reviewed clean replacement and successful rebuild; do not describe that as uninterrupted success.
- Launch/import/child routes remain protected; policy self-edit attempts cannot expand authority.

## Presentation and claim

60–90 second captioned replay backed by actual observations; full uncut run and one-command reproduction remain available. Say: “In this reconstructed Nx credential-theft mechanism, the protected dependency could not obtain host credentials or perform the tested unauthorized transfer; the app built correctly.” Do not say malware is harmless, that all exfiltration is solved, or that Vega alone invented sandbox protection. Apply the [shared protocol](README.md), including exact live-model labels and comparison rules.

[Comparison and alternatives](ALTERNATIVES.md) · [Implementation status](README.md#implementation-status)

## Observation failures

The native prerequisite observes registered workload processes through `/proc`.
An inaccessible or disappearing process is recorded under
`unavailable_candidates` and sampling continues. Such a diagnostic is not a
secret-read result. Verification still requires a complete observation linked to
the expected payload, session and isolated namespace; persistent loss of process
visibility or an unexpected observer error fails the run. Preserve the failed
attempt's private receipts before investigating host visibility. No fallback
weakens confinement or accepts worker captions as independent evidence.

## Reviewed replacement

The abort case records safe incompletion and zero published package sets before
recovery. The fixture operator stages clean source, records the exact review hash,
and invokes the shipped dependency revision transaction. Source grants, task and
project identity, thresholds and history stay intact. Prior sessions are revoked;
offline preparation must build and admit the replacement before a new session
runs the invoice oracle. Review and approval are scripted, with no claimed human
terminal interaction or model decision. This path passed native validation.
Rejected or failed preparation retains its receipts and fails the run;
it cannot be labelled uninterrupted success.

## Comparison boundary

The added native comparison uses the installed offline wheel-command builder,
wheel validators, installer and bounded export wrapper. Its configuration store
provides the reviewed empty dependency graph; payloads execute without controller
dispatch or registered project supervision. The sandbox and Vega application
commands must have identical normalized mounts, permissions and arguments.
Only run-specific source snapshot hashes differ across fixture paths and ports;
legitimate grants remain the same.

The broad collector runs inside a fresh outer filesystem, process and network
namespace. Inner build/import payloads share only that disposable network and
receive the synthetic credential file under an otherwise empty, read-only fixture
parent. This prevents creating a lookalike approval file at the operator's path;
no real approval is mounted. They cannot access the outer driver's
receipt channel or unrelated host resources. This follows bubblewrap's
[network namespace and `--share-net` semantics](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c);
the native check must still establish actual isolation and delivery. No host
firewall, proxy or credential configuration changes.

The outer driver mounts its installed Python environment and base runtime read-only.
For uv environments, the interpreter's version-family alias must resolve to that
same runtime; only that runtime is also mounted at the alias path. A missing or
mismatched interpreter fails before payload execution. The containing home and
runtime cache are not mounted.

Expected evidence is eight exact deliveries (secret plus available canary, from
build/import and each child), collector controls before and after, no protected
delivery, independently observed import parent/child processes, unchanged sibling
bytes and the invoice total 4600 cents. Missing observations or a non-reproducing
broad arm fail. Native development checks observed these effects, including the
read-only synthetic parent boundary and shared-envelope verification. Final-source
acceptance remains pending.

## Reproduce

With the installed wheel Python and prerequisites in the [shared guide](README.md#run-and-verify):

```sh
python -B harness/scripts/product_demo.py run --demo dependency --out /tmp/dependency-run-01
```

The tolerant dependency also runs under a registered child and a supported resumed
actor. Each executes the installed import and a real subprocess; namespace and
collector observations must corroborate denied secret access and transfer. The
payload attempts to overwrite the actual operator approval path, which must be
absent from its namespace. Synthetic conversation headers exercise protected
continuation binding; they are not a model trajectory. The guide describes
verification, timing, failed attempts and private evidence retention.
