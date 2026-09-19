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

60–90 second captioned replay backed by actual observations; full uncut run and one-command reproduction remain available. Say: “In this reconstructed Nx credential-theft mechanism, the protected dependency could not obtain host credentials or perform the tested unauthorized transfer; the app built correctly.” Do not say malware is harmless, that all exfiltration is solved, or that Vega alone invented sandbox protection. Apply the shared protocol in [shared protocol](README.md), including exact live-model labels and comparison rules.

[Comparison and alternatives](ALTERNATIVES.md) · [Implementation status](README.md#implementation-status)
