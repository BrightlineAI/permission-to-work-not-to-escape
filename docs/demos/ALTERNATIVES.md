# Alternatives and the comparison Vega must earn

Documentation checked 19 September 2026. This is a sourced capability comparison, not a hands-on performance ranking. Three demos must link this document.

| Option | What already overlaps | What to compare for this task |
|---|---|---|
| Correctly configured OS sandbox/container plus least privilege | Local read/write and outbound confinement can already prevent demo effects. | Mandatory real baseline: same useful resources, isolation and commands. Credit ties; measure setup, handoff, resume and shared response. |
| NVIDIA OpenShell | Agent runtime with filesystem, process, network and provider credential controls. Direct overlap with poisoned dependencies and local scope. | Strong relevant alternative. Do not call it just a container or assert missing coordination without testing its current facilities. |
| Amazon Bedrock AgentCore Policy | Gateway authorization with Cedar; current documentation also describes Dogwood session-aware temporal conditions, prior approvals and running thresholds. | Shared policy/history/counters are not unique to Vega. Compare local coding lifecycle and physical process revocation only after implementation tests. |
| agentgateway | Central MCP authorization at requests passing through its gateway. | Tool access overlap. A gateway check alone does not establish confinement of arbitrary local dependency code. |
| OPA / Cedar | Reusable policy engines supporting external authorization decisions. | Potential building blocks or alternatives; callers must integrate real effect enforcement and resource identity. |
| AWS secure multi-agent delegation sample | Narrowing delegated permissions, token chain and audit examples. | Direct architectural overlap; explicitly an educational reference, not production-ready proof. |

Sources:
- https://docs.nvidia.com/openshell/dev/about/overview
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html
- https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/mcp-authz/
- https://www.openpolicyagent.org/docs
- https://docs.cedarpolicy.com/auth/authorization.html
- https://github.com/aws-samples/sample-agentic-delegation

Vega's proposition to validate: one usable project permission workflow across supported coding agents, descendants and restarts, with preserved history, recoverable denials and coordinated stopping. Not a new invention of authorization or a replacement for isolation. If another platform already supplies a user's whole workflow, do not insist they add Vega.

No comparison can equate absent documentation with absent capability. Broad unprotected arms demonstrate the hazard; the proper sandbox arm tests added value. No new OpenShell/AWS installation or paid evaluation is required for this bounded task; untested comparisons remain labelled documentation-only. General information-flow enforcement, service-specific authorization and compromised-owner protection are outside these local demos.

LinuxArena and broader benchmarks are fully deferred/unvalidated for this release, not acceptance prerequisites. AgentDojo also requires future tool integrations. Do not claim demo results establish 80% coverage, 99% recall, or 1% false stops. The 46-case casebook is background intake research, not bundled demonstration evidence. See the maintained [incident provenance and limits](../../harness/DEMO.md#provenance-and-limits) and [scenario catalogue](../PROJECT-SAFETY-SCENARIOS.md); neither establishes 46 measured prevention results.
