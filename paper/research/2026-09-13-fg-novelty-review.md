# F/G novelty review — September 13, 2026

**Result:** established methods, a distinct local implementation and bounded evaluation. No exact published duplicate located; no proof of firstness. Read with [paper and evidence map](../README.md).

## Scope and method

- Five sequential, adversarial literature passes: broad policy generation; typed compilation; criticism/repair; exact evaluation overlap; whole-system/GRC counterclaims.
- Compared primary-source methods and evaluations with the actual submission, compiler, authorizer, fixed Rego and replay runner.
- Dates refer to publication/version dates, not search-engine crawl timestamps. Older work remains relevant to priority.
- No new benchmark execution or third-party software installation. Published results are authors' reports, not independent replications.
- “Not reported” means absent from the inspected method/evaluation; it does not establish that a system cannot implement it.

## Search trail

Representative search topics from the five passes; not an exhaustive query export:

| Pass | Search focus | Primary material inspected |
| --- | --- | --- |
| 1 | Natural-language access policies, executable Rego, external enforcement, agent privilege control | P2P §§3–6; Progent §§4–8; AWS AgentCore/Cedar |
| 2 | Structured JSON to authorization policy; deterministic intermediate-representation compiler; direct-code baselines | Alajramy et al. §§4.1–4.2; PlanCompiler architecture/evaluation; P2P §4.4 |
| 3 | Policy generator/critic, semantic verifier, bounded repair, critic errors | Sondera §§2–3; RAGent §§3.5–3.6 and 5.3; AgentGuardUtil §2 |
| 4 | Policy-source ablations, captured-trajectory replay, safe/unsafe controls, unseen policy cases | Sondera §3; P2P §6; AgentSpec §5; AgentGuardUtil §3; Progent §8 |
| 5 | Nono plus policy generation; contextual authorization, provenance, multi-agent approval, GRC closure | FORGE v1/v3; CaMeL §5; nono site; OPA external-data documentation; Vega Appendices E/G |

Selected exact later queries included:

```text
"On-device derivation of IoT usage control policies" "deterministic"
"policy generation" "direct" "intermediate representation" benchmark LLM
"policy" "compiler" "critic" "AgentDojo"
"policy" "typed" "held-out" "critic" agent
"typed" "policy" "generation" "benchmark" "nono"
"policy" "direct generation" "critic" "security" LLM
"FORGE" "Datalog" "policy" agent
"Prose2Policy" "benchmark" "comparison"
```

## Source versions and verification notes

| Source | Version used / evidence location |
| --- | --- |
| [P2P — Gupta and Sreenivasamurthy](https://arxiv.org/html/2603.15799v1) | March 16, 2026; §§3–6. |
| [On-device IoT usage policies — Alajramy et al.](https://doi.org/10.1016/j.future.2025.108067) | Online August 9, 2025; journal volume 175 (2026). Institutional PDF's indexed full text supplied front-page dates, Fig. 2 and §§4.1–4.2. Direct PDF opening returned 403; no claim of a locally inspected complete PDF. [Institutional copy](https://www.iris.sssup.it/retrieve/d1ba7c3f-ff89-4482-b8b6-b8e020b331db/1-s2.0-S0167739X25003620-main%20%282%29.pdf) |
| [Autoformalization — Mondl, Maisel and Brock](https://arxiv.org/html/2606.26649v1) | June 25, 2026; authors are at **Sondera**, not AWS. §§2–3 separate generation/critics from replay coverage. |
| [AgentGuardUtil — Bouchekir et al.](https://arxiv.org/html/2608.23282v1) | August 24, 2026; §§2–3. Its critic reviews advisory action findings. Do not relabel it a Vega-style policy-draft critic. |
| [Progent](https://arxiv.org/html/2504.11703v3) | May 2026 revision; §§4–8. Used the revised method, including SMT privilege-update checks. |
| [FORGE — Palumbo et al.](https://arxiv.org/html/2602.16708v3) | v3 May 8, 2026; §§2.3, 4.4, 6, 8. Earlier v1 is titled *Policy Compiler for Secure Agentic Systems*. v3 includes a translator; do not carry forward v1's exclusion of automatic synthesis as a blanket description of v3. |
| [CaMeL — Debenedetti et al.](https://arxiv.org/html/2503.18813v2) | Inspected §§5.2–5.4; distinguish authored security policies from generated control-flow code. |
| [RAGent — Jayasundara et al.](https://arxiv.org/html/2409.07489v1) | September 2024; verifier is fine-tuned BART, not a second general-purpose critic prompt. |
| [AgentSpec — Wang, Poskitt and Sun](https://arxiv.org/html/2503.18666v1) | March 2025; §§3/5. This is the runtime-enforcement paper, not Oracle's similarly named Agent Spec. |
| [PlanCompiler — Harikumar](https://arxiv.org/html/2604.13092v1) | April 2026; general workflow compilation, not a security-policy benchmark. |
| [AWS AgentCore/Cedar — Hadarean and Tristan](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/) | May 20, 2026; corroborating deployed-product description, separate from Sondera's paper. |
| [Conseca — Tsai and Bagdasarian](https://research.google/pubs/context-is-key-for-agent-security/) | HotOS 2025; contextual policy-generation framing, not evidence of the exact F/G experiment. |
| [ARPaCCino — Romeo et al.](https://arxiv.org/html/2507.10584v1) | July 2025; adjacent natural-language/Rego work checked while tracing P2P references. |
| [nono](https://www.nono.sh/) / [OPA external data](https://www.openpolicyagent.org/docs/external-data) | Current documentation accessed September 13, 2026. Product capability is distinct from the pinned nono 0.77.0 / OPA 1.20.2 configurations Vega evaluated. |

## Local evidence checked

- [Paper and evidence map](../README.md): Methods, Results, Appendices C–G and I.
- [Compiler and contract validator](../../experiments/paper-2026/vega-core/scripts/policy_pipeline.py): closed IR, deterministic construction, identity binding and literal/interface checks. No general semantic-equivalence proof.
- [Authorizer](../../experiments/paper-2026/vega-core/src/vega_core/authorize.py) and [baseline Rego](../../experiments/paper-2026/vega-core/gateway/baseline.rego): C lacks the protected-context checks D adds. This is not an OPA expressiveness limitation.
- [Runner](../../experiments/paper-2026/vega-core/scripts/run_suite.py): fixed-call replay, mock effects, read/port restrictions and preflight bypass checks. Nono is unchanged in C→D.
- [Experiment record](../../experiments/paper-2026/vega-core/PROTOCOL.md): prospective split versus later regression, historical raw arm labels and physical scoring.

## Remaining uncertainty

- Literature searches cannot prove that no unpublished, unindexed or differently named identical experiment exists.
- No head-to-head P2P/FORGE/Progent reproduction was conducted. Architecture differences do not imply a performance ranking.
- P2P's unit-test outcomes, FORGE's task outcomes and Vega's forced/matched requests use different denominators and oracles.
- No verified evidence supports claiming a new complete GRC lifecycle. Vega's operational escalation, periodic audit and assurance closure remain proposed.
