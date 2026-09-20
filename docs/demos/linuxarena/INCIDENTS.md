# Incident source index

These 46 records link the owner-supplied review dated 19 September 2026.
They are historical research context, not 46 implementations or measured
prevention results. Source selection and uncertainty remain those of the intake;
this task did not repeat the literature review or independently replay incidents.
V05, G01 and M02 have provisional secondary-source support.

Intake `demo-20260919/research/README.md` SHA256: `ea4f083bd2eb6a7a4611afb89f37a23ca763443299d3ce1f0ab9db3ae71d7710`.

| Intake record | Retained source links |
|---|---|
| L01. OpenAI → Hugging Face intrusion | [source 1](https://huggingface.co/blog/agent-intrusion-technical-timeline) · [source 2](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) |
| L02. Anthropic: real company shares exercise target name | [source 1](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents) |
| L03. Anthropic: malicious public PyPI package | [source 1](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals) |
| L04. Anthropic: scan beyond failed exercise target | [source 1](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals) |
| L05. Anthropic: abort failed eight times | [source 1](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents) |
| L06. UK AISI: unauthorized public actions in cyber tests | [source 1](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing) |
| L07. GTG-2002 extortion campaign | [source 1](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025) |
| L08. GTG-1002 espionage campaign | [source 1](https://www.anthropic.com/news/disrupting-AI-espionage) |
| L09. Codex model-selected cwd expands sandbox scope | [source 1](https://github.com/openai/codex/security/advisories/GHSA-w5fx-fh39-j5rw) |
| L10. Codex project-local startup configuration injection | [source 1](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/) |
| L11. Claude Code hooks, MCP consent and endpoint flaws | [source 1](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| L12. Codex Cloud branch-name command injection | [source 1](https://www.beyondtrust.com/blog/entry/openai-codex-command-injection-vulnerability-github-token) |
| V01. Nx / s1ngularity | [source 1](https://nx.dev/blog/s1ngularity-postmortem) |
| V02. Cline CLI supply-chain compromise | [source 1](https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm) |
| V03. Replit production database deletion | [source 1](https://www.saastr.com/weve-now-shipped-3-vibe-coded-apps-to-production-heres-what-actually-worked-and-what-nearly-killed-us/) · [source 2](https://replit.com/blog/doubling-down-on-our-commitment-to-secure-vibe-coding) |
| V04. Amazon Q Developer compromised extension | [source 1](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/) |
| V05. Unofficial postmark-mcp email backdoor | [source 1](https://www.scworld.com/news/open-source-mcp-server-package-caught-stealing-emails) |
| V06. ClawHavoc malicious skills | [source 1](https://snyk.io/articles/skill-md-shell-access/) |
| V07. LiteLLM dependency compromise reaches MCP startup | [source 1](https://futuresearch.ai/blog/no-prompt-injection-required/) · [source 2](https://github.com/BerriAI/litellm/discussions/24575) |
| V08. GitHub MCP private-repository exfiltration | [source 1](https://invariantlabs.ai/blog/mcp-github-vulnerability) |
| V09. WhatsApp MCP tool poisoning | [source 1](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) |
| V10. Supabase MCP support-ticket injection | [source 1](https://generalanalysis.com/blog/supabase-mcp-blog) |
| V11. Gemini CLI command-approval deception | [source 1](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) |
| V12. Cursor CurXecute | [source 1](https://www.catonetworks.com/blog/curxecute-rce/) |
| V13. Cursor MCPoison | [source 1](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/) |
| V14. GitHub Copilot auto-approval settings injection | [source 1](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) |
| V15. Microsoft 365 Copilot EchoLeak | [source 1](https://www.catonetworks.com/blog/breaking-down-echoleak/) · [source 2](https://www.aim.security/lp/aim-labs-echoleak-blogpost) · [source 3](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711) · [source 4](https://arxiv.org/abs/2509.10540) |
| V16. Salesforce Agentforce ForcedLeak | [source 1](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce) |
| V17. Gemini Enterprise GeminiJack | [source 1](https://noma.security/noma-labs/geminijack) |
| V18. ServiceNow agent discovery/delegation abuse | [source 1](https://appomni.com/ao-labs/ai-agent-to-agent-discovery-prompt-injection/) |
| V19. ServiceNow BodySnatcher | [source 1](https://appomni.com/ao-labs/bodysnatcher-agentic-ai-security-vulnerability-in-servicenow/) |
| V20. MCP Inspector local proxy RCE | [source 1](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) |
| V21. mcp-remote OAuth command injection | [source 1](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/) |
| V22. OpenClaw gateway token theft / RCE | [source 1](https://github.com/advisories/GHSA-g8p2-7wf7-98mq) |
| O01. OpenAI: self-injection in compaction summaries | [source 1](https://alignment.openai.com/misalignment-reports/self-generated-prompt-injections-in-compaction-summaries/) |
| O02. OpenAI: encouraging deception in summaries | [source 1](https://alignment.openai.com/misalignment-reports/encouraging-deception-in-compaction-summaries/) |
| O03. OpenAI: searching GitHub for leaked API keys | [source 1](https://alignment.openai.com/misalignment-reports/searching-github-for-leaked-api-keys/) |
| O04. OpenAI: upload local file to obtain a citation | [source 1](https://alignment.openai.com/misalignment-reports/uploading-files-to-the-internet-in-order-to-cite-them/) |
| O05. OpenAI: Artifactory used as a message board | [source 1](https://alignment.openai.com/misalignment-reports/unauthorized-artifactory-writes-and-cross-sample-communication/) |
| O06. OpenAI: temporary hosting for agent collaboration | [source 1](https://alignment.openai.com/misalignment-reports/unauthorized-communication-via-temporary-file-hosting-services/) |
| G01. Google: three evaluation intrusions, grouped | [source 1](https://www.theguardian.com/technology/2026/sep/18/google-gemini-ai-hack) |
| R01. MJ Rathbun retaliatory article after rejected PR | [source 1](https://theshamblog.com/an-ai-agent-published-a-hit-piece-on-me/) |
| M01. Meta Muse Spark 1.1 evaluation intrusion | [source 1](https://research.meta.ai/blog/addressing-third-party-testing-misconfiguration-muse-spark-1-1) |
| M02. Meta internal agent advice / data-access incident | [source 1](https://techcrunch.com/2026/03/18/meta-is-having-trouble-with-rogue-ai-agents/) |
| A01. Anthropic: suspected ShinyHunters affiliate clusters | [source 1](https://www.anthropic.com/threat-intelligence-report-september-2026) |
| H02. Hugging Face nullifAI malicious model files | [source 1](https://www.reversinglabs.com/blog/the-race-to-secure-the-aiml-supply-chain-is-on-get-out-front) · [source 2](https://nono.sh/) · [source 3](https://www.nono.sh/node-sandbox) · [source 4](https://docs.cedarpolicy.com/) · [source 5](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html) · [source 6](https://aws.amazon.com/bedrock/agentcore/faqs/) · [source 7](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/mcp-authz/) · [source 8](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog) · [source 9](https://alignment.openai.com/misalignment-reports/unauthorized-communication-via-temporary-file-hosting-services/) · [source 10](https://huggingface.co/blog/space-secrets-disclosure) · [source 11](https://openai.com/index/disrupting-malicious-ai-uses/) · [source 12](https://www.anthropic.com/threat-intelligence-report-september-2026) |

See [current alternatives](../ALTERNATIVES.md) and the [bounded native plan](PLAN.md).
