# Third-party materials

MIT covers the project's original code and original documentation. It does not relicense third-party benchmark content, quoted material, provider output or trademarks.

| Material | Treatment |
|---|---|
| DecodingTrust-Agent / DTAP | Upstream repository is pinned in `experiments/paper-2026/dtap-vega/frozen/manifest.json`. Included task material and patch context retain upstream Apache-2.0 terms; [license copy](licenses/DTAP-Apache-2.0.txt). The full upstream code/images are fetched separately. |
| AgentDyn, AgentDojo, InjecAgent, CompoSkill, WeClawArena | The core experiment contains locally adapted synthetic fixtures. Each case records its source benchmark, original artifact and revision. These are not complete upstream benchmark distributions. Preserve that attribution when adapting them further. |
| nono, Open Policy Agent, agentgateway, Docker, Codex | External tools, not vendored binaries. Obtain them from their maintainers under their own terms. Recorded versions/hashes are in experiment manifests. |
| Provider requests/responses | Research run artifacts, included to make the reported experiments inspectable; provider access and reuse remain subject to applicable terms. No model weights or authentication are distributed. |
| Research sources and incident reports | Citations and authored notes in `paper/research`. Original articles, datasets and quotations retain their source terms. |

Upstream URLs/revisions are preserved in case files, source notes and protocol documents. Changing an adapted fixture should not remove its source record or imply that the upstream authors endorse this project's results.

The exact DTAP export changes are recorded in `EXPORT.json`: two files have credential-shaped benchmark fixture text redacted; remaining files are unchanged. Reviewed patch files under `dtap-vega/patches/` identify changes to the upstream runner.

Earlier exploratory packages preserve their original attribution and provenance. They are research history, not a redistribution of the complete upstream projects or a grant of rights beyond those sources' licenses.
