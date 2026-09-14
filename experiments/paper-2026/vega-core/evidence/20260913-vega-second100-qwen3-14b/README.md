# Qwen3-14B second-100 deterministic/critic evidence

**Final-name mapping:** these immutable raw artifacts were created before the public
arm names were finalized. Artifact `E` is final public arm **F** (typed proposal plus
deterministic compiler). Artifact `F` is final public arm **G** (F plus critic). Files,
manifests and hashes retain their historical labels for chain of custody.

This bundle preserves the September 13, 2026 UTC VPS experiment. It contains adapted
synthetic fixtures, not official upstream benchmark scores.

## Reported runs

- `abcd-new-100/`: valid A/B/C/D run for cases 101–200. Qwen generated 36 attack
  requests. A/B/C completed 36/36 and D completed 0/36. The forced track was
  A/B/C 100/100 and D 0/100; benign completion was 100/100 in every arm.
- `frozen-2f5bcba/*-generation-*`: proposer and critic records for the prospective
  20/25/25/30 category split. Every split produced valid policies. Each final-holdout
  `evaluation.json` records 30/30 exact, 30/30 forced denial and 30/30 benign allow.
- `frozen-2f5bcba/physical-{e,f}-new100-final/`: final physical F/G replays stored under historical E/F filenames, with the
  code commit recorded in the manifest. Each audit is valid: 0/36 captured harmful
  effects, 0/100 forced harmful effects and 100/100 benign completion.
- `initial-iteration-6197b49/`: retained development evidence. The initial final-G
  validation-1 evaluation was 22/25 exact, 24/25 forced denial and 23/25 benign allow.
  It motivated a generic two-layer destination-semantics correction before validation
  2 and the final holdout. It is excluded from final results.

The earlier `physical-{e,f}-new100/` directories are equivalent passing replays whose
manifests recorded `code_commit: uncommitted`; they are retained but excluded in favor
of the `-final` reruns with `code_commit: 2f5bcba`.

## Integrity and reproduction

Generation manifests hash every trusted input, prompt and output policy. Assembly
manifests bind each policy to its source generation manifest. Physical manifests hash
the assembly and frozen captures; audit summaries verify identical replay, complete
records and passing live preflight.

Use `scripts/reproduce_second_100_vps.sh` from commit `2f5bcba` for the exact published
generator, or follow the staged commands in the benchmark README. A fresh OpenRouter
run is stochastic and is a replication of the protocol, not a byte-for-byte replay of
the retained LLM responses.
