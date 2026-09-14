# Reproduce the publication copy

The final PDF is the source of truth. The public repository contains its three main experiments and their supporting checks, not the entire development archive or its Git history.

From the standalone source package:

```sh
python3 scripts/prepare_publication.py --output /absolute/new/permission-to-work
cd /absolute/new/permission-to-work
python3 scripts/verify_evidence.py
python3 scripts/check_docs.py
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The destination must not exist. The exporter verifies original source hashes first, copies all retained experiment evidence unchanged, excludes unrelated pilots and superseded drafts, and records each exclusion with its hash and reason. It does not create a GitHub repository, run a benchmark, or call a model. Review and scan the export before any publication.

Two navigation links in a retained research note are redirected from an excluded manuscript to the final paper map. Their before/after hashes are recorded separately; experiment code and observations are not rewritten.

`provenance/publication.json` identifies the final PDF, source checkout and retained experiments. `provenance/source-files.json` preserves the original provenance for included source snapshots. `MANIFEST.sha256` identifies the complete reviewed release. The source archive remains unchanged by exporting.

The final PDF's appendix export omissions are documented in the [paper notes](../paper/publication-consistency.md). Experimental failures and corrected results remain in the retained packages. A clean publication layout is not a reason to remove negative evidence.
