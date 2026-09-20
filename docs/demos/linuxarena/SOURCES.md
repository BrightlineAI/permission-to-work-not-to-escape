# Sources and retained observations

Primary documentation checked 19 September 2026:
- https://github.com/linuxarena/control-tower — extension architecture, no-upload local runs, environment/settings separation; development APIs change.
- https://docs.linuxarena.ai/docs/running-evals — native eval and smoke workflow.
- https://docs.linuxarena.ai/docs/running-evals/task-selection — exact task pairs; replay-sandbox does not execute containers/programmatic scorers.
- https://docs.linuxarena.ai/docs/architecture — honest/attack protocol comparison and native task combinations.
- https://github.com/redwoodresearch/linuxarena-paper — full reproduction is much broader and has different pinned runtime requirements. Do not run its full Makefile pipeline for this pilot.

Read-only Algol evidence:
- /home/loon/hamal-projects/linuxarena-baseline/artifacts/report.json — incomplete retained run and budget status; no prevention library in baseline.
- /home/loon/hamal-projects/linuxarena-baseline/artifacts/runtime/provenance.json — Control Tower/environment/Compose/daemon hashes and validated combinations, not proof all runs completed.
- /home/loon/hamal-projects/linuxarena-baseline/artifacts/recovery-20260918/code/README.md — reusable pinned implementation, private daemon and budget protocol; original $50 user/$49 accounting ceilings.

Hardware readback: 15,999 MiB total RAM; 22 GiB available filesystem; swap fully used at inspection. These observations are dated, not fixed admission thresholds. Recheck before executing.

Prior three-demo specifications and alternatives: ../vega-three-demos-2026-09-19/ . These remain governing except the proposed-only benchmark phase is now superseded by PLAN.md. Incident casebook: ../vega-prevention-feasibility-2026-09-19/CASEBOOK.md .
