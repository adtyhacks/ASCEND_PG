# DVS discrepancy diagnosis

The saved assessment matching the reported 0/2 breakdown is
`scenario-ab12fa90ada5/run-cd38b43b9a38` (8 October 2026).
No browser selection was supplied; this is the only saved run in this checkout
containing attack episode evaluation records. Its saved evidence was read only.

## Evidence and cause

`run.json` records two episodes with `completed: false`, `end_reason:
execution_stop`, zero evasion, and zero stage depth. The corresponding six
`attack_finished` security records all have positive detection verdicts.
The first episode attempted stage 2 twice; the second attempted stages 0, 2,
0, 2. Both final records have `return_status: TIMEOUT` and `success: false`.
Attempted stages do not establish successful progression.

`strategic/rl_env.py::calculate_step_reward` advances stages only for a
successful, evaluated, undetected attack at the current stage. Completion
requires all four stages. `gui/campaign.py::_complete` sets the request state
to `COMPLETED` when a step result has been consumed, including detected or
timed-out results. `run_full` ends an episode on unsuccessful execution.
The UI presented that step state as campaign completion. Neither saved
episode actually completed under the existing criteria.

E = average evasion rate × 100, so all attacks detected correctly produces
E = 0. C = 0, S = 0, and P = 50 (the two-episode sequence does not meet the
five-episode plateau patience). Contributions are 0 + 0 + 0 + 7.5 = 7.5.
The observed numeric breakdown is supported by the saved evidence.

## Current paths and fixes

- `metrics/dvs.py::evaluate_agent` is the model evaluation path. It is not
  called by current saved-run reports and was not executed during diagnosis.
- GUI results flow through `gui/campaign.py::_complete` and
  `metrics/campaign_evaluation.py::persist_episode` into the selected run's
  `attack_episodes` and cached `dvs_evaluation`.
- `gui/reporting.py::select_run` uses explicit scenario/run IDs or the newest
  saved run. The browser sends the selected IDs for report requests.
  `summary` and report generation call `reports/pentest_report.py::generate_report`.
  HTML and PDF consume its shared DVS model.
- Reports now aggregate the selected run's saved episode inputs in memory,
  avoiding stale cached totals. Historical aggregate-only records remain
  supported after existing validation. Explicit interruption errors still
  prevent older episodes from concealing an unfinished result. Previously
  generated report files remain unchanged until explicitly regenerated.
- Aggregation rejects missing, nonfinite, malformed, or contradictory inputs.
  New episode records retain completed stages and no longer silently substitute
  zero for missing runtime progression or reward.
- Both episode persistence and model evaluation now take stage depth from
  the environment's actual completed stages. Previously they took the maximum
  undetected attempted stage, which could credit an out-of-sequence attempt.
  Historical records without stage lists retain their recorded scalar metrics;
  progression is not fabricated for them.
- GUI status and assessment selectors label request completion as attack-step
  state, and missing campaign DVS displays its unavailability reason.

Weights (0.30, 0.30, 0.25, 0.15), arithmetic, plateau rule, and rounding in
`metrics/dvs_score.py` are unchanged.

## Verification

29 tests passed across `scripts.test_campaign_evaluation`,
`scripts.test_dvs_reports`, and `scripts.test_finding_dvs` using unittest.
The new suite covers genuine 2/2 completion, interrupted episodes, zero
measured evasion, sequential stage depth, missing/invalid evidence, stale
caches, contributions/total consistency, and read-only saved-run verification.

Native Windows imports are blocked by the repository's Linux-only `fcntl`
dependency. The offline run supplied an in-memory import shim whose `flock`
raises on use; persistence was mocked. No lock operation was used. WSL listing
was unavailable in the sandbox. Python AST parsing, `node --check
gui/web/app.js`, and `git diff --check` passed. No campaigns, network tests,
CORE operations, saved-evidence writes, commits, or pushes were performed.
