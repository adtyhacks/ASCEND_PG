# Legacy UI cleanup on Abin

The dedicated entry point is `python -m gui.server` in the WSL application
environment, serving `http://127.0.0.1:8765`.

## Removed implementation

- `app/Home.py`
- `app/pages/1_Configure_Network.py`
- `app/pages/2_Run_Simulation.py`
- `app/pages/3_Live_Battle.py`
- `app/pages/4_Report.py`

Before removal, searches covered tracked and non-environment source, scripts,
documentation and configuration for page names, paths, Python imports and dynamic
loading. No production module imported or called these pages. References outside
the pages were documentation, comments, and the old startup test.

The `streamlit` requirement and the unused dependency-check import in
`scripts/test_unified_pipeline.py` were removed. The startup regression now serves
the dedicated GUI with imports of `streamlit` and the legacy `app` package blocked.
It verifies the actual HTML, JavaScript, CSS and report-summary HTTP responses.

## Preserved functionality

The production GUI/backend files were not changed by this cleanup. Earlier
uncommitted report fixes remain in place. Shared topology, PyVis visualization,
CORE/runtime, campaign, event-store, detector, PPO, reporting and XAI modules are
retained. These are framework-independent code, not unused UI pages.

The topology test now exports CSVs to a temporary directory, allowing verification
without overwriting repository topology data. No runtime/evidence artifacts are
deleted or edited. Existing ignored bytecode caches and installed packages in
virtual environments are left alone; package uninstallation is not part of this
source cleanup.

## Remaining textual references

No executable production Streamlit implementation or import remains. The following
references are intentionally retained:

- `.gitignore`: historical secrets exclusion and a runtime-artifact comment. The
  secrets exclusion protects against accidentally adding old credentials.
- `gui/__init__.py`, `gui/campaign.py`: independence and migration comments.
- `attacks/recon_step.py`, `scripts/core_session.py`, `scripts/ppo_step_watcher.py`,
  `scripts/run_cycle.py`, `testbed/run_store.py`, `testbed/scada_client.py`: historical
  UI comments/docstrings. Runtime, watcher and attack code are outside this cleanup.
- `testbed/core_runtime.py`: a pre-existing Linux requirement error message names
  the retired UI. It does not import that UI; CORE internals are excluded from scope.
- `testbed/visjs_topology.py`: standalone visualization documentation.
- `xai/attack_decision_explain.py`: a framework-independent compatibility alias
  with an old UI comment; keeping it avoids deleting shared XAI functionality.
- `scripts/test_event_store_jsonl.py`: writer fixture names/comments, with no
  dependency on the retired framework.
- `scripts/test_app_startup.py`: explicit forbidden-module names in the regression.
- `docs/EVALUATION_PARAMETERS.pdf`: existing historical binary documentation is
  not regenerated in this source cleanup; its Markdown source now names the GUI.

The previous untracked recovery/audit artifacts and archives are untouched and may
also contain historical UI references. They are not production source.

## Verification

Passed: `scripts/test_app_startup.py`, `scripts/test_gui_adapter.py`,
`scripts/test_gui_campaign.py`, `scripts/test_topology.py`,
`scripts/test_report.py`, `scripts/test_report_normalization.py`,
`scripts/test_gui_reports.py`, `scripts/test_gui_frontend.js`, and
`scripts/test_gui_report_frontend.js`. JavaScript syntax checks and
`git diff --check` passed. There are no cleanup blockers.

An in-memory compilation and AST import audit covers 112 Python source files in
the application and test directories, with no imports of the retired UI or `app`
package. Frontend regressions cover topology selection, PyVis rendering, CORE GUI
controls, runtime/campaign gates, Live Battle, background traffic and report
request/success/failure/open/download handling. Dedicated GUI, topology and report
regressions are run using the existing WSL virtual environment; fixtures write to
temporary directories. No commit or push is performed.

## Files modified by this cleanup

- `requirements.txt`
- `scripts/test_app_startup.py`
- `scripts/test_unified_pipeline.py`
- `scripts/test_topology.py`
- `CORE_IMPLEMENTATION_PLAN.md`
- `docs/core_wsl2.md`
- `docs/testbed_runbook.md`
- `docs/EVALUATION_PARAMETERS.md`
- `docs/streamlit_cleanup_audit.md` (new)

The five removed files are listed above. Existing modifications to `gui/server.py`,
`gui/web/app.js`, `gui/web/index.html`, `reports/pentest_report.py`,
`testbed/run_store.py`, `scripts/test_report_normalization.py` and the untracked
report service/tests predate this cleanup and were preserved.
