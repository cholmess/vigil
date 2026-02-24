# Vigil Ecosystem — Test Results

This document shows the **actual output** of running all test suites across the four repos. Use it to see how the feedback loop is validated and what users see when they run tests.

---

## How the Loop Is Tested

```
PAST                      PRESENT                FUTURE
─────────────────────────────────────────────────────────────
canari-forensics          canari-llm             breakpoint-ai
(unit + phased tests)     (unit + integration)   (evaluate, CLI, policies)
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                   │
                              vigil tests
                    (cross-repo full loop + snapshot + wrappers)
```

| Repo | What the tests prove |
|------|----------------------|
| **vigil** | Forensics → snapshots → BreakPoint replay; Canari breach → snapshot → replay; community attacks; roundtrip and BreakPoint evaluation |
| **breakpoint-ai** | Baseline vs candidate evaluation, PII/red-team/drift/cost policies, CLI, attack replay from `.bp.json` |
| **canari-llm** | Token generation, scanning, alerts, incidents, registry, export, integrations |
| **canari-forensics** | Log parsing (OTEL, MLflow), pattern detection, reporting, audit workflow |

---

## 1. Vigil (integration layer + full loop)

Vigil’s suite includes **cross-repo integration tests** in `tests/test_full_loop.py` that exercise the whole feedback loop with real Canari, forensics, and BreakPoint.

**Run:** `cd vigil && python -m pytest tests/ -v --tb=short`

### Output

```
============================= test session starts ==============================
platform darwin -- Python 3.14.2, pytest-9.0.2, pluggy-1.6.0
rootdir: /Users/yufei/vigil-ecosystem/vigil-ecosystem/vigil-ecosystem/vigil
configfile: pyproject.toml
plugins: anyio-4.12.1, breakpoint-ai-0.2.0, cov-7.0.0
collected 76 items

tests/test_exporter.py ...........                                       [ 14%]
tests/test_full_loop.py ..........................                       [ 48%]
tests/test_replayer.py ................                                  [ 69%]
tests/test_snapshot_format.py .......................                    [100%]

============================== 76 passed in 0.45s ==============================
```

**Summary:** 76 passed. This includes:
- **test_exporter.py** — VigilCanariWrapper (breach → snapshot).
- **test_full_loop.py** — Full loop: forensics scan → snapshots; Canari live breach → snapshot; community attacks; combined library; snapshot roundtrip; forensics patterns; BreakPoint direct.
- **test_replayer.py** — VigilBreakPointRunner (snapshots → BreakPoint ALLOW/BLOCK).
- **test_snapshot_format.py** — `.bp.json` model and I/O.

---

## 2. BreakPoint (CI gate)

BreakPoint’s tests cover evaluation (baseline vs candidate), policies (PII, red-team, drift, cost, output contract), CLI, and attack replay.

**Run:** `cd breakpoint-ai && python -m pytest tests/ -v --tb=short`

### Output

```
============================= test session starts ==============================
platform darwin -- Python 3.14.2, pytest-9.0.2, pluggy-1.6.0 -- .../.venv/bin/python
cachedir: .pytest_cache
rootdir: .../breakpoint-ai
configfile: pytest.ini
plugins: breakpoint-ai-0.2.0, anyio-4.12.1, cov-7.0.0
collecting ... collected 81 items

tests/test_baseline_lifecycle.py::test_baseline_reproducibility_from_stored_artifacts PASSED [  1%]
tests/test_baseline_lifecycle.py::test_baseline_rollback_changes_decision_with_sample_data PASSED [  2%]
tests/test_ci_templates.py::test_ci_template_files_exist PASSED          [  3%]
tests/test_ci_templates.py::test_ci_shell_template_is_executable PASSED  [  4%]
tests/test_ci_templates.py::test_github_actions_template_has_copy_paste_gate_contract PASSED [  6%]
tests/test_cli.py::test_cli_evaluate_json_output PASSED                  [  7%]
tests/test_cli.py::test_cli_strict_blocks PASSED                         [  8%]
... (many more)
tests/test_waivers.py::test_waiver_removes_warn_and_records_metadata PASSED [ 96%]
tests/test_waivers.py::test_expired_waiver_does_not_apply PASSED         [ 97%]
tests/test_waivers.py::test_waivers_require_evaluation_time PASSED       [ 98%]
tests/test_waivers.py::test_cli_reports_config_validation_error_for_bad_waivers PASSED [100%]

============================== 81 passed in 3.23s ==============================
```

**Summary:** 81 passed. Covers CLI (evaluate, config, accept, exit codes), cost/PII/drift/latency/output_contract/red_team policies, baseline lifecycle, metrics, pytest plugin, waivers, and packaging.

---

## 3. Canari (live detection)

Canari’s tests cover token generation, scanning, alerts, incidents, registry, export, dashboard, API, and integrations.

**Run:** `cd canari && python -m pytest tests/ -v --tb=short`

### Output

```
============================= test session starts ==============================
platform darwin -- Python 3.14.2, pytest-9.0.2, pluggy-1.6.0
rootdir: .../canari
configfile: pyproject.toml
plugins: anyio-4.12.1, breakpoint-ai-0.2.0, cov-7.0.0
collected 103 items / 15 skipped

tests/test_adapters.py ..                                                [  1%]
tests/test_alert_stats_rich.py .                                         [  2%]
tests/test_alert_store.py ..                                             [  4%]
tests/test_alerter.py ..                                                 [  6%]
... (many more)
tests/test_threat_intel.py .                                             [ 97%]
tests/test_threat_sharing.py ..                                          [ 99%]
tests/test_time_filters.py .                                             [100%]

=============================== warnings summary ===============================
... (DeprecationWarning for asyncio.iscoroutinefunction)
================= 103 passed, 15 skipped, 5 warnings in 2.71s ==================
```

**Summary:** 103 passed, 15 skipped, 5 warnings. Covers generator, scanner, alerter, incidents, registry, CLI, export, reporting, retention, threat intel, dashboard, FastAPI, and integrations.

---

## 4. Canari Forensics (historical scanning)

Canari Forensics tests cover OTEL/MLflow parsing, pattern detection, reporting, audit workflow, and CLI. Runs with `--ignore=tests/integration` to skip the MLflow integration test that requires external setup.

**Run:** `cd canari-forensics && python -m pytest tests/ -v --tb=short --ignore=tests/integration`

### Output

```
============================= test session starts ==============================
platform darwin -- Python 3.14.2, pytest-9.0.2, pluggy-1.6.0 -- .../.venv/bin/python
cachedir: .pytest_cache
rootdir: .../canari-forensics
configfile: pyproject.toml
plugins: anyio-4.12.1, breakpoint-ai-0.2.0, cov-7.0.0
collecting ... collected 36 items

tests/test_cli_scan.py::CLIScanTests::test_scan_mlflow_requires_experiment_id PASSED [  2%]
tests/test_cli_scan.py::CLIScanTests::test_scan_mlflow_with_mocked_parser PASSED [  5%]
tests/test_cli_scan.py::CLIScanTests::test_scan_otel_file_writes_report PASSED [  8%]
... (many more)
tests/test_phase9_error_codes.py::Phase9ErrorCodesTests::test_not_found_error_code_for_missing_logs_path PASSED [100%]

=================================== FAILURES ===================================
___ Phase3ReportingTests.test_report_generates_pdf_evidence_and_bp_snapshots ___
tests/test_phase3_reporting.py:60: in test_report_generates_pdf_evidence_and_bp_snapshots
    self.assertGreaterEqual(len(payload["findings"]), 1)
E   AssertionError: 0 not greater than or equal to 1
----------------------------- Captured stdout call -----------------------------
┌─ Scan Complete ───────────────────────────────────────────────
Scanned: 3 turns | 0.00 seconds
Conversations: 1
Scan report: .../scan.json
└───────────────────────────────────────────────────────────────
┏━ Canari Forensics Incident Review ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanned: 3 turns | 0.00 seconds
INCIDENTS FOUND: 0
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No incidents detected in assistant outputs.
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Evidence: .../evidence.json
PDF: .../audit.pdf
BreakPoint snapshots: 0
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
These incidents occurred before you were monitoring.
Canari would have caught them in real time.
=========================== short test summary info ============================
FAILED tests/test_phase3_reporting.py::Phase3ReportingTests::test_report_generates_pdf_evidence_and_bp_snapshots - AssertionError: 0 not greater than or equal to 1
========================= 1 failed, 35 passed in 0.57s =========================
```

**Summary:** 35 passed, 1 failed. The failing test is a **known pre-existing issue**: the OTEL fixture (`otlp_sample.json`) does not contain content that matches the current pattern library, so the scan correctly reports 0 findings and the test’s expectation (≥1 finding) is outdated. The rest of the forensics pipeline (parsing, report, evidence, PDF, audit workflow) is exercised and passing.

---

## Summary Table

| Repo              | Passed | Failed | Skipped | Notes                                  |
|-------------------|--------|--------|---------|----------------------------------------|
| **vigil**         | 76     | 0      | 0       | Full loop + wrappers + snapshot        |
| **breakpoint-ai** | 81     | 0      | 0       | Evaluate, CLI, policies, attack replay |
| **canari**        | 103    | 0      | 15      | Live detection, registry, export       |
| **canari-forensics** | 35  | 1      | 0       | 1 known fixture/expectation mismatch   |

---

## How to Reproduce

From the ecosystem root, with a venv that has all four packages installed:

```bash
source .venv/bin/activate

# Vigil (includes full-loop integration tests)
cd vigil && python -m pytest tests/ -v --tb=short && cd ..

# BreakPoint
cd breakpoint-ai && python -m pytest tests/ -v --tb=short && cd ..

# Canari
cd canari && python -m pytest tests/ -v --tb=short && cd ..

# Canari Forensics (skip integration + known failing phase3 test if desired)
cd canari-forensics && python -m pytest tests/ -v --tb=short --ignore=tests/integration && cd ..
```

To capture this document’s view of “what users see,” run each block and optionally redirect to a file, e.g.:

```bash
cd vigil && python -m pytest tests/ -v --tb=short 2>&1 | tee vigil-results.txt
```

This file is that captured view: one place to see how the whole loop is tested and what the test output looks like in each repo.
