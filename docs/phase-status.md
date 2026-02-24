# Phase Status

## Overview

| Phase | Name | Status |
|---|---|---|
| 0 | Shared Data Contract | Complete |
| 1 | Forensic Discovery | Complete |
| 2 | Regression Loop | Complete |
| 3 | Dashboard + API | Planned |
| 4 | Community Attack Library | Planned |
| 5 | SaaS / Enterprise | Planned |

---

## Phase 0 — Shared Data Contract

**Goal:** Establish the `.bp.json` format as a stable contract between all components.

| Deliverable | Status |
|---|---|
| `AttackSnapshot` Pydantic model with all spec fields | Complete |
| `snapshot_version`, `origin`, `breakpoint_test`, `forensics` blocks | Complete |
| `save_to_file` / `load_from_file` with `.bp.json` enforcement | Complete |
| Round-trip test coverage (100% on snapshot model) | Complete |
| `vigil_version` in every snapshot | Complete |

---

## Phase 1 — Forensic Discovery

**Goal:** Scan historical logs, find breaches, produce `.bp.json` snapshots.

| Deliverable | Status |
|---|---|
| `VigilForensicsWrapper` wrapping canari-forensics | Complete |
| OTEL parser support | Complete |
| MLflow Gateway parser support | Complete |
| Tier 1 (Canari synthetic tokens) — 8 patterns | Complete |
| Tier 2 (Real credentials: Stripe, AWS, GitHub, OpenAI, Slack, SendGrid, Google) — 15 patterns | Complete |
| Tier 3 (PII: email, phone, SSN, credit card) — 5 patterns | Complete |
| Supplementary (prompt injection indicators) — 2 patterns | Complete |
| `vigil forensics scan` CLI command | Complete |
| `vigil forensics summary / matches / evidence-pack / export-attacks` | Complete |
| `vigil forensics audit` (init / ingest / scan / report) | Complete |
| Scan-ID persistence under `.vigil-data/scans/` | Complete |
| `canari export-attack` CLI command (in canari repo) | Complete |

---

## Phase 2 — Regression Loop

**Goal:** Close the feedback loop — every snapshot becomes a regression test.

| Deliverable | Status |
|---|---|
| `VigilBreakPointRunner` with correct evaluate() semantics | Complete |
| BreakPoint called in `full` mode (red-team + PII policies active) | Complete |
| Baseline resolution: `breakpoint_test.baseline.output` → system prompt → safe default | Complete |
| `vigil test` CLI command (exit codes 0/1/2) | Complete |
| `VigilCanariWrapper` writing assistant output into `attack.conversation` | Complete |
| All exporter `AttackSnapshot` fields populated (origin, breakpoint_test, forensics) | Complete |
| Replayer helper functions (`_extract_user_input`, `_extract_assistant_output`, `_build_baseline`) | Complete |
| Test suite (snapshot format: 23 tests, exporter: 11, replayer: 16) — 50/50 passing | Complete |
| `vigil/src/vigil/__init__.py` public API surface | Complete |

---

## Phase 3 — Dashboard + API (Planned)

**Goal:** Web-visible forensics dashboard and REST API for CI consumption.

Planned deliverables:
- `vigil serve-dashboard` — local HTTP dashboard for scan results
- `vigil serve-api` — REST API for BreakPoint results and snapshot library
- API key auth and RBAC (reader / admin)
- Real-time Canari alert feed in dashboard
- Scan result deduplication across runs

---

## Phase 4 — Community Attack Library (Planned)

**Goal:** Shared repository of `.bp.json` attack snapshots.

Planned deliverables:
- `vigil community pull` — download new attack snapshots from the library
- `vigil community push` — opt-in upload of anonymised snapshots
- Community library browser in dashboard
- Severity triage workflow for community submissions

---

## Phase 5 — SaaS / Enterprise (Planned)

**Goal:** Managed Vigil with multi-tenant support and enterprise SSO.

Planned deliverables:
- Hosted snapshot storage
- Tenant-scoped scan history
- Enterprise SSO (SAML/OIDC)
- SOC2 evidence pack generation
- Webhook delivery for BLOCK results
