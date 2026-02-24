# Architecture

Vigil is an integration layer. It owns no detection logic of its own — it connects three
existing tools through a shared data format and a unified CLI.

## Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                        vigil (this repo)                        │
│                                                                 │
│  vigil.models          .bp.json schema (shared contract)        │
│  vigil.loop.exporter   Canari alert  → .bp.json                 │
│  vigil.loop.replayer   .bp.json      → BreakPoint evaluate()    │
│  vigil.forensics.engine log file     → .bp.json                 │
│  vigil.cli             `vigil` CLI entry point                  │
│  vigil.config          .vigil.yml loader                        │
└───────────┬─────────────────┬──────────────────┬───────────────┘
            │                 │                  │
            ▼                 ▼                  ▼
     canari-llm         canari-forensics    breakpoint-ai
  (runtime IDS)        (log scanner)       (CI gate)
```

## Package Roles

### `vigil.models`

Defines the `.bp.json` snapshot format as Pydantic v2 models. Every other
component either reads or writes this format. The models are the contract
between the three tools.

Key classes: `AttackSnapshot`, `SnapshotMetadata`, `SnapshotOrigin`,
`Canary`, `Attack`, `BreakPointTest`, `ForensicsProvenance`.

### `vigil.loop.exporter`

`VigilCanariWrapper` wraps a `CanariClient`. On each `process_turn()` call it
runs the LLM output through Canari's scanner. If a canary fires it serialises
the full exchange — system prompt, user input, and assistant response — into
a `.bp.json` file and returns the path.

Dependency: `canari-llm` (`CanariClient.scan_output`).

### `vigil.loop.replayer`

`VigilBreakPointRunner` loads every `.bp.json` in a directory, extracts the
assistant response captured at the time of the attack, and evaluates it
against a known-safe baseline using BreakPoint's `evaluate()` in `full` mode.

`full` mode activates the red-team and PII policies in addition to cost/drift,
giving the broadest possible safety signal for attack replay.

Dependency: `breakpoint-ai` (`breakpoint.evaluate`).

### `vigil.forensics.engine`

`VigilForensicsWrapper` wraps `canari-forensics`. It parses a log file or
directory with the appropriate parser (OTEL or MLflow), runs `detect_findings`
against the 27-pattern library, and converts each `Finding` into a
`AttackSnapshot` `.bp.json` file.

Dependency: `canari-forensics` (`OTELParser`, `MLflowGatewayParser`,
`detect_findings`).

### `vigil.cli`

Typer CLI with two top-level command groups:

- `vigil forensics` — scan, summary, matches, evidence-pack, export-attacks,
  audit (init / ingest / scan / report)
- `vigil test` — regression suite replay

Config is resolved in priority order: CLI flag → `.vigil.yml` → built-in
default.

### `vigil.config`

YAML loader for `.vigil.yml`. Validated with Pydantic v2. Returns all defaults
when the file is absent — vigil runs without any config file.

## Data Flow

```
                         PRODUCTION
                         ──────────
LLM app  ──(output)──► VigilCanariWrapper
                              │
                         canary fires?
                              │
                              ▼
                        .bp.json file
                              │
              ┌───────────────┼──────────────────┐
              │               │                  │
              ▼               ▼                  ▼
         git commit      vigil test          CI pipeline
                        (local check)      (full suite)


                         HISTORICAL
                         ──────────
log files ──────────► VigilForensicsWrapper
                              │
                       canari-forensics
                        detect_findings
                              │
                              ▼
                        .bp.json files
                              │
                              ▼
                      BreakPoint replay
```

## Dependency Graph

```
vigil
  ├── canari-llm          (runtime detection)
  ├── canari-forensics    (historical scanning)
  └── breakpoint-ai       (evaluation engine)

canari-llm          (no vigil dependency)
canari-forensics    (no vigil dependency)
breakpoint-ai       (no vigil dependency)
```

The dependency graph is intentionally one-directional. Vigil depends on all
three tools; none of them depend on vigil. This means:

- canari, canari-forensics, and breakpoint-ai can be used independently.
- vigil is the integration layer only — it adds no new detection logic.
- The `canari export-attack` CLI command in the canari package produces
  `.bp.json` files inline (without importing vigil) to preserve this boundary.

## Scan-ID Persistence

`vigil forensics scan` stores scan metadata under `.vigil-data/scans/<scan-id>.json`.
Audit workspaces are stored under `.vigil-data/audits/<audit-id>/`.
These directories are created automatically and are local-only.

## Pattern Library Tiers

canari-forensics ships with a four-tier pattern library used by
`VigilForensicsWrapper`:

| Tier | Kind | Count |
|---|---|---|
| 1 | Canari synthetic token formats | 8 |
| 2 | Real credentials (Stripe, AWS, GitHub, OpenAI, Slack, SendGrid, Google) | 15 |
| 3 | PII (email, phone, SSN, credit cards) | 5 |
| Supplementary | Prompt injection indicators | 2 |

Custom patterns can be appended at runtime via `load_pattern_pack()`.
