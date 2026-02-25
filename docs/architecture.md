# Architecture

Vigil is a self-contained LLM safety platform. It internalizes three tools —
**Canari** (live detection), **Canari Forensics** (log scanning), and **BreakPoint**
(CI gate) — and connects them through a shared data format and a unified CLI.

## Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                        vigil (this repo)                        │
│                                                                 │
│  vigil.models           .bp.json schema (shared contract)       │
│  vigil.canari           Canari runtime IDS (live detection)     │
│  vigil.breakpoint       BreakPoint policy suite (CI gate)       │
│  vigil.forensics        log scanner + pattern library           │
│  vigil.loop.exporter    Canari alert  → .bp.json                │
│  vigil.loop.replayer    .bp.json      → vigil.breakpoint.eval() │
│  vigil.forensics.engine log file      → .bp.json                │
│  vigil.cli              `vigil` CLI entry point                 │
│  vigil.config           .vigil.yml loader                       │
└─────────────────────────────────────────────────────────────────┘
```

## Package Roles

### `vigil.models`

Defines the `.bp.json` snapshot format as Pydantic v2 models. Every other
component either reads or writes this format. The models are the contract
between the three tools.

Key classes: `AttackSnapshot`, `SnapshotMetadata`, `SnapshotOrigin`,
`Canary`, `Attack`, `BreakPointTest`, `ForensicsProvenance`.

### `vigil.canari`

Internalized Canari runtime IDS. Provides `CanariClient`, `CanaryGenerator`,
`OutputScanner`, `AlertDispatcher`, `IncidentManager`, and framework
integrations (OpenAI patch, LangChain/LlamaIndex wrappers). Used directly
by `vigil.loop.exporter`.

### `vigil.breakpoint`

Internalized BreakPoint policy suite. Exposes a single `evaluate()` entry
point that runs PII, red-team, drift, cost, latency, and output-contract
policies against a baseline/candidate pair. Used directly by
`vigil.loop.replayer`.

### `vigil.forensics`

Internalized canari-forensics log scanner. Contains parsers (OTEL, MLflow,
JSONL, LangSmith, Langfuse, plain), the 27-pattern library, and the
`ForensicScanner` + `VigilForensicsWrapper` that convert findings into
`.bp.json` snapshots.

### `vigil.loop.exporter`

`VigilCanariWrapper` wraps `vigil.canari.CanariClient`. On each
`process_turn()` call it runs the LLM output through the canari scanner.
If a canary fires it serialises the full exchange — system prompt, user
input, and assistant response — into a `.bp.json` file and returns the path.

### `vigil.loop.replayer`

`VigilBreakPointRunner` loads every `.bp.json` in a directory, extracts the
assistant response captured at the time of the attack, and evaluates it
against a known-safe baseline using `vigil.breakpoint.evaluate()` in `full`
mode.

`full` mode activates the red-team and PII policies in addition to cost/drift,
giving the broadest possible safety signal for attack replay.

### `vigil.forensics.engine`

`VigilForensicsWrapper` is the public entry point to `vigil.forensics`. It
parses a log file or directory with the appropriate parser (OTEL or MLflow),
runs `detect_findings` against the 27-pattern library, and converts each
`Finding` into an `AttackSnapshot` `.bp.json` file.

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
                       vigil.forensics
                        detect_findings
                              │
                              ▼
                        .bp.json files
                              │
                              ▼
                  vigil.breakpoint replay
```

## Dependency Graph

```
vigil
  ├── vigil.canari        (Canari runtime IDS — live detection)
  ├── vigil.forensics     (canari-forensics scanner — historical scanning)
  └── vigil.breakpoint    (BreakPoint policy suite — CI gate)

vigil.loop
  ├── exporter   uses vigil.canari
  ├── replayer   uses vigil.breakpoint
  └── library    ships community .bp.json patterns
```

Vigil is self-contained — `vigil.canari`, `vigil.forensics`, and
`vigil.breakpoint` are internalized modules that mirror the three ecosystem
packages (canari-llm, canari-forensics, breakpoint-ai). Each can also be used
as a standalone package independently of vigil.

- The `canari export-attack` CLI command in the canari package produces
  `.bp.json` files inline (without importing vigil) to preserve this boundary.

## Scan-ID Persistence

`vigil forensics scan` stores scan metadata under `.vigil-data/scans/<scan-id>.json`.
Audit workspaces are stored under `.vigil-data/audits/<audit-id>/`.
These directories are created automatically and are local-only.

## Pattern Library Tiers

`vigil.forensics` ships with a four-tier pattern library used by
`VigilForensicsWrapper`:

| Tier | Kind | Count |
|---|---|---|
| 1 | Canari synthetic token formats | 8 |
| 2 | Real credentials (Stripe, AWS, GitHub, OpenAI, Slack, SendGrid, Google) | 15 |
| 3 | PII (email, phone, SSN, credit cards) | 5 |
| Supplementary | Prompt injection indicators | 2 |

Custom patterns can be appended at runtime via `load_pattern_pack()`.
