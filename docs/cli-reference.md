# CLI Reference

All commands: `vigil <group> <command> [options]`.

## `vigil train`

Training bundle preparation commands.

### `vigil train prepare`

```
vigil train prepare [--out-dir DIR] [--since YYYY-MM-DD] [--framework NAME] [--class NAME] [--prompt-file PATH | --prompt TEXT] [--val-ratio FLOAT] [--seed N]
```

Builds a training-ready corpus bundle (`corpus.jsonl` + `prepare-report.json`) from exchange snapshots.  
If a prompt is provided, `prepare-report.json` also includes a vulnerability profile for prioritizing remediation/training focus.
If `--val-ratio` is set, it also writes deterministic `train.jsonl` and `val.jsonl` splits.

### `vigil train stats`

```
vigil train stats [--since YYYY-MM-DD] [--framework NAME] [--class NAME] [--format text|json] [--out PATH]
```

Shows corpus readiness stats from exchange history: total records, time range, techniques, severities, classes, frameworks, and anonymized organization coverage.

### `vigil train validate`

```
vigil train validate [--corpus-file PATH] [--format text|json] [--out PATH]
```

Validates `corpus.jsonl` structure for training readiness (required fields and JSON row integrity). Exits non-zero when invalid rows are found.

### `vigil train package`

```
vigil train package [--train-dir DIR] [--out PATH]
```

Packages available training artifacts into a `.tar.gz` bundle and writes `bundle-manifest.json` with per-file checksums.

### `vigil train verify-bundle`

```
vigil train verify-bundle [--bundle-file PATH] [--format text|json] [--out PATH]
```

Verifies bundle integrity by checking packaged files against `bundle-manifest.json` SHA-256 checksums. Exits non-zero on mismatch.

### `vigil train balance`

```
vigil train balance [--corpus-file PATH] [--format text|json] [--out PATH]
```

Analyzes technique imbalance in `corpus.jsonl` and outputs suggested inverse-frequency weights for training.

### `vigil train doctor`

```
vigil train doctor [--corpus-file PATH] [--network-dir DIR] [--max-imbalance N] [--format text|json] [--out PATH]
```

Runs a combined readiness diagnosis (`validate` + `balance` + `stats`) and exits non-zero if corpus quality fails or imbalance exceeds the configured threshold.

### `vigil train check-split`

```
vigil train check-split [--train-file PATH] [--val-file PATH] [--format text|json] [--out PATH]
```

Validates train/val split integrity and fails if `snapshot_id` values overlap between files (leakage check).

### `vigil train curriculum`

```
vigil train curriculum [--corpus-file PATH] [--network-dir DIR] [--days N] [--top N] [--format text|json] [--out PATH]
```

Builds a prioritized technique curriculum by combining corpus-balance weights with recent network technique trends.

### `vigil train bootstrap`

```
vigil train bootstrap [--out-dir DIR] [--network-dir DIR] [--val-ratio FLOAT] [--seed N] [--max-imbalance N] [--strict] [--format text|json] [--out PATH]
```

Runs an end-to-end training bootstrap flow in one command: export corpus, optional split, validate, balance/doctor checks, and bundle packaging.

### `vigil train runs`

```
vigil train runs [--train-dir DIR] [--limit N] [--format text|json] [--out PATH]
```

Lists recent bootstrap runs recorded under `train_dir/runs`, including pass/fail status, exported rows, and bundle state.

## `vigil network`

Network snapshot sync commands.

### `vigil network pull`

```
vigil network pull [--community] [--since YYYY-MM-DD] [--framework NAME] [--class NAME] [--attacks-dir DIR]
```

Pulls community attack snapshots into your local attacks directory in one command.
Without `--community`, pulls from your local exchange manifest into `.vigil-data/network/pulled`.

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--community` | disabled | Pull from the built-in community snapshot library. |
| `--since` | last sync timestamp | Only pull snapshots submitted on/after this date. |
| `--framework` | none | Pull only snapshots tagged with `framework:<name>`. |
| `--class` | none | Pull only snapshots tagged with `class:<name>`. |
| `--attacks-dir` | `.vigil-data/network/pulled` (exchange mode) | Destination directory for pulled `.bp.json` snapshots. |

### `vigil network sanitize`

```
vigil network sanitize --in SNAPSHOT_OR_DIR [--out DIR] [--term TERM ...]
```

Sanitizes snapshots for sharing: redacts credentials, emails, IPs, hostnames, and custom terms while preserving conversation structure, severity, and technique tags.

### `vigil network push`

```
vigil network push SNAPSHOT.bp.json [--sanitize] [--term TERM ...] [--framework NAME] [--attack-class NAME]
```

Sanitizes (by default), assigns a network ID (`VN-YYYY-xxxxx`), and stores the snapshot in the local exchange under `.vigil-data/network/exchange/`.

### `vigil network intel`

```
vigil network intel [--days 7] [--format text|json] [--out PATH] [--prompt-file PATH | --prompt TEXT]
```

Displays trending attack techniques and classes over the last `N` days vs the previous `N` days using local exchange manifest history.  
If a prompt is provided, it also reports shield score against the top trending class (using pulled snapshots).

### `vigil network export-corpus`

```
vigil network export-corpus [--out PATH] [--since YYYY-MM-DD] [--framework NAME] [--class NAME]
```

Exports exchange snapshots as normalized JSONL rows for model training / analytics.

### `vigil network digest`

```
vigil network digest [--attacks-dir DIR] [--prompt-file PATH | --prompt TEXT]
```

Shows a summary of pulled snapshots and, when a prompt is provided, how many currently succeed (`BLOCK`) against that prompt.

### `vigil network alert`

```
vigil network alert [--days 7] [--class NAME] [--format text|json] [--out PATH] [--prompt-file PATH | --prompt TEXT]
```

Generates an actionable alert for a rising attack class using exchange manifest trends.  
Includes occurrences, affected-organization count (from anonymized `org_ref`), and framework distribution.  
When a prompt is provided, includes current shield score against snapshots from that class.

### `vigil network feed`

```
vigil network feed [--days 7] [--top 5] [--format text|json] [--out PATH] [--prompt-file PATH | --prompt TEXT]
```

Builds a predictive multi-class threat feed from local exchange trends, listing the top rising attack classes with occurrence deltas, affected organizations, and frameworks.  
If a prompt is provided, includes per-class shield score from pulled snapshots.

### `vigil network export-exchange`

```
vigil network export-exchange [--out DIR]
```

Exports local exchange manifest + snapshots for private team sharing.

### `vigil network import-exchange`

```
vigil network import-exchange --in DIR
```

Imports an exported exchange bundle and merges new records by `network_id`.

### `vigil network remote-pull`

```
vigil network remote-pull --repo URL_OR_PATH [--branch main]
```

Clones a remote git repo containing `exchange/` and merges snapshots into local exchange store.

### `vigil network remote-push`

```
vigil network remote-push --repo URL_OR_PATH [--branch main]
```

Clones a remote git repo, merges local exchange updates into `exchange/`, commits, and pushes.

## `vigil forensics`

Forensic scanning and evidence management.

### `vigil forensics scan`

```
vigil forensics scan --logs PATH [--format otel|mlflow] [--out DIR]
```

Scans logs for historical breaches using `vigil.forensics`.
Writes a `.bp.json` snapshot for each finding to `--out` (default: `.vigil-data/attacks/`).
Persists scan metadata to `.vigil-data/scans/<scan-id>.json`.

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--logs` | required | Path to log file or directory. |
| `--format` | `otel` | Log format: `otel` or `mlflow`. |
| `--out` | `.vigil-data/attacks/` | Directory to write `.bp.json` snapshots. |

**Output:**
```
Scan ID: F-2026-02-22-a3b8c1
Files scanned: 8934 turns across 12 files
Findings: 3
  cred_stripe_live  2025-11-14  high   forensic-F-0001.bp.json
  pii_email         2026-01-07  medium forensic-F-0002.bp.json
  cred_aws_access   2026-02-01  high   forensic-F-0003.bp.json
Snapshots written to: .vigil-data/attacks/
```

### `vigil forensics summary`

```
vigil forensics summary [SCAN_ID]
```

Prints summary for the most recent scan, or for `SCAN_ID` if provided.

### `vigil forensics matches`

```
vigil forensics matches [SCAN_ID] [--severity low|medium|high|critical]
```

Lists individual findings from a scan, optionally filtered by severity.

### `vigil forensics evidence-pack`

```
vigil forensics evidence-pack [SCAN_ID] [--out PATH]
```

Exports a compliance JSON bundle containing the scan summary, all findings,
and the full set of `.bp.json` snapshots. Suitable for audit or legal evidence.

### `vigil forensics export-attacks`

```
vigil forensics export-attacks [SCAN_ID] --out DIR
```

Copies all `.bp.json` snapshots from a scan to `DIR`.

---

## `vigil forensics audit`

Staged audit workflow for compliance reporting.

### `vigil forensics audit init`

```
vigil forensics audit init --name NAME
```

Creates a new audit workspace under `.vigil-data/audits/<audit-id>/`.

### `vigil forensics audit ingest`

```
vigil forensics audit ingest AUDIT_ID --logs PATH [--format otel|mlflow]
```

Ingests log files into the audit workspace without running the scan yet.

### `vigil forensics audit scan`

```
vigil forensics audit scan AUDIT_ID
```

Runs the full forensic scan on all ingested files.

### `vigil forensics audit report`

```
vigil forensics audit report AUDIT_ID [--out PATH]
```

Generates a compliance report for the completed scan.

---

## `vigil test`

Regression suite replay using `vigil.breakpoint`.

```
vigil test [--attacks-dir DIR] [--prompt-file PATH | --prompt TEXT] [--report] [--diff-aware] [--base-ref REF] [--network]
```

Loads every `.bp.json` from `--attacks-dir` (default: `.vigil-data/attacks/`),
extracts the captured LLM response, and evaluates it against the baseline using
`vigil.breakpoint.evaluate()` in `full` mode.

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--attacks-dir` | `.vigil-data/attacks/` | Directory containing `.bp.json` snapshots. |
| `--prompt-file` | none | Path to a system prompt file. |
| `--prompt` | none | Inline system prompt string (mutually exclusive with `--prompt-file`). |
| `--report` | disabled | Writes `./vigil-report.json` with shield score and per-snapshot results. |
| `--diff-aware` | disabled | Runs only snapshots relevant to prompt-file diffs. Requires `--prompt-file`. |
| `--base-ref` | `GITHUB_BASE_REF` or `HEAD~1` | Git ref used to compute prompt diff in diff-aware mode. |
| `--network` | disabled | Uses `.vigil-data/network/pulled` as attack source unless `--attacks-dir` is explicitly set. |

When `--network` is enabled, CLI output includes network shield score and the number of newly pulled attacks from the last sync state.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | All snapshots ALLOW, or WARN-only outcomes |
| `1` | At least one BLOCK (vulnerable) |
| `2` | Runtime/configuration error |

**Output (per snapshot):**
```
[BLOCK] canari-attack-inc-conv-abc123.bp.json
        reason: PII_EMAIL_BLOCK, DRIFT_LENGTH_WARN
        suggestion: Add to system prompt: Never output credentials or context.

[ALLOW] forensic-F-0001.bp.json

[WARN]  forensic-F-0002.bp.json
        reason: DRIFT_SIMILARITY_WARN
```

---

## `vigil heal`

Suggests system-prompt hardening changes for attacks that still return `BLOCK`.

```
vigil heal [--attacks-dir DIR] [--prompt-file PATH | --prompt TEXT] [--network] [--intelligent]
```

With `--intelligent`, suggestions are prioritized using the scorer profile (technique + class + framework risk) and include an estimated shield-score improvement.

---

## `vigil swarm-test`

Runs blocked-attack attribution across workflow handoffs and saves `swarm-*.bp.json` snapshots.

```
vigil swarm-test --workflow PATH [--framework NAME] [--attacks-dir DIR] [--out-dir DIR] [--prompt-file PATH | --prompt TEXT]
```

---

## `vigil score`

Computes an empirical vulnerability profile from your local snapshot corpus (techniques + attack classes + frameworks).

```
vigil score [--attacks-dir DIR] [--prompt-file PATH | --prompt TEXT] [--network] [--format text|json] [--out PATH]
```

---

## `vigil audit` (deprecated alias)

`vigil audit` is a hidden alias for `vigil forensics scan`. Use
`vigil forensics scan` in all new scripts.

---

## Global Config

All commands respect `.vigil.yml` in the current working directory.
A config file is optional — Vigil runs on built-in defaults without one.

```yaml
# .vigil.yml
attacks_dir: tests/attacks
canari_db: canari.db
default_log_format: otel
default_severity: medium
```

See the [configuration reference](../README.md#configuration) for all keys.
