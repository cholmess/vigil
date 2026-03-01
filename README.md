# vigil

Close the loop between detecting an LLM attack and making sure it never works again.

Most teams find out about a prompt injection weeks after it happened — if ever. The attacker asked the model to dump its context. The model complied. The response looked like a normal API call. No firewall flagged it. By the time anyone noticed, the system prompt, internal configuration, and synthetic credentials had already been exfiltrated.

Even teams that do detect attacks in real time rarely close the loop. They patch the system prompt, ship the fix, and move on. There is no record of what the attack looked like, no automated test that verifies the patch held, and no gate that catches the same vulnerability resurfacing in the next refactor.

Vigil fixes this. It bundles three capabilities into a single feedback loop:

| Module | What it does | When |
|---|---|---|
| `vigil.canari` | Injects honeypot tokens into LLM context and detects when they leak | Real time |
| `vigil.forensics` | Scans historical LLM logs for credential leaks and PII exfiltration | Historical |
| `vigil.breakpoint` | Replays captured attacks against the current system prompt and blocks regressions | Every deploy |

Every attack `vigil.canari` catches becomes a `.bp.json` snapshot. Every finding `vigil.forensics` surfaces becomes a `.bp.json` snapshot. Every snapshot becomes a `vigil.breakpoint` regression test. Every deploy is gated against the full history of known attacks. The system gets harder to attack every time it is attacked.

## Install

```bash
pip install vigil
```

Or from source:

```bash
pip install -e .
```

## Quick start

```bash
# 1) Scan historical logs for past breaches
vigil forensics scan \
  --logs ./logs/ \
  --format otel \
  --attacks-dir ./tests/attacks/

# (Week 2) Pull seed community attacks in one command
vigil network pull --community

# (Phase 2) Sanitize and submit snapshots to the local exchange
vigil network sanitize --in ./tests/attacks --out ./.vigil-data/network/sanitized --term Acme
vigil network push ./.vigil-data/network/sanitized/inc-abc123.bp.json --framework langchain --attack-class tool-result-injection
vigil network pull --since 2026-01-01 --framework langchain --class tool-result-injection
vigil network intel --days 7 --prompt-file system_prompt.txt
vigil network intel --format json --out ./.vigil-data/network/intel/latest.json
vigil network alert --days 7 --prompt-file system_prompt.txt
vigil network alert --format json --out ./.vigil-data/network/intel/alert.json
vigil network feed --days 7 --top 5
vigil network feed --format json --out ./.vigil-data/network/intel/feed.json
vigil network feed --prompt-file system_prompt.txt
vigil network export-corpus --out ./.vigil-data/network/corpus/corpus.jsonl
vigil network digest --prompt-file system_prompt.txt
vigil network export-exchange --out ./.vigil-data/network/export
vigil network import-exchange --in ./.vigil-data/network/export
vigil network remote-push --repo git@github.com:your-org/vigil-exchange.git
vigil network remote-pull --repo git@github.com:your-org/vigil-exchange.git
vigil train prepare --out-dir ./.vigil-data/train
vigil train prepare --out-dir ./.vigil-data/train --prompt-file system_prompt.txt
vigil train prepare --out-dir ./.vigil-data/train --val-ratio 0.2 --seed 42
vigil train stats --format json --out ./.vigil-data/train/stats.json
vigil train validate --corpus-file ./.vigil-data/train/corpus.jsonl
vigil train package --train-dir ./.vigil-data/train --out ./.vigil-data/train/train-bundle.tar.gz
vigil train verify-bundle --bundle-file ./.vigil-data/train/train-bundle.tar.gz
vigil train balance --corpus-file ./.vigil-data/train/corpus.jsonl
vigil train doctor --corpus-file ./.vigil-data/train/corpus.jsonl --max-imbalance 5
vigil train check-split --train-file ./.vigil-data/train/train.jsonl --val-file ./.vigil-data/train/val.jsonl
vigil train curriculum --corpus-file ./.vigil-data/train/corpus.jsonl --network-dir ./.vigil-data/network --days 30 --top 5
vigil train bootstrap --out-dir ./.vigil-data/train --network-dir ./.vigil-data/network --val-ratio 0.2 --strict

# 2) Test current system prompt against every known attack
vigil test --prompt-file system_prompt.txt
# → BLOCK: still vulnerable
vigil test --network --prompt-file system_prompt.txt

# Suggest hardening changes for blocked attacks
vigil heal --prompt-file system_prompt.txt
vigil heal --intelligent --prompt-file system_prompt.txt

# Multi-agent (swarm) attribution test
vigil swarm-test \
  --workflow ./workflows/research_agent.py \
  --framework langgraph \
  --prompt-file system_prompt.txt \
  --attacks-dir ./tests/attacks

# Empirical vulnerability scoring (technique/class/framework)
vigil score --prompt-file system_prompt.txt
vigil score --prompt-file system_prompt.txt --format json --out ./.vigil-data/train/score.json

# Week 3: diff-aware mode (fast CI loop)
vigil test --prompt-file system_prompt.txt --diff-aware
# → runs only snapshots relevant to prompt diff

# 3) Harden — read the hardening_suggestion in the snapshot, edit system_prompt.txt

# 4) Verify
vigil test --prompt-file system_prompt.txt
# → ALLOW: hardened

# Optional: machine-readable CI artifact
vigil test --prompt-file system_prompt.txt --report
# → writes ./vigil-report.json

# 5) Commit the snapshot as a permanent regression test
git add system_prompt.txt tests/attacks/
git commit -m "harden prompt against context dump (inc-conv-abc123)"
git push
# → CI runs full suite → green
```

## GitHub Action (local)

Use the local action in this repository:

```yaml
name: LLM Safety Gate
on: [pull_request]

jobs:
  vigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ./.github/actions/vigil-test
        with:
          prompt-file: system_prompt.txt
          attacks-dir: tests/attacks
          report: "true"
          diff-aware: "true"
```

A ready-to-use workflow is also included at `.github/workflows/vigil.yml`.

## Forensic audit workflow

```bash
# Initialize a named audit workspace
vigil forensics audit init --name "Q1 2026 Audit" --client "Acme Corp" --application "AI Gateway"

# Ingest one or more log sources
vigil forensics audit ingest --audit-id <audit-id> --source ./logs/prod/ --label "Production"
vigil forensics audit ingest --audit-id <audit-id> --source ./logs/staging/ --label "Staging"

# Scan all ingested sources
vigil forensics audit scan --audit-id <audit-id>

# Generate compliance report and evidence pack
vigil forensics audit report --audit-id <audit-id> --format json
```

## Export a live Canari incident

```bash
canari --db canari.db export-attack \
  --incident inc-conv-abc123 \
  --out ./tests/attacks/

vigil test --attacks-dir ./tests/attacks/ --prompt-file system_prompt.txt
```

## Python API

```python
from vigil.loop.exporter import VigilCanariWrapper
from vigil.loop.scanner import CanariScanner

scanner = CanariScanner()
wrapper = VigilCanariWrapper(scanner=scanner)
snap_path = wrapper.process_turn(system_prompt=SYSTEM_PROMPT, user_input=user_message, llm_output=assistant_response)
if snap_path: print(f"Attack snapshot: {snap_path}")
```

```python
from vigil import VigilForensicsWrapper

scanner = VigilForensicsWrapper(attacks_dir="./tests/attacks/", log_format="otel")
result = scanner.run_audit(log_path="./logs/")
print(f"Findings: {result.finding_count}")
```

```python
from vigil import VigilBreakPointRunner

runner = VigilBreakPointRunner(
    attacks_dir="./tests/attacks/",
    current_system_prompt=open("system_prompt.txt").read(),
)
results = runner.run_regression_suite()
if any(r.status == "BLOCK" for r in results):
    raise SystemExit(2)
```

## Docs

- [Architecture](docs/architecture.md) — module structure and data flow
- [The Feedback Loop](docs/loop.md) — the full loop explained
- [Snapshot Format](docs/snapshot-format.md) — `.bp.json` field contract
- [CLI Reference](docs/cli-reference.md) — all `vigil` commands
- [Forensics](docs/forensics.md) — pattern library, log formats, evidence pack
- [Integration Guide](docs/integration-guide.md) — Python API usage
- [Quickstart](docs/quickstart.md) — 10-minute walkthrough

Framework examples:

- [examples/frameworks/README.md](examples/frameworks/README.md)

## Related Tools

- [BreakPoint](https://github.com/cholmess/breakpoint-ai) — catch regressions before you ship
- [Canari](https://github.com/cholmess/canari) — detect attacks in real time
- [Canari Forensics](https://github.com/cholmess/canari-forensics) — audit logs for past breaches

## Maintainer

Maintained by Christopher Holmes Silva.

- X: https://x.com/cholmess
- LinkedIn: https://linkedin.com/in/cholmess

Feedback is welcome from developers shipping LLM applications.
