# Vigil

![CI](https://github.com/cholmess/vigil/actions/workflows/vigil.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/vigil-llm)](https://pypi.org/project/vigil-llm/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Community Attacks](https://img.shields.io/badge/community%20attacks-50%20snapshots-green)](https://github.com/cholmess/vigil-community-attacks)

**LLM security regression testing and forensic audit — open source.**

Close the loop between detecting a prompt injection attack and making sure it never works again.

---

## The problem

Most teams find out about a prompt injection weeks after it happened — if ever. The attacker asked the model to dump its context. The model complied. The response looked like a normal API call. No firewall flagged it.

Even teams that do detect attacks rarely close the loop. They patch the system prompt, ship the fix, and move on. There is no record of what the attack looked like, no automated test that verifies the patch held, and no gate that catches the same vulnerability resurfacing in the next refactor.

**Vigil fixes this.**

---

## Quick start

```bash
pip install vigil-llm

# Pull 50 real-world attack patterns from the community library
vigil network pull --community

# Run them against your system prompt
vigil test --prompt-file system_prompt.txt --report
```

If any snapshot triggers, you have a vulnerability. Fix the prompt, rerun, commit the snapshot as a permanent CI gate.

---

## How it works

Vigil bundles three capabilities into a single feedback loop:

| Module | What it does | When |
|---|---|---|
| `vigil.canari` | Injects honeypot tokens into LLM context and detects when they leak | Real time |
| `vigil.forensics` | Scans historical LLM logs for credential leaks and PII exfiltration | Historical |
| `vigil.breakpoint` | Replays captured attacks against the current system prompt and blocks regressions | Every deploy |

Every attack `vigil.canari` catches becomes a `.bp.json` snapshot. Every finding `vigil.forensics` surfaces becomes a `.bp.json` snapshot. Every snapshot becomes a `vigil.breakpoint` regression test. Every deploy is gated against the full history of known attacks.

**The system gets harder to attack every time it is attacked.**

---

## The feedback loop

```
Attack detected (Canari)
        ↓
Snapshot created (.bp.json)
        ↓
Snapshot committed to repo
        ↓
BreakPoint runs on every PR
        ↓
Vulnerability can never silently return
```

---

## Community attack library

50 real-world attack snapshots sourced from published security research — ready to pull in one command.

```bash
vigil network pull --community
```

Covers: direct injection, indirect RAG injection, prompt leakage, multi-turn manipulation, agent hijacking, tool injection, jailbreaks.

→ [vigil-community-attacks](https://github.com/cholmess/vigil-community-attacks)

---

## GitHub Actions — CI gate in 5 lines

```yaml
# .github/workflows/vigil.yml
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

---

## Full CLI reference

```bash
# Forensics — scan historical logs for past attacks
vigil forensics scan \
  --logs ./logs/ \
  --format otel \
  --attacks-dir ./tests/attacks/

# Forensic audit workflow (full evidence pack)
vigil forensics audit init --name "Q1 2026 Audit" --client "Acme Corp" --application "AI Gateway"
vigil forensics audit ingest --audit-id <id> --source ./logs/prod/ --label "Production"
vigil forensics audit scan --audit-id <id>
vigil forensics audit report --audit-id <id> --format json

# Test current system prompt against all known attacks
vigil test --prompt-file system_prompt.txt
vigil test --prompt-file system_prompt.txt --report
vigil test --prompt-file system_prompt.txt --diff-aware     # CI fast path
vigil test --network --prompt-file system_prompt.txt

# Hardening suggestions
vigil heal --prompt-file system_prompt.txt
vigil heal --intelligent --prompt-file system_prompt.txt

# Vulnerability scoring
vigil score --prompt-file system_prompt.txt
vigil score --prompt-file system_prompt.txt --format json --out ./score.json

# Multi-agent (swarm) testing
vigil swarm-test \
  --workflow ./workflows/research_agent.py \
  --framework langgraph \
  --prompt-file system_prompt.txt \
  --attacks-dir ./tests/attacks

# Network — community attack exchange
vigil network pull --community
vigil network pull --since 2026-01-01 --framework langchain --class tool-result-injection
vigil network push <snapshot.bp.json> --framework langchain --attack-class tool-result-injection
vigil network intel --days 7 --prompt-file system_prompt.txt
vigil network alert --days 7 --prompt-file system_prompt.txt
vigil network feed --days 7 --top 5
vigil network digest --prompt-file system_prompt.txt

# Training pipeline
vigil train prepare --out-dir ./.vigil-data/train --val-ratio 0.2 --seed 42
vigil train stats
vigil train validate --corpus-file ./.vigil-data/train/corpus.jsonl
vigil train balance --corpus-file ./.vigil-data/train/corpus.jsonl
vigil train doctor --corpus-file ./.vigil-data/train/corpus.jsonl
vigil train curriculum --corpus-file ./.vigil-data/train/corpus.jsonl --days 30
vigil train bootstrap --out-dir ./.vigil-data/train --strict
vigil train package --train-dir ./.vigil-data/train --out ./train-bundle.tar.gz
vigil train verify-bundle --bundle-file ./train-bundle.tar.gz
vigil train runs --limit 10
```

---

## Export a live Canari incident as a snapshot

```bash
canari --db canari.db export-attack \
  --incident inc-conv-abc123 \
  --out ./tests/attacks/

vigil test --attacks-dir ./tests/attacks/ --prompt-file system_prompt.txt
```

---

## Python API

```python
# Real-time detection
from vigil.loop.exporter import VigilCanariWrapper
from vigil.loop.scanner import CanariScanner

scanner = CanariScanner()
wrapper = VigilCanariWrapper(scanner=scanner)
snap_path = wrapper.process_turn(
    system_prompt=SYSTEM_PROMPT,
    user_input=user_message,
    llm_output=assistant_response
)
if snap_path:
    print(f"Attack snapshot: {snap_path}")

# Historical forensics
from vigil import VigilForensicsWrapper

scanner = VigilForensicsWrapper(
    attacks_dir="./tests/attacks/",
    log_format="otel"
)
result = scanner.run_audit(log_path="./logs/")
print(f"Findings: {result.finding_count}")

# Regression testing
from vigil import VigilBreakPointRunner

runner = VigilBreakPointRunner(
    attacks_dir="./tests/attacks/",
    current_system_prompt=open("system_prompt.txt").read(),
)
results = runner.run_regression_suite()
if any(r.status == "BLOCK" for r in results):
    raise SystemExit(2)
```

---

## Documentation

- [Architecture](docs/architecture.md) — module structure and data flow
- [The Feedback Loop](docs/loop.md) — the full loop explained
- [Snapshot Format](docs/snapshot-format.md) — `.bp.json` field contract
- [CLI Reference](docs/cli.md) — all vigil commands
- [Forensics](docs/forensics.md) — pattern library, log formats, evidence pack
- [Integration Guide](docs/integration.md) — Python API usage
- [Quickstart](docs/quickstart.md) — 10-minute walkthrough

Framework examples: [examples/frameworks/](examples/frameworks/README.md)

---

## Free forensics audit

Running an LLM application in production?

We're offering free forensics audits for early design partners — scan your historical OTEL logs and find out if there are successful attacks you missed.

What you get: a full evidence pack with every finding documented as a `.bp.json` snapshot, ready to commit as permanent CI gates.

**[Open an issue](https://github.com/cholmess/vigil/issues)** or reach out directly:
- X: [@cholmess](https://x.com/cholmess)
- LinkedIn: [cholmess](https://linkedin.com/in/cholmess)

---

## Maintainer

Maintained by [Christopher Holmes Silva](https://github.com/cholmess).

Feedback is welcome from developers shipping LLM applications.
