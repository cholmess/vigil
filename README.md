# vigil

[![PyPI package](https://img.shields.io/pypi/v/vigil?label=pypi%20package)](https://pypi.org/project/vigil/)
[![CI](https://github.com/cholmess/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/cholmess/vigil/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Close the loop between detecting an LLM attack and making sure it never works again.

Canari catches prompt injection in real time. Canari Forensics finds attacks in historical logs. BreakPoint tests whether your current system prompt still defends against them. Vigil is the integration layer that connects all three — every attack becomes a `.bp.json` snapshot, every snapshot becomes a regression test, every deploy is gated against the full attack history.

## Install

```bash
pip install vigil
```

Or from source with the full local ecosystem:

```bash
pip install -e ../canari
pip install -e ../canari-forensics
pip install -e ../breakpoint-ai
pip install -e . --no-deps
pip install typer pyyaml pydantic
```

## Quick start

```bash
# 1) Scan historical logs for past breaches
vigil forensics scan \
  --logs ./logs/ \
  --format otel \
  --out ./tests/attacks/

# 2) Test current system prompt against every known attack
vigil test --prompt-file system_prompt.txt
# → BLOCK: still vulnerable

# 3) Harden — read the hardening_suggestion in the snapshot, edit system_prompt.txt

# 4) Verify
vigil test --prompt-file system_prompt.txt
# → ALLOW: hardened

# 5) Commit the snapshot as a permanent regression test
git add system_prompt.txt tests/attacks/
git commit -m "harden prompt against context dump (inc-conv-abc123)"
git push
# → CI runs full suite → green
```

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
from vigil import VigilCanariWrapper

wrapper = VigilCanariWrapper(canari_db="canari.db", attacks_dir="./tests/attacks/")

# Drop into your LLM call handler
snap_path = wrapper.process_turn(
    system_prompt=SYSTEM_PROMPT,
    user_input=user_message,
    llm_output=assistant_response,
)
if snap_path:
    print(f"Attack snapshot: {snap_path}")
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

- [Architecture](docs/architecture.md) — how the three tools connect
- [The Feedback Loop](docs/loop.md) — the full loop explained
- [Snapshot Format](docs/snapshot-format.md) — `.bp.json` field contract
- [CLI Reference](docs/cli-reference.md) — all `vigil` commands
- [Forensics](docs/forensics.md) — pattern library, log formats, evidence pack
- [Integration Guide](docs/integration-guide.md) — Python API usage
- [Quickstart](docs/quickstart.md) — 10-minute walkthrough

## Related Tools

- [BreakPoint](https://github.com/cholmess/breakpoint-ai) — catch regressions before you ship
- [Canari](https://github.com/cholmess/canari) — detect attacks in real time
- [Canari Forensics](https://github.com/cholmess/canari-forensics) — audit logs for past breaches

## Maintainer

Maintained by Christopher Holmes Silva.

- X: https://x.com/cholmess
- LinkedIn: https://linkedin.com/in/cholmess

Feedback is welcome from developers shipping LLM applications.
