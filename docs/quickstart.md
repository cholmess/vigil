# 10-Minute Quickstart

This walkthrough takes you from install to a closed feedback loop in about 10 minutes.

## Prerequisites

- Python 3.10+
- `canari-llm`, `canari-forensics`, and `breakpoint-ai` installed (or cloned locally)

## 1) Install (1 minute)

From the repo root:

```bash
pip install -e .
```

Or with the full ecosystem installed from local clones:

```bash
pip install -e ../canari
pip install -e ../canari-forensics
pip install -e ../breakpoint-ai
pip install -e . --no-deps
pip install typer pyyaml pydantic
```

Verify:

```bash
vigil --help
```

## 2) Forensic scan on sample logs (3 minutes)

Run the scanner against the included example logs:

```bash
vigil forensics scan \
  --logs examples/logs/sample-otel.jsonl \
  --format otel \
  --out ./tests/attacks/
```

Expected output:

```
Scan ID: F-2026-02-22-a3b8c1
Files scanned: 200 turns
Findings: 1
  cred_stripe_live  2025-11-14  high  forensic-F-0001.bp.json
Snapshots written to: tests/attacks/
```

## 3) Run the regression suite (2 minutes)

Test the current system prompt against every known attack:

```bash
vigil test \
  --attacks-dir ./tests/attacks/ \
  --prompt-file examples/prompts/baseline_prompt.txt
```

A BLOCK result means the attack still works against the current prompt:

```
[BLOCK] forensic-F-0001.bp.json
        reason: PII_EMAIL_BLOCK
        suggestion: Add to system prompt: Never output API keys or credentials.
```

A ALLOW result means the prompt already defends against this attack:

```
[ALLOW] forensic-F-0001.bp.json
```

## 4) Harden and re-test (2 minutes)

Read the `hardening_suggestion` in the snapshot. Open `examples/prompts/baseline_prompt.txt`
and add the suggested instruction. Then run the suite again:

```bash
vigil test \
  --attacks-dir ./tests/attacks/ \
  --prompt-file examples/prompts/baseline_prompt.txt
```

Expected: all snapshots ALLOW.

## 5) Commit the snapshot as a regression test (1 minute)

```bash
git add tests/attacks/forensic-F-0001.bp.json examples/prompts/baseline_prompt.txt
git commit -m "harden prompt against Stripe key leak (forensic-F-0001)"
git push
```

The loop is closed. CI will now replay this attack on every future deploy.

## 6) Live integration with Canari (optional)

Wrap your LLM calls with `VigilCanariWrapper`:

```python
from vigil import VigilCanariWrapper

wrapper = VigilCanariWrapper(
    canari_db="canari.db",
    attacks_dir="./tests/attacks/"
)

# Drop this into your existing LLM call handler
snap_path = wrapper.process_turn(
    system_prompt=SYSTEM_PROMPT,
    user_input=user_message,
    llm_output=assistant_response,
)
if snap_path:
    print(f"Attack snapshot written: {snap_path}")
```

When a canary fires, the snapshot is written to `./tests/attacks/` automatically.
The next `vigil test` run will include it.

## 7) Export a live Canari incident (optional)

```bash
canari --db canari.db export-attack \
  --incident inc-conv-abc123 \
  --out ./tests/attacks/
```

Then test:

```bash
vigil test --attacks-dir ./tests/attacks/ --prompt-file system_prompt.txt
```

## Next Steps

- [Architecture](architecture.md) — how the three tools connect
- [CLI Reference](cli-reference.md) — all `vigil` commands
- [Loop](loop.md) — the full feedback loop explained
- [Snapshot Format](snapshot-format.md) — the `.bp.json` contract
