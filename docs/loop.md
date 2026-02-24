# The Feedback Loop

The core idea of Vigil is that every attack makes the system harder to attack.

## The Problem It Solves

Traditional LLM security is reactive:

1. Attacker finds a prompt injection.
2. Developer patches the system prompt.
3. Next deploy ships without testing whether the patch actually holds.
4. Attacker finds the same vulnerability in a different form.

The cycle repeats because there is no persistent record of what attacks have
been tried, and no automated gate that checks whether the current prompt still
defends against them.

## How the Loop Works

```
                    ┌─────────────────────────────┐
                    │                             │
             ┌──────▼──────┐               ┌─────┴──────┐
             │   Canari    │               │ BreakPoint │
             │  (present)  │               │  (future)  │
             └──────┬──────┘               └─────▲──────┘
                    │                             │
              attack fires                  replay test
                    │                        (CI gate)
                    ▼                             │
              .bp.json ─────────────────────────►│
              snapshot                           │
                    ▲                             │
                    │                             │
             ┌──────┴──────┐                      │
             │  Forensics  │                      │
             │   (past)    │─── .bp.json ─────────┘
             └─────────────┘
```

**Step 1 — Canari fires in production.**
A canary token leaks in an LLM response. Canari raises an alert within 6ms.

**Step 2 — Export the attack.**
```bash
canari --db canari.db export-attack --incident inc-conv-abc123 --out ./tests/attacks/
```
This writes `canari-attack-inc-conv-abc123.bp.json` — a snapshot of the full
conversation including the system prompt, the malicious user turn, and the
assistant response that triggered the canary.

**Step 3 — Test the current prompt.**
```bash
vigil test --prompt-file system_prompt.txt
# → BLOCK: still vulnerable
```
BreakPoint evaluates the captured LLM response against the expected safe
baseline. BLOCK means the attack still works.

**Step 4 — Harden the system prompt.**
Read the `hardening_suggestion` in the snapshot. Edit `system_prompt.txt`.

**Step 5 — Verify.**
```bash
vigil test --prompt-file system_prompt.txt
# → ALLOW: hardened
```

**Step 6 — Commit and push.**
```bash
git add system_prompt.txt tests/attacks/canari-attack-inc-conv-abc123.bp.json
git commit -m "harden prompt against context dump (inc-conv-abc123)"
git push
```

**Step 7 — CI runs the full suite.**
Every future deploy tests the current system prompt against every known attack
snapshot. New attacks are caught the moment they are added to the library.

The loop is now closed. The snapshot from today's attack becomes tomorrow's
regression test.

## The Forensics Entry Point

For teams that did not have Canari deployed yet:

```bash
vigil forensics scan --logs ./logs/ --format otel
# Scanned 8,934 turns in 0.8 seconds
# FOUND: 2 incidents before you were monitoring
#   2025-11-14: Stripe key leaked (forensic-F-0001.bp.json)
#   2026-01-07: AWS key leaked   (forensic-F-0002.bp.json)

vigil test --prompt-file system_prompt.txt --attacks-dir ./tests/attacks/
# forensic-F-0001.bp.json: BLOCK — still vulnerable
# forensic-F-0002.bp.json: ALLOW — already covered
```

Forensic findings feed into the same loop as live Canari alerts. The source
field on the snapshot (`"forensics"` vs `"canari"`) tells you where each attack
came from, but BreakPoint replays them identically.

## The Full Loop Timeline

```
PAST                     PRESENT               FUTURE
────────────────────────────────────────────────────────────────
Forensics scan           Canari alert          BreakPoint CI gate
finds old breach         fires in prod         blocks the regression

"Were we already         "Are we being         "Did this change
compromised?"            attacked now?"        break anything?"

      │                        │                      │
      └────────────────────────┴──────────────────────┘
                          .bp.json
                      (the shared contract)
```

## Why 10 Minutes

The plan calls for the hardening workflow to complete in under 10 minutes:

| Step | Time |
|---|---|
| Canari fires, Slack alert received | 0:00 |
| Export the attack snapshot | 0:30 |
| Run `vigil test` — BLOCK | 1:30 |
| Edit system prompt | 6:30 |
| Run `vigil test` — ALLOW | 7:30 |
| `git commit && git push` | 8:00 |
| CI runs full suite — green | ~10:00 |

The bottleneck is reading the `hardening_suggestion` and editing the system
prompt. Everything else is two commands and a commit.

## What the Loop Does Not Do

- It does not automatically patch the system prompt. Hardening is always a
  human decision.
- It does not guarantee that a patched prompt is secure against all future
  attacks — only that it covers all attacks in the snapshot library.
- It does not run the attack through a live LLM during `vigil test`. BreakPoint
  evaluates the captured response from the snapshot, not a new LLM call.
  This keeps the CI gate fast and deterministic.
