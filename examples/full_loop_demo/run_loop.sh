#!/usr/bin/env bash
# Ensure vigil is on PATH
# Try common install locations in order
if ! command -v vigil &> /dev/null; then
  # Try pip user install location
  export PATH="$HOME/.local/bin:$PATH"
fi
if ! command -v vigil &> /dev/null; then
  # Try local venv
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
  if [ -f "$REPO_ROOT/.venv/bin/vigil" ]; then
    export PATH="$REPO_ROOT/.venv/bin:$PATH"
  fi
fi
if ! command -v vigil &> /dev/null; then
  echo "ERROR: vigil not found. Run: pip install vigil"
  echo "Or from repo root: pip install -e ."
  exit 1
fi

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
ATTACKS_DIR="$DEMO_DIR/attacks"
LOGS_DIR="$DEMO_DIR/sample-logs"
PROMPT_VULNERABLE="$DEMO_DIR/vulnerable_prompt.txt"
PROMPT_HARDENED="$DEMO_DIR/hardened_prompt.txt"

echo ""
echo "VIGIL — THE LLM PRODUCTION SAFETY PLATFORM"
echo "Past. Present. Future. Loop."
echo ""
sleep 1

# Clean state for deterministic reruns
rm -rf "$ATTACKS_DIR"
rm -rf "$DEMO_DIR/.vigil-data"
mkdir -p "$ATTACKS_DIR"

echo "════ ACT 1: SCANNING HISTORICAL LOGS ════"
echo ""
sleep 0.5

vigil forensics scan \
  --logs "$LOGS_DIR" \
  --format otel \
  --attacks-dir "$ATTACKS_DIR"

sleep 1

echo ""
echo "════ ACT 2: LIVE ATTACK DETECTION ════"
echo ""
sleep 0.5

python3 "$DEMO_DIR/app.py" --demo --attacks-dir "$ATTACKS_DIR"

sleep 1

echo ""
echo "════ ACT 3: TESTING CURRENT PROMPT ════"
echo ""
sleep 0.5

vigil test \
  --attacks-dir "$ATTACKS_DIR" \
  --prompt-file "$PROMPT_VULNERABLE" || true
# BLOCK is expected in Act 3.

sleep 1

echo ""
echo "════ ACT 4: AFTER HARDENING ════"
echo ""
sleep 0.5

vigil test \
  --attacks-dir "$ATTACKS_DIR" \
  --prompt-file "$PROMPT_HARDENED"
# No || true here. This must pass.

echo ""
echo "VIGIL LOOP COMPLETE"
echo "Past:    Historical breaches found and exported as regression tests"
echo "Present: Live attack caught and exported as regression test"
echo "Future:  All attacks replayed, prompt hardened, CI ready"
echo "The system is harder to attack than it was 3 minutes ago."
echo ""
