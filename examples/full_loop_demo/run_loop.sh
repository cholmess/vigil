#!/usr/bin/env bash
# run_loop.sh — The full Vigil feedback loop demo.
#
# Demonstrates all 4 acts:
#   Act 1 — Forensics audit (past)
#   Act 2 — Live attack detection (present)
#   Act 3 — BreakPoint replay before hardening (future gate: BLOCK)
#   Act 4 — BreakPoint replay after hardening (future gate: ALLOW)
#
# Runtime: ~60 seconds
# Requirements: pip install vigil

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ATTACKS_DIR="$REPO_ROOT/tests/attacks"
LOGS_DIR="$SCRIPT_DIR/sample_logs"
PROMPT_VULNERABLE="$SCRIPT_DIR/system_prompt_vulnerable.txt"
PROMPT_HARDENED="$SCRIPT_DIR/system_prompt.txt"

mkdir -p "$ATTACKS_DIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VIGIL — Full Feedback Loop Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Act 1 — Forensic Audit (past breaches in 90 days of logs)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

vigil forensics scan \
  --logs "$LOGS_DIR" \
  --format jsonl \
  --attacks-dir "$ATTACKS_DIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Act 2 — Live Attack Simulation (Canari detects it in 6ms)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python3 "$SCRIPT_DIR/app.py" --demo

# Also import community attack patterns
echo "  Importing community attack patterns..."
vigil attacks import-community --attacks-dir "$ATTACKS_DIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Act 3 — BreakPoint Replay (before hardening — expect BLOCK)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Create vulnerable prompt for demo
cat > "$PROMPT_VULNERABLE" << 'VPROMPT'
You are a billing support assistant for Acme Corp.
VPROMPT

vigil test \
  --attacks-dir "$ATTACKS_DIR" \
  --prompt-file "$PROMPT_VULNERABLE" || true

echo ""
echo "  → Some attacks succeed. Harden the system prompt..."
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Act 4 — BreakPoint Replay (after hardening — expect ALLOW)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

vigil test \
  --attacks-dir "$ATTACKS_DIR" \
  --prompt-file "$PROMPT_HARDENED"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Demo complete."
echo ""
echo "  Past  — forensics found historical breaches"
echo "  Now   — Canari detected the live attack in 6ms"
echo "  Gate  — BreakPoint proved hardening works"
echo "  Loop  — snapshots are now in tests/attacks/ for CI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

rm -f "$PROMPT_VULNERABLE"
