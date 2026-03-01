#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHONPATH="$REPO_ROOT/src"
export PYTHONPATH

if ! python3 -c "import typer, pydantic, yaml" >/dev/null 2>&1; then
  echo "ERROR: Missing Python dependencies for vigil demo."
  echo "Run in an environment with project deps installed, for example:"
  echo "  pip install -e ."
  echo "Then rerun:"
  echo "  ./examples/full_loop_demo/run_end_to_end.sh"
  exit 2
fi

ATTACKS_DIR="$SCRIPT_DIR/attacks"
LOGS_DIR="$SCRIPT_DIR/sample-logs"
PROMPT_VULNERABLE="$SCRIPT_DIR/vulnerable_prompt.txt"
PROMPT_HARDENED="$SCRIPT_DIR/hardened_prompt.txt"

NETWORK_DIR="$SCRIPT_DIR/.vigil-data/network"
PULLED_DIR="$SCRIPT_DIR/.vigil-data/network/pulled"
TRAIN_DIR="$SCRIPT_DIR/.vigil-data/train"
INTEL_DIR="$SCRIPT_DIR/.vigil-data/network/intel"

vigil_cmd() {
  python3 -m vigil "$@"
}

echo ""
echo "VIGIL END-TO-END DEMO"
echo "Loop + Network + Train Bootstrap"
echo ""

rm -rf "$SCRIPT_DIR/.vigil-data"
rm -rf "$ATTACKS_DIR"
mkdir -p "$ATTACKS_DIR" "$INTEL_DIR" "$TRAIN_DIR"

echo "1) Forensics scan -> snapshots"
vigil_cmd forensics scan --logs "$LOGS_DIR" --format otel --attacks-dir "$ATTACKS_DIR"

echo ""
echo "2) Live canari-style attack simulation"
python3 "$SCRIPT_DIR/app.py" --demo --attacks-dir "$ATTACKS_DIR"

echo ""
echo "3) Replay before hardening (expected BLOCK)"
if vigil_cmd test --attacks-dir "$ATTACKS_DIR" --prompt-file "$PROMPT_VULNERABLE"; then
  echo "Unexpected PASS against vulnerable prompt."
else
  echo "Expected: vulnerable prompt blocks failed."
fi

echo ""
echo "4) Replay after hardening (must PASS)"
vigil_cmd test --attacks-dir "$ATTACKS_DIR" --prompt-file "$PROMPT_HARDENED" --report

echo ""
echo "5) Publish local snapshots to exchange"
for bp in "$ATTACKS_DIR"/*.bp.json; do
  [ -f "$bp" ] || continue
  vigil_cmd network push "$bp" --sanitize --network-dir "$NETWORK_DIR"
done

echo ""
echo "6) Pull + threat intel feed"
vigil_cmd network pull --network-dir "$NETWORK_DIR" --attacks-dir "$PULLED_DIR"
vigil_cmd network intel --network-dir "$NETWORK_DIR" --days 30 --format json --out "$INTEL_DIR/intel.json"
vigil_cmd network alert --network-dir "$NETWORK_DIR" --days 30 --format json --out "$INTEL_DIR/alert.json"
vigil_cmd network feed --network-dir "$NETWORK_DIR" --days 30 --top 5 --format json --out "$INTEL_DIR/feed.json"

echo ""
echo "7) Train bootstrap + integrity checks"
vigil_cmd train bootstrap --out-dir "$TRAIN_DIR" --network-dir "$NETWORK_DIR" --val-ratio 0.2 --format json --out "$TRAIN_DIR/bootstrap.json"
vigil_cmd train verify-bundle --bundle-file "$TRAIN_DIR/train-bundle.tar.gz" --format json --out "$TRAIN_DIR/verify-bundle.json"
vigil_cmd train runs --train-dir "$TRAIN_DIR" --format json --out "$TRAIN_DIR/runs.json"

echo ""
echo "DONE"
echo "Artifacts:"
echo "  - Attack snapshots:      $ATTACKS_DIR"
echo "  - Network intel reports: $INTEL_DIR"
echo "  - Train artifacts:       $TRAIN_DIR"
echo ""
