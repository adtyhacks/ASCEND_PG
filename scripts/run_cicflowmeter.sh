#!/bin/bash
# scripts/run_cicflowmeter.sh
#
# Wrapper around CICFlowMeter that handles paths, the dedicated venv,
# and output naming conventions expected by label_captured_flows.py.
#
# Usage:
#   bash scripts/run_cicflowmeter.sh <input.pcap> <output_dir> [scenario_id]
#
# Arguments:
#   input.pcap   — PCAP file produced by capture_testbed_session.sh
#   output_dir   — directory to write the CICFlowMeter CSV into
#                  (created if it doesn't exist)
#   scenario_id  — (optional) used to name the output CSV, e.g. "cycle_001"
#                  defaults to the PCAP basename without extension
#
# Example (full pipeline for scenario cycle_001):
#   sudo bash scripts/capture_testbed_session.sh \
#       --interface s1-mon --scenario cycle_001 --duration 900
#   bash scripts/run_cicflowmeter.sh \
#       data/captures/cycle_001/capture.pcap \
#       data/cicflow_output/ \
#       cycle_001
#   python3 scripts/label_captured_flows.py \
#       --flows data/cicflow_output/cycle_001.csv \
#       --scenario-id cycle_001 \
#       --output data/processed/cycle_001_labeled_flows.csv

set -e

VENV_DIR="$HOME/cicflow-env"
CICFLOWMETER="$VENV_DIR/bin/cicflowmeter"

# --- Parse args ---
INPUT_PCAP="${1:-}"
OUTPUT_DIR="${2:-data/cicflow_output}"
SCENARIO_ID="${3:-}"

if [ -z "$INPUT_PCAP" ]; then
    echo "Usage: bash scripts/run_cicflowmeter.sh <input.pcap> [output_dir] [scenario_id]"
    exit 1
fi

if [ ! -f "$INPUT_PCAP" ]; then
    echo "ERROR: PCAP file not found: $INPUT_PCAP"
    exit 1
fi

if [ ! -f "$CICFLOWMETER" ]; then
    echo "ERROR: CICFlowMeter not installed at $VENV_DIR"
    echo "       Run: sudo bash scripts/install_cicflowmeter.sh"
    exit 1
fi

# Default scenario_id from PCAP filename
if [ -z "$SCENARIO_ID" ]; then
    SCENARIO_ID=$(basename "$INPUT_PCAP" .pcap)
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_CSV="$OUTPUT_DIR/${SCENARIO_ID}.csv"

echo "=== ASCEND-PG: CICFlowMeter Flow Extraction ==="
echo "  Input PCAP : $INPUT_PCAP"
echo "  Output CSV : $OUTPUT_CSV"
echo "  Scenario   : $SCENARIO_ID"
echo ""

PCAP_SIZE=$(du -sh "$INPUT_PCAP" | cut -f1)
echo "[1/2] Processing $PCAP_SIZE PCAP — this may take a few minutes ..."

# CICFlowMeter writes the CSV to the specified path
"$CICFLOWMETER" -f "$INPUT_PCAP" -c "$OUTPUT_CSV"

if [ ! -f "$OUTPUT_CSV" ]; then
    echo "ERROR: Output CSV was not created — check cicflowmeter output above"
    exit 1
fi

ROW_COUNT=$(wc -l < "$OUTPUT_CSV")
echo "[2/2] Done — $((ROW_COUNT - 1)) flow rows written to $OUTPUT_CSV"
echo ""
echo "Next step — label flows with attack windows:"
echo "  python3 scripts/label_captured_flows.py \\"
echo "    --flows $OUTPUT_CSV \\"
echo "    --scenario-id $SCENARIO_ID \\"
echo "    --output data/processed/${SCENARIO_ID}_labeled_flows.csv"
