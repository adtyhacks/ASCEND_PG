#!/bin/bash
# scripts/install_cicflowmeter.sh
#
# Installs CICFlowMeter (hieulw/cicflowmeter, v0.5.0+) into a dedicated
# Python 3.11 virtual environment at ~/cicflow-env to avoid conflicts with
# the system Python 3.14 used by pymodbus and the rest of ASCEND-PG.
#
# Why a separate venv:
#   - cicflowmeter depends on scapy + numpy + scipy, which have C extensions
#     that may not compile cleanly against Python 3.14 yet.
#   - The labeling script (scripts/label_captured_flows.py) runs under the
#     system Python and only reads the CSV output — no shared env needed.
#
# Run once on the WSL2/Ubuntu machine:
#   sudo bash scripts/install_cicflowmeter.sh
#
# After install, process a PCAP with:
#   ~/cicflow-env/bin/cicflowmeter -f <pcap> -c <output.csv>
# Or use the wrapper:
#   bash scripts/run_cicflowmeter.sh <pcap_file> <output_csv>

set -e

VENV_DIR="$HOME/cicflow-env"
PYTHON_BIN=""

echo "=== ASCEND-PG: CICFlowMeter Install Script ==="
echo ""

# --- Step 1: Find Python 3.11 ---
echo "[1/5] Locating Python 3.11 ..."
for candidate in python3.11 python3.12 python3.10; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON_BIN=$(command -v "$candidate")
        echo "      Found: $PYTHON_BIN ($($PYTHON_BIN --version))"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[1/5] Python 3.11 not found — installing from deadsnakes PPA ..."
    sudo apt update -qq
    sudo apt install -y software-properties-common
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt update -qq
    sudo apt install -y python3.11 python3.11-venv python3.11-distutils
    PYTHON_BIN=$(command -v python3.11)
    echo "      Installed: $PYTHON_BIN ($($PYTHON_BIN --version))"
fi

# --- Step 2: Install system deps for scapy / numpy build ---
echo "[2/5] Installing system dependencies (libpcap, build-essential) ..."
sudo apt install -y libpcap-dev build-essential python3-dev 2>/dev/null || true

# --- Step 3: Create venv ---
echo "[3/5] Creating virtual environment at $VENV_DIR ..."
if [ -d "$VENV_DIR" ]; then
    echo "      Existing venv found — removing and recreating"
    rm -rf "$VENV_DIR"
fi
"$PYTHON_BIN" -m venv "$VENV_DIR"

# --- Step 4: Install cicflowmeter into the venv ---
echo "[4/5] Installing cicflowmeter (hieulw fork, pip) ..."
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel --quiet
"$VENV_DIR/bin/pip" install cicflowmeter --quiet

echo "      Installed version: $("$VENV_DIR/bin/pip" show cicflowmeter | grep Version)"

# --- Step 5: Verify ---
echo "[5/5] Verifying install ..."
if "$VENV_DIR/bin/cicflowmeter" --help &>/dev/null; then
    echo "      cicflowmeter OK"
else
    echo "      WARNING: cicflowmeter --help failed — check install above"
fi

echo ""
echo "=== Install complete ==="
echo ""
echo "Usage:"
echo "  Process a PCAP file:"
echo "    $VENV_DIR/bin/cicflowmeter -f <input.pcap> -c <output.csv>"
echo ""
echo "  Or use the project wrapper (handles paths automatically):"
echo "    bash scripts/run_cicflowmeter.sh <input.pcap> <output_dir>"
echo ""
echo "  Wrapper command for capture_testbed_session output:"
echo "    bash scripts/run_cicflowmeter.sh \\"
echo "      data/captures/cycle_001/capture.pcap \\"
echo "      data/cicflow_output/"
