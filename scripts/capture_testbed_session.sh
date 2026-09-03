#!/usr/bin/env bash
# Capture one bounded ASCEND-PG testbed session from the OVS monitor interface.
# Run this in a separate WSL host-shell terminal while the Mininet testbed and
# Suricata are already running. It deliberately captures raw evidence only;
# it never launches attacks itself.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/capture_testbed_session.sh \
    --interface <monitor-interface> --scenario <name> --duration <seconds> \
    [--output-dir data/captured_pcaps] [--eve-log /var/log/suricata/eve.json] \
    [--filter '<tcpdump BPF filter>']

Example:
  sudo bash scripts/capture_testbed_session.sh \
    --interface s1-eth6 --scenario cycle_001 --duration 900

Start this capture before running normal traffic or scripts/run_cycle.py. The
script writes a PCAP, UTC metadata, and a snapshot of Suricata eve.json when
available. It stops automatically after the requested duration.
EOF
}

interface=""
scenario=""
duration=""
output_dir="data/captured_pcaps"
eve_log="/var/log/suricata/eve.json"
capture_filter=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) interface="${2:-}"; shift 2 ;;
    --scenario) scenario="${2:-}"; shift 2 ;;
    --duration) duration="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --eve-log) eve_log="${2:-}"; shift 2 ;;
    --filter) capture_filter="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$interface" || -z "$scenario" || -z "$duration" ]]; then
  echo "--interface, --scenario, and --duration are required." >&2
  usage >&2
  exit 2
fi

if ! [[ "$scenario" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "Scenario must contain only letters, numbers, underscores, or hyphens." >&2
  exit 2
fi

if ! [[ "$duration" =~ ^[1-9][0-9]*$ ]]; then
  echo "Duration must be a positive integer number of seconds." >&2
  exit 2
fi

command -v tcpdump >/dev/null || { echo "tcpdump is required." >&2; exit 1; }
command -v timeout >/dev/null || { echo "timeout is required." >&2; exit 1; }

mkdir -p "$output_dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="${scenario}_${stamp}"
pcap_path="${output_dir}/${base}.pcap"
metadata_path="${output_dir}/${base}_metadata.json"
eve_copy_path="${output_dir}/${base}_eve.json"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[capture] interface=${interface}, scenario=${scenario}, duration=${duration}s"
echo "[capture] writing ${pcap_path}"

set +e
if [[ -n "$capture_filter" ]]; then
  timeout --signal=INT "${duration}s" tcpdump -i "$interface" -U -n -w "$pcap_path" "$capture_filter"
else
  timeout --signal=INT "${duration}s" tcpdump -i "$interface" -U -n -w "$pcap_path"
fi
capture_status=$?
set -e

# timeout returns 124 for the intended bounded completion; tcpdump returns 0
# if stopped cleanly before the timeout. Any other status is a real failure.
if [[ $capture_status -ne 0 && $capture_status -ne 124 ]]; then
  echo "[capture] tcpdump failed with status ${capture_status}" >&2
  exit "$capture_status"
fi

ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ -f "$eve_log" ]]; then
  cp "$eve_log" "$eve_copy_path"
  echo "[capture] copied Suricata evidence to ${eve_copy_path}"
fi

cat > "$metadata_path" <<EOF
{
  "source": "ascend_pg_testbed",
  "scenario_id": "${scenario}",
  "interface": "${interface}",
  "started_at_utc": "${started_at}",
  "ended_at_utc": "${ended_at}",
  "duration_seconds_requested": ${duration},
  "pcap": "$(basename "$pcap_path")",
  "suricata_eve_snapshot": "$(basename "$eve_copy_path")",
  "capture_filter": "${capture_filter}"
}
EOF

echo "[capture] complete: ${metadata_path}"
