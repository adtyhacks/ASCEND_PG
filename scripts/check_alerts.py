#!/usr/bin/env python3
"""Quick diagnostic: check what SIDs are in eve.json and which time windows they fall in."""
import json, sys
from pathlib import Path

EVE = Path("/var/log/suricata/eve.json")
if not EVE.exists():
    print("eve.json not found")
    sys.exit(1)

alerts = []
with open(EVE) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("event_type") != "alert":
            continue
        alert = e.get("alert", {})
        sid = alert.get("signature_id", 0)
        sig = alert.get("signature", "")
        ts = e.get("timestamp", "")
        flow = e.get("flow", {})
        flow_start = flow.get("start", "")
        src = e.get("src_ip", "")
        dst = e.get("dest_ip", "")
        sp = e.get("src_port", "")
        dp = e.get("dest_port", "")
        alerts.append({
            "sid": sid, "sig": sig[:70], "ts": ts[:26],
            "flow_start": flow_start[:26] if flow_start else "",
            "src": src, "dst": dst, "sp": sp, "dp": dp,
        })

print(f"Total alerts in eve.json: {len(alerts)}")
print()

# Group by SID
from collections import Counter
sid_counts = Counter(a["sid"] for a in alerts)
print("Alerts by SID:")
for sid, count in sorted(sid_counts.items()):
    sig = next((a["sig"] for a in alerts if a["sid"] == sid), "")
    print(f"  SID {sid}: {count} alerts  {sig}")
print()

# Show last 20 alerts with timestamps
print("Last 20 alerts:")
for a in alerts[-20:]:
    print(f"  [{a['ts']}] SID {a['sid']} {a['src']}:{a['sp']} -> {a['dst']}:{a['dp']}  {a['sig']}")
