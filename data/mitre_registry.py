"""
ASCEND-PG — Authoritative MITRE ATT&CK for ICS Technique Registry

Single source of truth binding:
  - MITRE Technique ID
  - Official MITRE Name & Tactic
  - RL Action Space Index (0-17)
  - Attack Script Implementation & Arguments
  - Suricata Detection Rule SIDs
  - Reporting & XAI labels

Resolves T0840 vs T0842 semantic distinction:
  - T0840: Network Connection Enumeration (active Modbus FC scan via fc_scan.py)
  - T0842: Network Sniffing (passive sniffing, historical alias in trained model)
Resolves T0855:
  - Primary: cmd_inject_coil.py (actuator/breaker command injection)
  - Secondary variants: cmd_inject_register.py, malicious_fc.py
"""

from typing import Dict, List, Any, Optional

TECHNIQUES: List[Dict[str, Any]] = [
    # Stage 0: Initial Access & Discovery (indices 0..3)
    {
        "index": 0,
        "id": "T0886",
        "name": "Remote Services",
        "tactic": "Initial Access, Lateral Movement",
        "stage": 0,
        "default_step": "remote_services",
        "script": "attacks/remote_services.py",
        "detect_sids": [9000026],
        "description": "SSH access to SCADA followed by Modbus commands through the pivot",
        "mock_prob": 0.50,
    },
    {
        "index": 1,
        "id": "T0846",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "stage": 0,
        "default_step": "recon_nmap_devid",
        "script": "attacks/recon_step.py",
        "detect_sids": [9000004],
        "description": "Nmap host sweep and Modbus port probe across ICS subnet",
        "mock_prob": 0.70,
    },
    {
        "index": 2,
        "id": "T0888",
        "name": "Remote System Information Discovery",
        "tactic": "Discovery",
        "stage": 0,
        "default_step": "recon_nmap_devid",
        "script": "attacks/recon_step.py",
        "detect_sids": [9000004],
        "description": "Modbus Read Device Identification (Function Code 0x2B/0x0E)",
        "mock_prob": 0.45,
    },
    {
        "index": 3,
        "id": "T0840",  # Canonical MITRE ID for FC Scan / Connection Enumeration
        "alias_ids": ["T0842"],  # RL model index 3 historical alias
        "name": "Network Connection Enumeration",
        "historical_name": "Network Sniffing",
        "tactic": "Discovery",
        "stage": 0,
        "default_step": "recon_fc_scan",
        "script": "attacks/fc_scan.py",
        "detect_sids": [9000005, 9000006],
        "description": "Function code scanning (FC 1-127) to fingerprint supported PLC capabilities",
        "mock_prob": 0.25,
    },

    # Stage 1: Lateral Movement & Collection & C2 (indices 4..7)
    {
        "index": 4,
        "id": "T0830",
        "name": "Adversary-in-the-Middle",
        "tactic": "Collection",
        "stage": 1,
        "default_step": "mitm_proxy",
        "script": "attacks/mitm_proxy.py",
        "detect_sids": [9000022],
        "description": "Transparent TCP proxy modifying Modbus FC03 responses in transit",
        "mock_prob": 0.55,
    },
    {
        "index": 5,
        "id": "T0801",
        "name": "Monitor Process State",
        "tactic": "Collection",
        "stage": 1,
        "default_step": "monitor_process_state",
        "script": "attacks/monitor_process_state.py",
        "detect_sids": [9000023],
        "description": "Scripted repeated polling of power grid telemetry registers",
        "mock_prob": 0.35,
    },
    {
        "index": 6,
        "id": "T0802",
        "name": "Automated Collection",
        "tactic": "Collection",
        "stage": 1,
        "default_step": "automated_collection",
        "script": "attacks/automated_collection.py",
        "detect_sids": [9000027],
        "description": "Full register-range sweep across all emulated PLCs",
        "mock_prob": 0.60,
    },
    {
        "index": 7,
        "id": "T0869",
        "name": "Standard Application Layer Protocol",
        "tactic": "Command and Control",
        "stage": 1,
        "default_step": "standard_protocol_c2",
        "script": "attacks/standard_protocol_c2.py",
        "detect_sids": [9000028],
        "description": "Attacker traffic disguised as legitimate Modbus TCP polling",
        "mock_prob": 0.40,
    },

    # Stage 2: Inhibit Response & Impair Process Control (indices 8..15)
    {
        "index": 8,
        "id": "T0814",
        "name": "Denial of Service",
        "tactic": "Inhibit Response Function",
        "stage": 2,
        "default_step": "dos_loud",
        "variants": ["dos_quiet", "dos_conn_exhaust"],
        "script": "attacks/dos_attack.py",
        "detect_sids": [9000002, 9000023, 9000010],
        "description": "Modbus request flood and TCP connection pool exhaustion on port 502",
        "mock_prob": 0.85,
    },
    {
        "index": 9,
        "id": "T0878",
        "name": "Alarm Suppression",
        "tactic": "Inhibit Response Function",
        "stage": 2,
        "default_step": "alarm_suppression",
        "script": "attacks/alarm_suppression.py",
        "detect_sids": [9000029],
        "description": "Modbus write to alarm-setpoint and trip threshold registers",
        "mock_prob": 0.60,
    },
    {
        "index": 10,
        "id": "T0816",
        "name": "Device Restart/Shutdown",
        "tactic": "Inhibit Response Function",
        "stage": 2,
        "default_step": "device_restart",
        "script": "attacks/device_restart.py",
        "detect_sids": [9000007],
        "description": "Modbus write to simulated restart/reset coil",
        "mock_prob": 0.75,
    },
    {
        "index": 11,
        "id": "T0881",
        "name": "Service Stop",
        "tactic": "Inhibit Response Function",
        "stage": 2,
        "default_step": "service_stop",
        "script": "attacks/service_stop.py",
        "detect_sids": [9000030],
        "description": "Malformed Modbus frame to crash or hang PLC server process",
        "mock_prob": 0.70,
    },
    {
        "index": 12,
        "id": "T0836",
        "name": "Modify Parameter",
        "tactic": "Impair Process Control",
        "stage": 2,
        "default_step": "fdi_attack",
        "variants": ["naive_response_injection", "complex_response_injection"],
        "script": "attacks/fdi_attack.py",
        "detect_sids": [9000001],
        "description": "False Data Injection modifying generator voltage and measurement registers",
        "mock_prob": 0.65,
    },
    {
        "index": 13,
        "id": "T0835",
        "name": "Manipulate I/O Image",
        "tactic": "Inhibit Response Function",
        "stage": 2,
        "default_step": "manipulate_io_image",
        "script": "attacks/manipulate_io_image.py",
        "detect_sids": [9000007],
        "description": "Direct coil/holding-register writes overriding safety logic",
        "mock_prob": 0.65,
    },
    {
        "index": 14,
        "id": "T0806",
        "name": "Brute Force I/O",
        "tactic": "Impair Process Control",
        "stage": 2,
        "default_step": "brute_force_io",
        "script": "attacks/brute_force_io.py",
        "detect_sids": [9000023],
        "description": "Rapid sequential writes across full I/O address range",
        "mock_prob": 0.80,
    },
    {
        "index": 15,
        "id": "T0855",
        "replacement_id": "T1692.001",
        "catalog_status": "Historical technique ID; replaced by Unauthorized Message: Command Message",
        "name": "Unauthorized Command Message",
        "tactic": "Impair Process Control",
        "stage": 2,
        "default_step": "cmd_inject_coil",
        "variants": ["cmd_inject_register", "malicious_fc"],
        "script": "attacks/cmd_inject_coil.py",
        "detect_sids": [9000007, 9000001, 9000006, 9000008, 9000009],
        "description": "Command injection via actuator/coil writes (FC05/FC15), setpoint writes (FC06/FC16), or diagnostic functions",
        "mock_prob": 0.75,
    },

    # Stage 3: Impact (indices 16..17)
    {
        "index": 16,
        "id": "T0832",
        "name": "Manipulation of View",
        "tactic": "Impact",
        "stage": 3,
        "default_step": "replay_attack",
        "script": "attacks/replay_attack.py",
        "detect_sids": [],
        "description": "Replay of recorded normal telemetry to mask ongoing grid faults",
        "mock_prob": 0.40,
    },
    {
        "index": 17,
        "id": "T0815",
        "name": "Denial of View",
        "tactic": "Impact",
        "stage": 3,
        "default_step": "denial_of_view",
        "script": "attacks/denial_of_view.py",
        "detect_sids": [9000001, 9000024],
        "description": "Block SCADA polling responses so HMI displays stale measurements",
        "mock_prob": 0.70,
    },
]

# Lookup tables
BY_ID: Dict[str, Dict[str, Any]] = {}
BY_INDEX: Dict[int, Dict[str, Any]] = {}

for t in TECHNIQUES:
    BY_ID[t["id"]] = t
    BY_INDEX[t["index"]] = t
    for alias in t.get("alias_ids", []):
        BY_ID[alias] = t

def get_technique_by_id(tech_id: str) -> Optional[Dict[str, Any]]:
    return BY_ID.get(tech_id)


def get_display_technique(tech_id):
    """Display historical IDs faithfully; execution alias preserves RL index 3."""
    if tech_id == "T0842":
        return {"id": "T0842", "name": "Network Sniffing", "tactic": "Discovery",
                "detect_sids": [], "default_step": "passive_sniffing"}
    return get_technique_by_id(tech_id)

def get_technique_by_index(idx: int) -> Optional[Dict[str, Any]]:
    return BY_INDEX.get(idx)

def get_step_for_technique(tech_id: str) -> Optional[str]:
    t = get_technique_by_id(tech_id)
    return t["default_step"] if t else None

def get_rl_techniques() -> List[Dict[str, Any]]:
    """Return the exact 18-element list matching RL action indices 0..17."""
    return [BY_INDEX[i] for i in range(len(TECHNIQUES))]
