"""Focused owned CORE smoke test. Refuses occupied runtime; no PPO or watcher."""
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    from testbed.core_runtime import core_request
    from testbed.topology import Topology, get_topology, activate_topology, TOPOLOGY_LOCK
    from testbed.generate_core_topo import generate_core_xml
    from testbed import run_store
    with TOPOLOGY_LOCK:
        status = core_request("status")
        if status.get("session_id") is not None:
            raise RuntimeError("Managed CORE runtime is occupied; existing session/watcher preserved. Stop it explicitly before this smoke test.")
        previous = get_topology()
        topology = Topology.from_exchange(json.loads((ROOT / "examples/core_firewall_smoke.json").read_text()))
        created = None
        try:
            activate_topology(topology)
            with tempfile.TemporaryDirectory(prefix="ascend-firewall-") as directory:
                xml = generate_core_xml(output_path=str(Path(directory) / "firewall.xml"), topology=get_topology())
                run = run_store.create_run(topology.canonical_snapshot())
                created = core_request("start", xml=xml, scenario_id=run["scenario_id"], run_id=run["run_id"])
                result = core_request("firewall_smoke", generation_id=created["generation_id"])
                print(json.dumps({"installation": created["firewalls"], **result, "scenario_id": run["scenario_id"], "run_id": run["run_id"]}, indent=2))
                if not result["packet_enforcement_verified"]: raise RuntimeError("Controlled firewall packet verification failed.")
        finally:
            if created is not None:
                # core_request stop still validates token/endpoint ownership.
                core_request("stop", generation_id=created["generation_id"])
            # Startup cleanup failures retain the active topology for that session.
            if core_request("status").get("session_id") is None:
                activate_topology(previous)


if __name__ == "__main__": main()
