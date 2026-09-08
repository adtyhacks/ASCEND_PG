#!/usr/bin/env python3
"""
scripts/start_testbed.py

One-Shot Testbed Orchestrator for ASCEND-PG.

Automates the entire WSL2 startup in a single command:
1. Cleans stale Mininet state.
2. Boots the 7-host ICS topology (plc1–plc5, scada, attacker).
3. Automatically launches all 5 Modbus PLC servers in their network namespaces.
4. Automatically launches the SCADA polling client.
5. Starts Suricata IDS on s1-eth7 (attacker switch port).
6. Starts Modbus/Flow loggers for realistic network logging.
7. Provides an interactive menu to trigger attack cycles, test ping, or open CLI.
8. Automatically terminates and cleans all background processes on exit.

Usage:
    sudo python3 scripts/start_testbed.py
"""

import os
import sys
import time
import signal
import subprocess
import threading
from pathlib import Path

# Ensure repo root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mininet.net import Mininet
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel

from testbed.mininet_topology import IcsTopo, PLC_IPS, SCADA_IP, ATTACKER_IP


class TestbedOrchestrator:
    def __init__(self):
        self.net = None
        self.plc_procs = []
        self.scada_proc = None
        self.suricata_proc = None
        self.modbus_logger = None
        self.flow_logger = None
        self.running = True

    def check_root(self):
        if os.geteuid() != 0:
            print("\n[!] ERROR: start_testbed.py must be run with root/sudo privileges.")
            print("    Run: sudo python3 scripts/start_testbed.py\n")
            sys.exit(1)

    def clean_stale(self):
        print("[1/6] Cleaning stale Mininet state...")
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start_network(self):
        print("[2/6] Starting 7-host Mininet ICS topology...")
        setLogLevel("error")
        topo = IcsTopo()
        self.net = Mininet(topo=topo, controller=OVSController)
        self.net.start()
        print("      Network up on 10.0.0.0/24:")
        print(f"      - PLCs: plc1..plc5 ({PLC_IPS[0]} - {PLC_IPS[-1]})")
        print(f"      - SCADA: scada ({SCADA_IP})")
        print(f"      - Attacker: attacker ({ATTACKER_IP})")

    def start_plcs(self):
        print("[3/6] Launching 5 Modbus PLC servers...")
        plc_script = str(PROJECT_ROOT / "testbed" / "plc_server.py")
        for i, ip in enumerate(PLC_IPS, start=1):
            host = self.net.get(f"plc{i}")
            proc = host.popen([sys.executable, plc_script, "-i", ip, "-p", "502"])
            self.plc_procs.append(proc)
        time.sleep(1.0)
        print("      5 Modbus PLCs running (addresses 1-100 initialized).")

    def start_scada(self):
        print("[4/6] Launching SCADA polling client...")
        scada_script = str(PROJECT_ROOT / "testbed" / "scada_client.py")
        scada_host = self.net.get("scada")
        self.scada_proc = scada_host.popen(
            [sys.executable, scada_script, "--targets", *PLC_IPS, "-p", "502", "--interval", "1.0"]
        )
        print("      SCADA poller active (streaming telemetry to data/log_store.json).")

    def start_suricata(self):
        print("[5/6] Starting Suricata IDS on s1-eth7 (attacker port)...")
        suricata_yaml = Path("/etc/suricata/suricata.yaml")
        if suricata_yaml.exists():
            self.suricata_proc = subprocess.Popen(
                ["suricata", "-c", str(suricata_yaml), "-i", "s1-eth7"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            print("      Suricata IDS active on s1-eth7.")
        else:
            print("      [!] Suricata config not found, skipping.")

    def start_loggers(self):
        print("[6/6] Starting Modbus/Flow loggers on s1-eth7...")
        try:
            from defense.modbus_logger import ModbusLogger
            from defense.flow_logger import FlowLogger

            self.modbus_logger = ModbusLogger(interface="s1-eth7")
            self.flow_logger = FlowLogger(interface="s1-eth7")

            modbus_thread = threading.Thread(target=self.modbus_logger.start, daemon=True)
            flow_thread = threading.Thread(target=self.flow_logger.start, daemon=True)
            modbus_thread.start()
            flow_thread.start()

            time.sleep(1)
            print("      Modbus logger active (data/modbus_log.json)")
            print("      Flow logger active (data/flow_log.json)")
        except ImportError as e:
            print(f"      [!] Could not start loggers: {e}")
        except Exception as e:
            print(f"      [!] Logger error: {e}")

    def stop_loggers(self):
        if self.modbus_logger:
            try:
                self.modbus_logger.stop()
            except Exception:
                pass
        if self.flow_logger:
            try:
                self.flow_logger.stop()
            except Exception:
                pass

    def run_attack_cycle(self):
        print("\n" + "=" * 70)
        print(" EXECUTING 18-STEP ATTACK CYCLE FROM ATTACKER HOST (10.0.0.66)")
        print("=" * 70)
        attacker = self.net.get("attacker")
        cycle_script = str(PROJECT_ROOT / "scripts" / "run_cycle.py")
        venv_python = Path.home() / "ascend-pg-venv" / "bin" / "python3"
        if venv_python.exists():
            python_cmd = str(venv_python)
        else:
            python_cmd = sys.executable
        proc = attacker.popen([python_cmd, cycle_script])
        proc.wait()
        print("\n[+] Cycle execution completed. Verdicts saved to data/cycle_report.json.")

    def pingall(self):
        print("\nTesting connectivity across all 7 hosts...")
        self.net.pingAll()

    def open_cli(self):
        print("\n[Entering Mininet Interactive CLI. Type 'exit' to return to menu.]")
        CLI(self.net)

    def view_log_summary(self):
        log_store = PROJECT_ROOT / "data" / "log_store.json"
        if log_store.exists():
            import json
            try:
                data = json.loads(log_store.read_text())
                print(f"\nTotal Logged Events: {len(data)}")
                recent = data[-5:] if len(data) >= 5 else data
                for item in recent:
                    print(f" - [{item.get('timestamp', 'N/A')}] {item.get('stage')}: {item.get('action')} ({item.get('technique')})")
            except Exception as e:
                print(f"Error reading log: {e}")
        else:
            print("\nNo events logged yet in data/log_store.json.")

    def view_network_logs(self):
        import json
        modbus_log = PROJECT_ROOT / "data" / "modbus_log.json"
        flow_log = PROJECT_ROOT / "data" / "flow_log.json"

        print("\n" + "=" * 70)
        print(" NETWORK LOG SUMMARY")
        print("=" * 70)

        if modbus_log.exists():
            try:
                data = json.loads(modbus_log.read_text())
                print(f"\nModbus Packets: {len(data)}")
                if data:
                    funcs = {}
                    for pkt in data:
                        fn = pkt.get("function_name", "unknown")
                        funcs[fn] = funcs.get(fn, 0) + 1
                    for fn, count in sorted(funcs.items(), key=lambda x: -x[1])[:5]:
                        print(f"  {fn}: {count}")
            except Exception as e:
                print(f"  Error reading modbus log: {e}")
        else:
            print("\nModbus log: No data yet")

        if flow_log.exists():
            try:
                data = json.loads(flow_log.read_text())
                print(f"\nNetwork Flows: {len(data)}")
                if data:
                    total_bytes = sum(f.get("total_bytes", 0) for f in data)
                    total_pkts = sum(f.get("total_packets", 0) for f in data)
                    print(f"  Total bytes: {total_bytes:,}")
                    print(f"  Total packets: {total_pkts:,}")
            except Exception as e:
                print(f"  Error reading flow log: {e}")
        else:
            print("\nFlow log: No data yet")

    def cleanup(self):
        print("\n\nShutting down ASCEND-PG testbed...")
        self.stop_loggers()
        if hasattr(self, 'ppo_watcher_proc') and self.ppo_watcher_proc is not None:
            self.ppo_watcher_proc.terminate()
        if self.scada_proc:
            self.scada_proc.terminate()
        for p in self.plc_procs:
            p.terminate()
        if self.suricata_proc:
            self.suricata_proc.terminate()
        if self.net:
            self.net.stop()
        print("Cleanup complete. All testbed services stopped.")

    def run_ppo_watcher(self):
        print("\n" + "=" * 70)
        print(" STARTING PPO STEP WATCHER ON ATTACKER HOST")
        print("=" * 70)
        print(" The watcher will poll data/pending_step.json for attack commands")
        print(" from the Streamlit Live Battle page and execute them on the")
        print(" Mininet attacker host.")
        print(" Press Ctrl+C in the watcher terminal to stop.")
        print("=" * 70)
        attacker = self.net.get("attacker")
        watcher_script = str(PROJECT_ROOT / "scripts" / "ppo_step_watcher.py")
        venv_python = Path.home() / "ascend-pg-venv" / "bin" / "python3"
        if venv_python.exists():
            python_cmd = str(venv_python)
        else:
            python_cmd = sys.executable
        proc = attacker.popen([python_cmd, watcher_script])
        print(f"\n[+] PPO Step Watcher launched on attacker (PID: {proc.pid})")
        print(f"    Python: {python_cmd}")
        print("    You can now use the Live Battle page in 'PPO + Real Testbed' mode.")
        print("    The watcher runs in the background. Use menu option [7] to check status.")
        self.ppo_watcher_proc = proc

    def check_ppo_watcher(self):
        if hasattr(self, 'ppo_watcher_proc') and self.ppo_watcher_proc is not None:
            poll = self.ppo_watcher_proc.poll()
            if poll is None:
                print(f"\n[+] PPO Step Watcher is running (PID: {self.ppo_watcher_proc.pid})")
            else:
                print(f"\n[!] PPO Step Watcher has exited (code: {poll})")
                self.ppo_watcher_proc = None
        else:
            print("\n[!] PPO Step Watcher is not running. Use menu option [6] to start it.")

    def menu_loop(self):
        while self.running:
            print("\n" + "=" * 70)
            print(" ASCEND-PG ONE-SHOT TESTBED DASHBOARD")
            print("=" * 70)
            print(" [1] Run 16-Step Automated Attack Cycle")
            print(" [2] Ping All Hosts (Connectivity Sanity Check)")
            print(" [3] View Recent Logged Events")
            print(" [4] View Network Logs (Modbus/Flow)")
            print(" [5] Open Interactive Mininet CLI")
            print(" [6] Exit & Stop Testbed")
            print(" --- PPO Integration ---")
            print(" [7] Start PPO Step Watcher (for Live Battle page)")
            print(" [8] Check PPO Watcher Status")
            print("=" * 70)
            try:
                choice = input("Select an option [1-8]: ").strip()
                if choice == "1":
                    self.run_attack_cycle()
                elif choice == "2":
                    self.pingall()
                elif choice == "3":
                    self.view_log_summary()
                elif choice == "4":
                    self.view_network_logs()
                elif choice == "5":
                    self.open_cli()
                elif choice == "6" or choice.lower() in ("exit", "quit", "q"):
                    self.running = False
                elif choice == "7":
                    self.run_ppo_watcher()
                elif choice == "8":
                    self.check_ppo_watcher()
                else:
                    print("Invalid option. Enter 1 to 8.")
            except (KeyboardInterrupt, EOFError):
                self.running = False


def main():
    orch = TestbedOrchestrator()
    orch.check_root()

    # Handle Ctrl+C gracefully
    def sig_handler(sig, frame):
        orch.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        orch.clean_stale()
        orch.start_network()
        orch.start_plcs()
        orch.start_scada()
        orch.start_suricata()
        orch.start_loggers()
        orch.menu_loop()
    finally:
        orch.cleanup()


if __name__ == "__main__":
    main()
