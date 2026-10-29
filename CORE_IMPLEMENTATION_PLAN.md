# Goal
Swap the Mininet emulation backend with the CORE (Common Open Research Emulator) backend. We will implement this in a way that allows you to open the topology in the CORE GUI, visually drag-and-drop new routers, switches, and hosts, and then run the AI agent against that customized visual network.

## User Review Required
> [!WARNING]
> **WSL GUI Support Required**
> Because you want to use the Drag-and-Drop GUI, you must be able to run Linux graphical apps from your WSL environment. 
> - If you are on Windows 11, **WSLg** is built-in and `core-gui` will pop up automatically.
> - If you are on Windows 10, you may need an X-Server (like VcXsrv or Xming) running in the background.

> [!IMPORTANT]
> **CORE Installation Instructions**
> ```bash
> sudo add-apt-repository ppa:vnsec/core-network
> sudo apt-get update
> sudo apt-get install core-network core-network-daemon core-network-gui
> ```

## Proposed Changes

To enable the drag-and-drop feature, we will change how the testbed is initialized. Instead of the Python script silently forcing the network to start in the background (like Mininet), we will generate a file that you can open and edit in the GUI.

### testbed/

#### [NEW] `testbed/generate_core_topo.py`
A new script that reads your Pandapower grid (e.g., IEEE-30) and generates a `core_topology.xml` file. It will automatically place all the Generators, RTUs, and Firewalls on the canvas, pre-configured to run your `plc_server.py`.

#### [MODIFY] `testbed/grid_env.py` (or a new `core_env.py`)
Instead of building the network from scratch, the environment script will now look for the *currently running* CORE session (the one you hit "Start" on in the GUI). It will connect to the running nodes, verify they are alive, and allow the RL agent to execute attacks against them.

## New Workflow for You:
1. Run `python testbed/generate_core_topo.py --case 30`.
2. Type `core-gui` in your WSL terminal. The desktop app will open.
3. **File -> Open -> `core_topology.xml`**. You will see the entire IEEE-30 grid.
4. **Drag and Drop:** Use the left toolbar to drag in extra routers, switches, or attacker Kali Linux hosts. Draw lines to connect them.
5. Hit the **Play** button in the GUI to instantiate the Linux containers.
6. Launch the dedicated GUI with `.venv-wsl/bin/python -m gui.server` and open `http://127.0.0.1:8765` to use the existing runtime and campaign controls.
