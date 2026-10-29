import pandapower as pp
import pandapower.networks as pn
import pandas as pd
import numpy as np
from testbed.topology import run_power_flow

def build_baseline(n_packets=500, seed=42, case_name="case14"):
    """
    Loads the requested pandapower network, solves power flow, and generates a
    matching synthetic traffic log. Returns (net, grid_df, traffic_df).
    """
    if case_name == "case30":
        net = pn.case30()
    else:
        net = pn.case14()
        
    run_power_flow(net)

    grid_df = pd.DataFrame({
        "bus_id": net.res_bus.index,
        "voltage_pu": net.res_bus["vm_pu"].values,
        "voltage_angle_deg": net.res_bus["va_degree"].values,
    })

    rng = np.random.default_rng(seed)
    bus_ids = net.bus.index.tolist()
    inter_arrival = rng.exponential(scale=0.5, size=n_packets)
    timestamps = pd.to_datetime("2026-01-01") + pd.to_timedelta(np.cumsum(inter_arrival), unit="s")

    traffic_df = pd.DataFrame({
        "timestamp": timestamps,
        "src_bus": rng.choice(bus_ids, size=n_packets),
        "dst_bus": rng.choice(bus_ids, size=n_packets),
        "packet_size_bytes": rng.normal(300, 50, size=n_packets).clip(min=64).astype(int),
        "voltage_pu": rng.normal(1.0, 0.01, size=n_packets),
    })
    traffic_df = traffic_df[traffic_df["src_bus"] != traffic_df["dst_bus"]].reset_index(drop=True)

    return net, grid_df, traffic_df
