import numpy as np
import pandas as pd


def inject_fdi(traffic_df, bias=0.08, fraction=0.15, seed=1):
    """
    False Data Injection: attacker adds a deliberate, sustained bias to
    voltage readings on a subset of packets — mimics a manipulated sensor
    feeding falsified measurements into the control system.
    """
    rng = np.random.default_rng(seed)
    df = traffic_df.copy()
    n_target = int(len(df) * fraction)
    target_idx = rng.choice(df.index, size=n_target, replace=False)
    df.loc[target_idx, "voltage_pu"] += bias
    df["is_attacked"] = False
    df.loc[target_idx, "is_attacked"] = True
    return df


def inject_dos(traffic_df, flood_factor=6, seed=2):
    """
    Denial of Service: attacker floods the network with a burst of
    abnormally frequent, small packets aimed at a single bus.
    """
    rng = np.random.default_rng(seed)
    df = traffic_df.copy()
    target_bus = rng.choice(df["dst_bus"].unique())
    n_flood = len(df) * flood_factor
    flood_rows = pd.DataFrame({
        "timestamp": df["timestamp"].max() + pd.to_timedelta(np.arange(n_flood) * 0.01, unit="s"),
        "src_bus": rng.choice(df["src_bus"].unique(), size=n_flood),
        "dst_bus": target_bus,
        "packet_size_bytes": rng.integers(64, 100, size=n_flood),  # abnormally small, rapid packets
        "voltage_pu": rng.normal(1.0, 0.01, size=n_flood),
        "is_attacked": True,
    })
    df["is_attacked"] = False
    return pd.concat([df, flood_rows], ignore_index=True)


def inject_replay(traffic_df, fraction=0.15, seed=3):
    """
    Replay attack: attacker re-sends old, legitimate-looking packets with
    stale timestamps out of chronological order.
    """
    rng = np.random.default_rng(seed)
    df = traffic_df.copy()
    n_target = int(len(df) * fraction)
    replay_idx = rng.choice(df.index[: len(df) // 2], size=n_target, replace=False)
    replayed = df.loc[replay_idx].copy()
    replayed["timestamp"] = df["timestamp"].max() + pd.to_timedelta(1, unit="s")  # stale data resent "now"
    replayed["is_attacked"] = True
    df["is_attacked"] = False
    return pd.concat([df, replayed], ignore_index=True)


def inject_mitm(traffic_df, fraction=0.15, delay_secs=2.5, seed=4):
    """
    Man-in-the-Middle: attacker intercepts packets, reroutes them through
    an unexpected destination, and adds transmission delay.
    """
    rng = np.random.default_rng(seed)
    df = traffic_df.copy()
    n_target = int(len(df) * fraction)
    target_idx = rng.choice(df.index, size=n_target, replace=False)
    all_buses = df["dst_bus"].unique()
    df.loc[target_idx, "dst_bus"] = rng.choice(all_buses, size=n_target)  # rerouted
    df.loc[target_idx, "timestamp"] += pd.to_timedelta(delay_secs, unit="s")  # added latency
    df["is_attacked"] = False
    df.loc[target_idx, "is_attacked"] = True
    return df


ATTACK_FUNCTIONS = {
    "FDI": inject_fdi,
    "DoS": inject_dos,
    "Replay": inject_replay,
    "MITM": inject_mitm,
}