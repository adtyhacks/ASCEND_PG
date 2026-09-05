#!/usr/bin/env python3
"""Label CICFlowMeter output using ASCEND-PG campaign episode windows.

The input flow CSV must come from a PCAP captured during one ASCEND-PG
testbed session. Labels are assigned by the step windows saved in
``data/cycle_report.json`` rather than random row sampling. This preserves
episode provenance for proper train/validation/test splits.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


DEFAULT_REPO = Path(__file__).resolve().parent.parent
DEFAULT_REPORT = DEFAULT_REPO / "data" / "cycle_report.json"
TIMESTAMP_CANDIDATES = ("Timestamp", "timestamp", "Flow Start", "FlowStart")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", required=True, type=Path,
                        help="CICFlowMeter CSV exported from one captured PCAP")
    parser.add_argument("--report", default=DEFAULT_REPORT, type=Path,
                        help="campaign cycle_report.json with step windows")
    parser.add_argument("--output", required=True, type=Path,
                        help="destination labeled flow CSV")
    parser.add_argument("--manifest", type=Path,
                        help="optional output JSON manifest (defaults beside --output)")
    parser.add_argument("--timestamp-column",
                        help="flow-start timestamp column; auto-detected if omitted")
    parser.add_argument("--source", default="ascend_pg_testbed")
    parser.add_argument("--scenario-id", required=True,
                        help="immutable ID for this capture/campaign session")
    parser.add_argument("--topology-id", default="ieee14_default")
    return parser.parse_args()


def resolve_timestamp_column(frame: pd.DataFrame, requested: str | None) -> str:
    if requested:
        if requested not in frame.columns:
            raise ValueError(f"Timestamp column {requested!r} does not exist.")
        return requested
    for candidate in TIMESTAMP_CANDIDATES:
        if candidate in frame.columns:
            return candidate
    raise ValueError(
        "No timestamp column found. Pass --timestamp-column explicitly. "
        f"Columns include: {', '.join(map(str, frame.columns[:20]))}"
    )


def attack_type_for_step(step_name: str) -> str:
    name = step_name.lower()
    if "fdi" in name:
        return "fdi"
    if "dos" in name:
        return "dos"
    if "recon" in name:
        return "recon"
    if "replay" in name:
        return "replay"
    if "mitm" in name:
        return "mitm"
    return name


def main() -> None:
    args = parse_arguments()
    if not args.flows.is_file():
        raise FileNotFoundError(f"Flow CSV not found: {args.flows}")
    if not args.report.is_file():
        raise FileNotFoundError(f"Cycle report not found: {args.report}")

    frame = pd.read_csv(args.flows, low_memory=False)
    timestamp_column = resolve_timestamp_column(frame, args.timestamp_column)
    timestamps = pd.to_datetime(frame[timestamp_column], utc=True, errors="coerce")
    invalid_timestamps = int(timestamps.isna().sum())
    if invalid_timestamps:
        raise ValueError(
            f"{invalid_timestamps} flow rows have unparseable timestamps in "
            f"{timestamp_column!r}. Fix the export/time zone before labeling."
        )

    report = json.loads(args.report.read_text(encoding="utf-8"))
    steps = report.get("steps", [])
    if not steps:
        raise ValueError("Cycle report contains no steps; cannot create labels.")

    labeled = frame.copy()
    labeled.insert(0, "timestamp_utc", timestamps.dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    labeled.insert(1, "source", args.source)
    labeled.insert(2, "scenario_id", args.scenario_id)
    labeled.insert(3, "episode_id", args.scenario_id)
    labeled.insert(4, "topology_id", args.topology_id)
    labeled.insert(5, "step_id", "normal")
    labeled.insert(6, "attack_type", "normal")
    labeled.insert(7, "mitre_technique", "N/A")
    labeled.insert(8, "label_binary", 0)
    labeled.insert(9, "label_multiclass", "normal")

    assigned_counts: dict[str, int] = {}
    for step in steps:
        start = pd.to_datetime(step["start"], utc=True)
        end = pd.to_datetime(step["end"], utc=True)
        name = str(step["name"])
        technique = "+".join(step.get("techniques", [])) or "N/A"
        mask = (timestamps >= start) & (timestamps <= end)
        count = int(mask.sum())
        assigned_counts[name] = count
        labeled.loc[mask, "step_id"] = name
        labeled.loc[mask, "attack_type"] = attack_type_for_step(name)
        labeled.loc[mask, "mitre_technique"] = technique
        labeled.loc[mask, "label_binary"] = 1
        labeled.loc[mask, "label_multiclass"] = attack_type_for_step(name)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    labeled.to_csv(args.output, index=False)

    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest = {
        "source": args.source,
        "scenario_id": args.scenario_id,
        "topology_id": args.topology_id,
        "input_flow_csv": str(args.flows),
        "cycle_report": str(args.report),
        "timestamp_column": timestamp_column,
        "row_count": int(len(labeled)),
        "normal_rows": int((labeled["label_binary"] == 0).sum()),
        "attack_rows": int((labeled["label_binary"] == 1).sum()),
        "assigned_rows_by_step": assigned_counts,
        "labeling_rule": "flow-start timestamp inside campaign step window",
        "warning": (
            "Split by episode_id/scenario_id, never randomly by row. "
            "Review zero-row steps for capture clock/time-zone mismatch."
        ),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(labeled)} labeled flows to {args.output}")
    print(f"Wrote labeling manifest to {manifest_path}")
    for step_name, count in assigned_counts.items():
        print(f"  {step_name}: {count} flow rows")


if __name__ == "__main__":
    main()
