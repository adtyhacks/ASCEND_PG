"""Human-readable aliases for opaque ASCEND runtime identifiers.

This module is presentation-only.  It derives stable ordinals from persisted
run metadata and canonical event chronology, and never rewrites those sources.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

from testbed import run_store


_STEP_ID = re.compile(r"^step-(\d+)(?:-|$)", re.IGNORECASE)


def _present(value: Any) -> bool:
    return value is not None and str(value).strip() not in {"", "N/A", "NONE"}


def _ordered_unique(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not _present(value):
            continue
        key = str(value)
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def _run_key(run: dict[str, Any]) -> tuple[str, str, str]:
    return (str(run.get("started_at") or run.get("created_at") or ""),
            str(run.get("scenario_id") or ""), str(run.get("run_id") or ""))


def _event_value(event: dict[str, Any], canonical: str, normalized: str) -> Any:
    if canonical in event:
        return event.get(canonical)
    if normalized in event:
        return event.get(normalized)
    evidence = event.get("Evidence") or event.get("evidence") or {}
    attack = evidence.get("attack") if isinstance(evidence, dict) else None
    return attack.get(canonical) if isinstance(attack, dict) else None


def _step_number(event: dict[str, Any]) -> int | None:
    for key in ("ppo_step", "Step", "current_step"):
        value = event.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    correlation = _event_value(event, "correlation_id", "Correlation ID")
    match = _STEP_ID.match(str(correlation or ""))
    return int(match.group(1)) if match else None


class IdentifierAliases:
    """One reusable alias registry for GUI and report presentation."""

    def __init__(self, runs: Iterable[dict[str, Any]] = (), events: Iterable[dict[str, Any]] = ()):
        ordered_runs = sorted((dict(run) for run in runs), key=_run_key)
        self._assessment = {value: index for index, value in enumerate(
            _ordered_unique(run.get("run_id") for run in ordered_runs), 1)}
        self._session = {value: index for index, value in enumerate(
            _ordered_unique(run.get("core_session_id") for run in ordered_runs), 1)}
        self._generation = {value: index for index, value in enumerate(
            _ordered_unique(run.get("generation_id") for run in ordered_runs), 1)}

        event_rows = [dict(event) for event in events]
        correlations: dict[tuple[str, str], tuple[int, str, str]] = {}
        for event in event_rows:
            correlation = _event_value(event, "correlation_id", "Correlation ID")
            if not _present(correlation):
                continue
            run_id = _event_value(event, "run_id", "Run ID") or ""
            step = _step_number(event)
            key = (str(run_id), str(correlation))
            order = (step if step is not None else 2**31,
                     str(_event_value(event, "timestamp", "Timestamp") or ""), str(correlation))
            correlations[key] = min(correlations.get(key, order), order)
        ordered_correlations = sorted(correlations, key=lambda key: (key[0], correlations[key]))
        per_run: dict[str, int] = {}
        self._event: dict[tuple[str, str], int] = {}
        for key in ordered_correlations:
            per_run[key[0]] = per_run.get(key[0], 0) + 1
            self._event[key] = per_run[key[0]]

    @staticmethod
    def _label(mapping: dict[str, int], value: Any, prefix: str) -> str | None:
        if not _present(value):
            return None
        number = mapping.get(str(value))
        return f"{prefix} {number}" if number is not None else None

    def assessment(self, run_id: Any) -> str | None:
        return self._label(self._assessment, run_id, "Assessment")

    def core_session(self, session_id: Any) -> str | None:
        return self._label(self._session, session_id, "CORE Session")

    def runtime_generation(self, generation_id: Any) -> str | None:
        return self._label(self._generation, generation_id, "Runtime Generation")

    def attack_event(self, correlation_id: Any, run_id: Any = None) -> str | None:
        if not _present(correlation_id):
            return None
        number = self._event.get((str(run_id or ""), str(correlation_id)))
        if number is None:
            match = _STEP_ID.match(str(correlation_id))
            number = int(match.group(1)) if match else None
        return f"Attack Event {number}" if number is not None else None

    def attack_step(self, event: dict[str, Any]) -> str | None:
        number = _step_number(event)
        if number is None:
            correlation = _event_value(event, "correlation_id", "Correlation ID")
            run_id = _event_value(event, "run_id", "Run ID") or ""
            number = self._event.get((str(run_id), str(correlation)))
        return f"Attack Step {number}" if number is not None else None

    def run_identity(self, run: dict[str, Any] | None) -> dict[str, Any]:
        run = run or {}
        return {
            "assessment": {"display_name": self.assessment(run.get("run_id")), "internal_id": run.get("run_id")},
            "core_session": {"display_name": self.core_session(run.get("core_session_id")), "internal_id": run.get("core_session_id")},
            "runtime_generation": {"display_name": self.runtime_generation(run.get("generation_id")), "internal_id": run.get("generation_id")},
        }

    def decorate_event(self, event: dict[str, Any]) -> dict[str, Any]:
        row = dict(event)
        correlation = _event_value(row, "correlation_id", "Correlation ID")
        run_id = _event_value(row, "run_id", "Run ID")
        row["display_identity"] = {
            "attack_step": self.attack_step(row),
            "attack_event": self.attack_event(correlation, run_id),
        }
        return row


def aliases_for(runs: Iterable[dict[str, Any]], events: Iterable[dict[str, Any]] = ()) -> IdentifierAliases:
    return IdentifierAliases(runs, events)


def saved_run_metadata() -> list[dict[str, Any]]:
    """Read valid saved run metadata in newest-first display order."""
    runs: list[dict[str, Any]] = []
    for path in run_store.RUNS.glob("*/*/run.json"):
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
            if run["scenario_id"] != path.parent.parent.name or run["run_id"] != path.parent.name:
                continue
            run_store._path(run["scenario_id"], run["run_id"])
            runs.append(run)
        except (OSError, ValueError, KeyError):
            continue
    return sorted(runs, key=_run_key, reverse=True)
