"""Shared three-state detector semantics, independent of attack execution."""


def detection_result(record):
    evidence = record.get("evidence") or {}
    # A correlated alert is positive evidence even if execution subsequently failed.
    if record.get("event_type") == "detection" or str(record.get("result", "")).lower() == "detected":
        return True
    for source in (record, evidence):
        if source.get("detection_evaluated") is False:
            return None
        for field in ("detected", "Detected", "combined_detected"):
            if type(source.get(field)) is bool:
                return source[field]
    # Historical executor assigned these methods ONLY on a positive verdict,
    # before its FAILED/TIMEOUT branch accidentally cleared the boolean.
    method = record.get("detection_method") or evidence.get("detection_method")
    if method in {"ml", "suricata", "both"}:
        return True
    if str(record.get("result", "")).lower() == "undetected" or evidence.get("return_status") == "UNDETECTED":
        return False
    return None


def detection_label(value):
    return "Detected" if value is True else "Not Detected" if value is False else "Detection Not Available / Not Evaluated"


def technical_details(event):
    from data.mitre_registry import get_display_technique
    tid = event.get("mitre_technique") or event.get("MITRE ID") or event.get("technique_id")
    tech = get_display_technique(tid) or {}
    evidence = event.get("evidence") or {}
    details = {"Framework": "MITRE ATT&CK for ICS", "Technique ID": tid,
            "Technique": tech.get("name", "Unmapped technique"),
            "Tactic": tech.get("tactic", "Unavailable"),
            "Internal Identifier": event.get("Internal Identifier") or evidence.get("step_name") or tech.get("default_step"),
            "Detection Method": event.get("Detection Method") or event.get("detection_method") or evidence.get("detection_method", "Unavailable"),
            "Detection Result": detection_label(detection_result(event)),
            "Suricata SIDs": tech.get("detect_sids", [])}
    if tech.get("replacement_id"):
        details["Current MITRE ID"] = tech["replacement_id"]
        details["Catalog Status"] = tech["catalog_status"]
    return details


def decorate_event(event):
    return {**event, "detected": detection_result(event), "technical_details": technical_details(event)}
