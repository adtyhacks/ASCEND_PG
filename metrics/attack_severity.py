"""Canonical capability policy; severity is independent of detection/outcome."""
from data.mitre_registry import get_technique_by_id

# Derived from the implemented operations, not the registry's mock probabilities.
# T0806's implementation reads/enumerates I/O despite the registry's write wording.
DISCOVERY = {"T0846", "T0888", "T0840", "T0842"}
COLLECTION = {"T0886", "T0801", "T0802", "T0806"}


def resolve_attack_severity(metadata):
    technique_id = metadata.get("technique_id", "")
    technique = get_technique_by_id(technique_id)
    if technique is None:
        return {"severity": "HIGH", "reason": "Unknown implementation: conservative legacy HIGH fallback.",
                "policy": "attack-capability-v1"}
    canonical_id = technique["id"]
    step = metadata.get("step_name")
    if step and step not in {technique["default_step"], *technique.get("variants", [])}:
        return {"severity": "HIGH", "reason": "Technique/implementation mismatch: conservative HIGH fallback.",
                "policy": "attack-capability-v1"}
    if canonical_id in DISCOVERY:
        severity, reason = "LOW", "Discovery/fingerprinting probe; no implemented state modification."
    elif canonical_id in COLLECTION:
        severity, reason = "MEDIUM", "Remote access/collection or I/O enumeration; information-access capability."
    else:
        severity, reason = "HIGH", "State modification, interception or control/service interference capability."
    return {"severity": severity, "reason": reason + " Actual consequences require separate evidence.",
            "policy": "attack-capability-v1"}
