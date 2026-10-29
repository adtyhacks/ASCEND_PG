"""Finding DVS v1: explicit severity plus verified adverse observations, 0..100.

Policy weights are not empirical measurements or a standard. Historical campaign
events lack corroborating bundles. Missing evidence is neutral. Evidence v2 is
documented in docs/EVALUATION_PARAMETERS.md.
"""

SEVERITY_POINTS = {"INFORMATIONAL": 0, "INFO": 0, "LOW": 5,
                   "MEDIUM": 10, "HIGH": 15, "CRITICAL": 20}
IMPACT_POINTS = {"integrity": 10, "availability": 10, "confidentiality": 5,
                 "operational_impact": 15, "physical_impact": 20, "safety_impact": 20}
SOURCES = {"integrity": "target_readback", "availability": "service_observation",
           "confidentiality": "collection_verification",
           "operational_impact": "process_measurement",
           "physical_impact": "physical_measurement", "safety_impact": "safety_measurement"}
SUCCESS = {"SUCCESS", "DETECTED", "UNDETECTED"}


def compute_finding_dvs(attack_severity, execution_result, verified_impact=None,
                        *, correlation_id=None, start_time=None, end_time=None,
                        evidence_bundle=None, evidence_identity=None):
    """Do not infer observations from detection, technique or execution success.

    Each impact dimension is binary: zero or its full policy weight. FAILED and
    TIMEOUT can retain corroborated in-window partial effects. Legacy claim flags
    alone never establish impact; references must resolve to retained facts.
    No quantitative magnitude, criticality, duration or detector-confidence multiplier
    is supported. Invalid/missing severity or execution status means not assessed.
    """
    severity = str(attack_severity or "").strip().upper()
    status = str(execution_result or "").strip().upper()
    breakdown = {"severity": {"points": 0, "maximum": 20, "state": "unknown"}}
    breakdown.update({name: {"points": 0, "maximum": points, "state": "unknown"}
                      for name, points in IMPACT_POINTS.items()})
    if severity not in SEVERITY_POINTS or status not in SUCCESS | {"FAILED", "TIMEOUT"}:
        return {"score": None, "breakdown": breakdown, "verified_impact": None,
                "reason": "Not assessed: explicit attack severity or executor status is missing/unsupported.",
                "version": "finding-dvs-v1"}
    breakdown["severity"].update(points=SEVERITY_POINTS[severity], state="recorded")
    accepted = {}
    from metrics.finding_evidence import verify_impacts
    identity = dict(evidence_identity or {})
    identity["correlation_id"] = correlation_id
    verified = verify_impacts(evidence_bundle, identity, start_time, end_time)
    for dimension in IMPACT_POINTS:
        verdict = verified[dimension]
        breakdown[dimension].update(state=verdict["state"], reason=verdict["reason"], references=verdict["references"])
        if verdict["state"] == "verified_adverse":
            breakdown[dimension]["points"] = IMPACT_POINTS[dimension]
            accepted[dimension] = verdict
    score = round(float(min(100, max(0, sum(c["points"] for c in breakdown.values())))), 1)
    reason = (f"Recorded attack severity contributes {SEVERITY_POINTS[severity]}/20; "
              f"verified adverse effects contribute {score - SEVERITY_POINTS[severity]:.1f}/80. "
              "Detection, requested magnitude and traffic contribute zero. "
              + ("No verified adverse impact credited; unknown dimensions are not verified absence."
                 if not accepted else "Corroborated in-window effects retained, including partial effects before failure/timeout.")
              + " States: " + ", ".join(f"{d}={verified[d]['state']}" for d in IMPACT_POINTS))
    return {"score": score, "breakdown": breakdown, "verified_impact": accepted or None,
            "reason": reason, "version": "finding-dvs-v1"}
