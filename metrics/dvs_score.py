"""Canonical DVS arithmetic, shared by evaluation and reports. No evaluation runs here.

This is the existing aggregate defence-posture metric, not a per-finding impact
score. Valid evaluation inputs produce scores from 7.5 to 100 (bounded 0..100).
"""
NUM_STAGES = 4

# DVS weights
W_EVASION = 0.30
W_CAMPAIGN = 0.30
W_STAGE_DEPTH = 0.25
W_PLATEAU = 0.15

RATING_BANDS = [
    (25, "Robust", "🟢", "Defenses withstand most attack campaigns."),
    (50, "Moderate", "🟡", "Some multi-stage attack paths succeed; targeted hardening needed."),
    (75, "Vulnerable", "🟠", "Majority of campaigns complete successfully; significant defense gaps."),
    (100, "Critical", "🔴", "Defenses comprehensively bypassed; immediate remediation required."),
]


def _get_rating(score: float) -> dict:
    """Maps a DVS score to a rating band."""
    for threshold, name, color, description in RATING_BANDS:
        if score <= threshold:
            return {"rating": name, "color": color, "description": description}
    return {"rating": "Critical", "color": "🔴", "description": RATING_BANDS[-1][3]}


def compute_dvs(eval_results: dict) -> dict:
    """
    Computes the Defense Vulnerability Score from evaluation results.

    Args:
        eval_results: dict from evaluate_agent()

    Returns:
        dict with score, rating, color, breakdown, description
    """
    # Sub-scores (each in [0, 100])
    evasion_score = eval_results["avg_evasion_rate"] * 100
    campaign_score = eval_results["completion_rate"] * 100
    stage_depth_score = (eval_results["avg_max_stage"] / (NUM_STAGES - 1)) * 100
    plateau_score = 100.0 if eval_results["plateau_detected"] else 50.0

    # Weighted composite
    dvs = (
        W_EVASION * evasion_score
        + W_CAMPAIGN * campaign_score
        + W_STAGE_DEPTH * stage_depth_score
        + W_PLATEAU * plateau_score
    )
    dvs = float(max(0, min(dvs, 100)))

    rating_info = _get_rating(dvs)

    breakdown = {
        "evasion": {
            "score": round(evasion_score, 1),
            "weight": W_EVASION,
            "weighted": round(W_EVASION * evasion_score, 1),
            "detail": f"Average evasion rate: {eval_results['avg_evasion_rate']:.1%}",
        },
        "campaign": {
            "score": round(campaign_score, 1),
            "weight": W_CAMPAIGN,
            "weighted": round(W_CAMPAIGN * campaign_score, 1),
            "detail": f"Campaign completion: {eval_results['completion_count']}/{eval_results['num_episodes']}",
        },
        "stage_depth": {
            "score": round(stage_depth_score, 1),
            "weight": W_STAGE_DEPTH,
            "weighted": round(W_STAGE_DEPTH * stage_depth_score, 1),
            "detail": f"Avg max stage reached: {eval_results['avg_max_stage']:.1f}/{NUM_STAGES - 1}",
        },
        "plateau": {
            "score": round(plateau_score, 1),
            "weight": W_PLATEAU,
            "weighted": round(W_PLATEAU * plateau_score, 1),
            "detail": f"Plateau {'detected' if eval_results['plateau_detected'] else 'not detected'}",
        },
    }

    return {
        "score": round(dvs, 1),
        "rating": rating_info["rating"],
        "color": rating_info["color"],
        "description": rating_info["description"],
        "breakdown": breakdown,
        "eval_summary": {
            "num_episodes": eval_results["num_episodes"],
            "avg_evasion_rate": round(eval_results["avg_evasion_rate"], 3),
            "completion_rate": round(eval_results["completion_rate"], 3),
            "avg_max_stage": round(eval_results["avg_max_stage"], 2),
            "avg_reward": round(eval_results["avg_reward"], 2),
            "plateau_detected": eval_results["plateau_detected"],
        },
    }


