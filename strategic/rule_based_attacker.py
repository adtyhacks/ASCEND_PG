"""
Deterministic adaptive attacker — no ML training required.
Satisfies "attack sequence changes according to defense" via explicit rules:
if an attack type keeps getting detected, switch to a different one.
"""

ATTACK_TYPES = ["FDI", "DoS", "Replay", "MITM"]

class RuleBasedAttacker:
    def __init__(self):
        self.detection_history = {a: [] for a in ATTACK_TYPES}

    def choose_attack(self):
        """Pick the attack type with the lowest recent detection rate."""
        detection_rates = {}
        for attack, history in self.detection_history.items():
            recent = history[-5:]  # look at last 5 attempts of this type
            if len(recent) == 0:
                detection_rates[attack] = 0.0  # untried attacks are prioritized first
            else:
                detection_rates[attack] = sum(recent) / len(recent)

        # Choose the attack type currently evading detection best
        best_attack = min(detection_rates, key=detection_rates.get)
        return best_attack

    def record_result(self, attack_type, was_detected: bool):
        self.detection_history[attack_type].append(1 if was_detected else 0)