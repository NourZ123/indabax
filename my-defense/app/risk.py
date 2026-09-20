"""Risk scoring thresholds and decision cutoffs."""

BASE_RISK = 0.05
BLOCK_THRESHOLD = 0.8
ESCALATE_THRESHOLD = 0.5

INJECTION_STRONG = 0.55
INJECTION_WEAK = 0.25
SENSITIVE_STRONG = 0.6
SENSITIVE_WEAK = 0.2
MISSING_CONFIRMATION_WEIGHT = 0.4


def clamp(risk: float) -> float:
    return min(risk, 1.0)
