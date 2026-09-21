"""Risk aggregation. A risk score is an aggregated security score, not a calibrated
probability of attack -- it only orders decisions against the two thresholds below.

Each module returns its own [0,1] score for its category. `aggregate` combines them with
diminishing weight per rank (largest signal at full weight, next at half, next at a quarter,
...) instead of summing blindly, because several categories are frequently built from the same
underlying evidence (e.g. "argument introduced by untrusted content" feeds injection, goal
mismatch, and multistep history all at once). Weights are documented per category below and
must not be duplicated as magic numbers elsewhere.
"""

from __future__ import annotations

BASE_RISK = 0.05
BLOCK_THRESHOLD = 0.8
ESCALATE_THRESHOLD = 0.5

# Per-category weight applied before ranking. "policy" already encodes near-hard signals
# (missing confirmation, missing prerequisite) on its own [0,1] scale, so it gets full weight.
WEIGHTS: dict[str, float] = {
    "policy": 1.0,
    "injection": 0.55,
    "goal_mismatch": 0.35,
    "data_flow": 0.6,
    "history": 0.35,
    "memory": 0.5,
}

_RANK_DISCOUNT = (1.0, 0.5, 0.25, 0.15, 0.1)


def clamp(risk: float) -> float:
    return max(0.0, min(risk, 1.0))


def aggregate(base: float, category_scores: dict[str, float]) -> float:
    weighted = sorted(
        (WEIGHTS.get(category, 0.3) * score, category) for category, score in category_scores.items() if score > 0
    )
    weighted.reverse()
    total = base
    for rank, (contribution, _category) in enumerate(weighted):
        discount = _RANK_DISCOUNT[rank] if rank < len(_RANK_DISCOUNT) else _RANK_DISCOUNT[-1]
        total += contribution * discount
    return clamp(total)
