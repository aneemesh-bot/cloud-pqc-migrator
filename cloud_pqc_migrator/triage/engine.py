from __future__ import annotations

from cloud_pqc_migrator.models import CBoM, Gap
from .rules import evaluate_tls, evaluate_kms, evaluate_iam


def evaluate(cbom: CBoM, t_proj_months: int = 6) -> list[Gap]:
    """
    Run all rule sets against every CryptoAsset in the CBoM.
    Returns a deduplicated list of Gap objects sorted by priority (1=CRITICAL first).
    """
    seen_ids: set[str] = set()
    all_gaps: list[Gap] = []

    for asset in cbom.assets:
        for rule_fn in (evaluate_tls, evaluate_kms, evaluate_iam):
            for gap in rule_fn(asset):
                if gap.gap_id not in seen_ids:
                    seen_ids.add(gap.gap_id)
                    all_gaps.append(gap)

    all_gaps.sort(key=lambda g: (g.priority.value, g.asset.resource_id))
    return all_gaps
