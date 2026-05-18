from __future__ import annotations

from typing import Any


def top1_action_accuracy(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = 0
    hits = 0
    for row in rows:
        actions = row.get("action_scores") if isinstance(row.get("action_scores"), list) else []
        if not actions:
            continue
        total += 1
        best = max(actions, key=lambda item: float(item.get("score") or 0.0))
        hits += 1 if float(best.get("action_prior") or 0.0) >= 0.5 else 0
    return {"top1_action_prior_accuracy": hits / max(1, total), "samples": total}

