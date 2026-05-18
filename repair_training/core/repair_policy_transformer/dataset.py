from __future__ import annotations

from pathlib import Path

from repair_training.core.datasets import read_jsonl, split_rows
from repair_training.core.repair_policy_transformer.schema import PolicyGraphTrainingSample, sample_from_dict


def read_policy_graph_samples(path: str | Path) -> list[PolicyGraphTrainingSample]:
    return [sample_from_dict(row) for row in read_jsonl(path)]


def split_policy_graph_samples(samples: list[PolicyGraphTrainingSample]) -> dict[str, list[PolicyGraphTrainingSample]]:
    rows = [sample.to_dict() for sample in samples]
    splits = split_rows(rows, key_fn=lambda row: str((row.get("source") or {}).get("episode_id") or row.get("sample_id") or ""))
    return {name: [sample_from_dict(row) for row in split_rows_] for name, split_rows_ in splits.items()}

