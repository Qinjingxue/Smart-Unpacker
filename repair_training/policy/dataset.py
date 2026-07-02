from __future__ import annotations

from pathlib import Path

from repair_training.data.io import read_jsonl, split_rows
from sunpack.repair.model.policy.schema import (
    PolicyGraphTrainingSample,
    PolicyGraphTransitionSample,
    PolicyWorldTrainingSample,
    sample_from_dict,
    transition_sample_from_dict,
    world_sample_from_dict,
)


def read_policy_graph_samples(path: str | Path) -> list[PolicyGraphTrainingSample]:
    return [sample_from_dict(row) for row in read_jsonl(path)]


def read_policy_transition_samples(path: str | Path) -> list[PolicyGraphTransitionSample]:
    return [transition_sample_from_dict(row) for row in read_jsonl(path)]


def read_policy_world_samples(path: str | Path) -> list[PolicyWorldTrainingSample]:
    rows = read_jsonl(path)
    output: list[PolicyWorldTrainingSample] = []
    for row in rows:
        if row.get("schema_version") in {"repair_policy_graph_row_v1", "repair_policy_graph_row_v2"} or "actions" in row and "graph" in row and not row.get("task"):
            ranking = sample_from_dict(row)
            output.append(world_sample_from_dict({
                "task": "ranking",
                "sample_id": ranking.sample_id,
                "format": ranking.format,
                "graph": ranking.graph,
                "current_node_id": ranking.current_node_id,
                "best_node_id": ranking.best_node_id,
                "actions": [action.to_dict() for action in ranking.actions],
                "ranking_sample": ranking.to_dict(),
                "source": ranking.source,
            }))
        else:
            output.append(world_sample_from_dict(row))
    return output


def split_policy_graph_samples(samples: list[PolicyGraphTrainingSample]) -> dict[str, list[PolicyGraphTrainingSample]]:
    rows = [sample.to_dict() for sample in samples]
    splits = split_rows(rows, key_fn=lambda row: str((row.get("source") or {}).get("episode_id") or row.get("sample_id") or ""))
    return {name: [sample_from_dict(row) for row in split_rows_] for name, split_rows_ in splits.items()}


def split_policy_world_samples(samples: list[PolicyWorldTrainingSample]) -> dict[str, list[PolicyWorldTrainingSample]]:
    rows = [sample.to_dict() for sample in samples]
    splits = split_rows(rows, key_fn=lambda row: str((row.get("source") or {}).get("episode_id") or row.get("sample_id") or ""))
    return {name: [world_sample_from_dict(row) for row in split_rows_] for name, split_rows_ in splits.items()}
