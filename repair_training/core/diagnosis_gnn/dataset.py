from __future__ import annotations

from pathlib import Path

from repair_training.core.datasets import read_jsonl, split_rows
from sunpack.repair.model.diagnosis.graph_schema import DiagnosisGraphSample


def read_diagnosis_graph_samples(path: str | Path) -> list[DiagnosisGraphSample]:
    return [DiagnosisGraphSample.from_dict(row) for row in read_jsonl(path)]


def split_diagnosis_graph_samples(samples: list[DiagnosisGraphSample]) -> dict[str, list[DiagnosisGraphSample]]:
    rows = [sample.to_dict() for sample in samples]
    split_rows_ = split_rows(rows)
    by_key = {sample.sample_id + "|" + str(index): sample for index, sample in enumerate(samples)}
    # Preserve exact objects while using the existing split bucketing semantics.
    lookup = {id(row): sample for row, sample in zip(rows, samples)}
    output: dict[str, list[DiagnosisGraphSample]] = {"train": [], "valid": [], "test": []}
    for split, split_items in split_rows_.items():
        for row in split_items:
            sample = lookup.get(id(row))
            if sample is not None:
                output[split].append(sample)
    if samples and not output["train"]:
        output["train"] = list(samples)
    return output
