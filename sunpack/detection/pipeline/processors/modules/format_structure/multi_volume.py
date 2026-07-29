from __future__ import annotations

from typing import Any

from sunpack.detection.pipeline.processors.context import FactProcessorContext


def detection_analysis_volumes(context: FactProcessorContext) -> list[Any]:
    """Project detection relation facts into Analysis multi-volume source entries."""
    facts = context.fact_bag
    volumes = facts.get("relation.split_volumes") or []
    if volumes:
        inputs: list[Any] = list(volumes)
    else:
        paths = list(facts.get("candidate.member_paths") or [])
        head = str(facts.get("file.path") or "")
        if head and head not in paths:
            paths.insert(0, head)
        inputs = [
            {"path": str(path), "number": index + 1}
            for index, path in enumerate(dict.fromkeys(paths or [head]))
            if str(path)
        ]
    if not inputs:
        raise ValueError("detection candidate has no binary input")
    return inputs
