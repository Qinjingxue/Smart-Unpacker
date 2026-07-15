from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from typing import Any

from sunpack.analysis.scheduler import ArchiveAnalysisScheduler
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.rules.fact_requirements import ArchiveStructureCandidate


DEFAULT_HEAD_BYTES = 1024 * 1024
DEFAULT_TAIL_BYTES = 1024 * 1024
DEFAULT_FULL_SCAN_MAX_BYTES = 64 * 1024 * 1024
_CANDIDATE_GATE = ArchiveStructureCandidate()


@register_processor(
    "structure_evidence",
    input_facts=("file.path", "file.magic_bytes"),
    output_facts=("analysis.structure_evidence",),
    schemas={
        "analysis.structure_evidence": {
            "type": "dict",
            "description": "On-demand forensic structure evidence produced inside the detection pipeline.",
        },
    },
)
def process_structure_evidence(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    config = context.fact_config
    if not _CANDIDATE_GATE.matches(facts, config):
        return _empty_evidence()

    scheduler = ArchiveAnalysisScheduler(_analysis_config(context.config, config))
    task = ArchiveTask.from_fact_bag(facts, score=0)
    report = scheduler.analyze_task(task)
    selected = list(report.selected)
    if not selected:
        selected = [
            item
            for item in report.evidences
            if item.segments and bool(item.details.get("password_required"))
        ]
    best = max(selected, key=lambda item: float(item.confidence or 0.0)) if selected else None
    return {
        "analyzed": True,
        "has_extractable": bool(report.has_extractable),
        "password_required": bool(best and best.details.get("password_required")),
        "selected": _evidence_payload(best),
        "evidences": [_evidence_payload(item) for item in report.evidences],
        "prepass": dict(report.prepass or {}),
        "fuzzy": dict(report.fuzzy or {}),
        "read_bytes": int(report.read_bytes or 0),
        "cache_hits": int(report.cache_hits or 0),
    }


def _analysis_config(root_config: dict[str, Any], fact_config: dict[str, Any]) -> dict[str, Any]:
    config = deepcopy(root_config)
    analysis = config.setdefault("analysis", {})
    analysis["parallel"] = False
    analysis["max_read_mb_per_archive"] = int(fact_config.get("max_read_mb_per_archive", 64) or 0)
    prepass = analysis.setdefault("prepass", {})
    prepass.update({
        "enabled": True,
        "head_bytes": int(fact_config.get("head_bytes", DEFAULT_HEAD_BYTES) or 0),
        "tail_bytes": int(fact_config.get("tail_bytes", DEFAULT_TAIL_BYTES) or 0),
        "full_scan_max_bytes": int(
            fact_config.get("full_scan_max_bytes", DEFAULT_FULL_SCAN_MAX_BYTES) or 0
        ),
        "deep_scan": bool(fact_config.get("deep_scan", False)),
    })
    analysis.setdefault("fuzzy", {})["enabled"] = bool(fact_config.get("fuzzy_enabled", False))
    return config


def _evidence_payload(evidence) -> dict[str, Any]:
    if evidence is None:
        return {}
    payload = asdict(evidence)
    segments = payload.get("segments") or []
    first = segments[0] if segments else {}
    payload["start_offset"] = int(first.get("start_offset") or 0)
    payload["end_offset"] = first.get("end_offset")
    return payload


def _empty_evidence() -> dict[str, Any]:
    return {
        "analyzed": False,
        "has_extractable": False,
        "password_required": False,
        "selected": {},
        "evidences": [],
        "prepass": {},
        "fuzzy": {},
        "read_bytes": 0,
        "cache_hits": 0,
    }
