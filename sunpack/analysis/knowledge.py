from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sunpack.analysis import ArchiveAnalysisReport
from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.context import normalize_zip_runtime_route_evidence
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_flags, write_payload, write_value


def write_analysis_report(task: ArchiveTask, report: ArchiveAnalysisReport) -> None:
    knowledge = ensure_knowledge(task)
    selected = report.selected[0] if report.selected else None
    write_payload(
        knowledge,
        "analysis",
        {
            "status": "extractable" if report.has_extractable else "not_extractable",
            "report_path": report.path,
            "read_bytes": report.read_bytes,
            "cache_hits": report.cache_hits,
            "prepass": dict(report.prepass or {}),
            "fuzzy": dict(report.fuzzy or {}),
            "selected_format": getattr(selected, "format", "") if selected is not None else "",
            "confidence": float(getattr(selected, "confidence", 0.0) or 0.0) if selected is not None else 0.0,
            "evidences": [_evidence_payload(item) for item in report.evidences],
        },
        source_layer="analysis",
        source_module="analysis_stage",
    )
    if selected is not None:
        write_payload(
            knowledge,
            "analysis.summary",
            {
                "format": getattr(selected, "format", "") or "",
                "confidence": float(getattr(selected, "confidence", 0.0) or 0.0),
                "status": getattr(selected, "status", "") or "",
            },
            source_layer="analysis",
            source_module="analysis_stage",
        )
        _write_format_evidence(knowledge, selected)
    commit_task_knowledge(task, knowledge)


def write_analysis_refresh(
    task: ArchiveTask,
    report: ArchiveAnalysisReport,
    *,
    extractable_segments: list[dict[str, Any]] | None = None,
    selected_segment: tuple[ArchiveFormatEvidence, ArchiveSegment, int] | None = None,
) -> None:
    knowledge = ensure_knowledge(task)
    selected = report.selected[0] if report.selected else None
    write_payload(
        knowledge,
        "analysis",
        {
            "status": "extractable" if report.has_extractable else "not_extractable",
            "report_path": report.path,
            "read_bytes": report.read_bytes,
            "cache_hits": report.cache_hits,
            "prepass": dict(report.prepass or {}),
            "fuzzy": dict(report.fuzzy or {}),
            "selected_format": getattr(selected, "format", "") if selected is not None else "",
            "confidence": float(getattr(selected, "confidence", 0.0) or 0.0) if selected is not None else 0.0,
            "evidences": [_evidence_payload(item) for item in report.evidences],
        },
        source_layer="analysis",
        source_module="analysis_stage",
    )
    if selected is not None:
        write_payload(
            knowledge,
            "analysis.summary",
            {
                "format": getattr(selected, "format", "") or "",
                "confidence": float(getattr(selected, "confidence", 0.0) or 0.0),
                "status": getattr(selected, "status", "") or "",
            },
            source_layer="analysis",
            source_module="analysis_stage",
        )
        _write_format_evidence(knowledge, selected)
    segments = list(extractable_segments or [])
    write_value(
        knowledge,
        "analysis.extractable_segments",
        segments,
        source_layer="analysis",
        source_module="analysis_stage",
    )
    write_value(
        knowledge,
        "analysis.extractable_segment_count",
        int(len(segments)),
        source_layer="analysis",
        source_module="analysis_stage",
    )
    if selected_segment is not None:
        evidence, segment, index = selected_segment
        write_payload(
            knowledge,
            "analysis.selected_segment",
            {
                "index": int(index),
                "format": evidence.format,
                "confidence": float(evidence.confidence or 0.0),
                "status": evidence.status,
                "segment": asdict(segment),
            },
            source_layer="analysis",
            source_module="analysis_stage",
            confidence=float(evidence.confidence or 0.0),
        )
        _write_format_evidence(knowledge, evidence)
    commit_task_knowledge(task, knowledge)


def write_selected_segment(task: ArchiveTask, evidence: ArchiveFormatEvidence, segment: ArchiveSegment, *, index: int) -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "analysis.selected_segment",
        {
            "index": int(index),
            "format": evidence.format,
            "confidence": float(evidence.confidence or 0.0),
            "status": evidence.status,
            "segment": asdict(segment),
        },
        source_layer="analysis",
        source_module="analysis_stage",
        confidence=float(evidence.confidence or 0.0),
    )
    _write_format_evidence(knowledge, evidence)
    commit_task_knowledge(task, knowledge)


def write_extractable_segments(task: ArchiveTask, segments: list[dict[str, Any]]) -> None:
    knowledge = ensure_knowledge(task)
    write_value(
        knowledge,
        "analysis.extractable_segments",
        list(segments or []),
        source_layer="analysis",
        source_module="analysis_stage",
    )
    write_value(
        knowledge,
        "analysis.extractable_segment_count",
        int(len(segments or [])),
        source_layer="analysis",
        source_module="analysis_stage",
    )
    commit_task_knowledge(task, knowledge)


def write_analysis_error(task: ArchiveTask, error: str) -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "analysis",
        {"status": "error", "error": str(error or "")},
        source_layer="analysis",
        source_module="analysis_stage",
    )
    commit_task_knowledge(task, knowledge)


def _write_format_evidence(knowledge: Any, evidence: ArchiveFormatEvidence) -> None:
    details = dict(evidence.details or {})
    write_payload(
        knowledge,
        f"format.{evidence.format}",
        {
            "evidence": _evidence_payload(evidence),
            "structure": details.get("zip_structure_features") or details.get("structure") or {},
            "container_tags": details.get("zip_container_tags") or details.get("container_tags") or [],
        },
        source_layer="analysis",
        source_module="analysis_stage",
        confidence=float(evidence.confidence or 0.0),
    )
    route_payload = normalize_zip_runtime_route_evidence({
        "format": evidence.format,
        "analysis_evidence": {"details": details},
        "source_derivation": {
            "zip_structure_features": details.get("zip_structure_features") or {},
            "zip_container_tags": details.get("zip_container_tags") or [],
        },
    })
    route_flags = [str(flag) for flag in route_payload.get("route_evidence_flags") or [] if str(flag)]
    if route_flags:
        write_flags(
            knowledge,
            f"format.{evidence.format}.route_evidence",
            route_flags,
            source_layer="analysis",
            source_module="analysis_stage",
            confidence=float(evidence.confidence or 0.0),
        )
        write_payload(
            knowledge,
            f"format.{evidence.format}",
            {"route_evidence_flags": route_flags},
            source_layer="analysis",
            source_module="analysis_stage",
        )


def _evidence_payload(evidence: ArchiveFormatEvidence) -> dict[str, Any]:
    return {
        "format": evidence.format,
        "confidence": float(evidence.confidence or 0.0),
        "status": evidence.status,
        "warnings": list(evidence.warnings),
        "details": dict(evidence.details),
        "segments": [asdict(segment) for segment in evidence.segments],
    }
