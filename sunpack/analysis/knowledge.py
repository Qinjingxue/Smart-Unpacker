from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sunpack.analysis import ArchiveAnalysisReport
from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.context import normalize_runtime_route_evidence
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_flags, write_payload, write_value


def write_analysis_report(task: ArchiveTask, report: ArchiveAnalysisReport) -> None:
    knowledge = ensure_knowledge(task)
    selected = _best_selected(report)
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
    selected = _best_selected(report)
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
    format_key = "7z" if evidence.format in {"7z", "seven_zip"} else evidence.format
    write_payload(
        knowledge,
        f"format.{format_key}",
        {
            "evidence": _evidence_payload(evidence),
            "structure": _format_structure_payload(evidence.format, details),
            "container_tags": _format_container_tags(evidence.format, details),
        },
        source_layer="analysis",
        source_module="analysis_stage",
        confidence=float(evidence.confidence or 0.0),
    )
    if evidence.format in {"7z", "seven_zip"}:
        route_flags = _seven_zip_route_flags_from_details(details)
        if route_flags:
            write_flags(
                knowledge,
                "format.7z.route_evidence",
                route_flags,
                source_layer="analysis",
                source_module="analysis_stage",
                confidence=float(evidence.confidence or 0.0),
            )
            write_payload(
                knowledge,
                "format.7z",
                {"route_evidence_flags": route_flags},
                source_layer="analysis",
                source_module="analysis_stage",
            )
        return
    if evidence.format != "zip":
        return
    route_payload = normalize_runtime_route_evidence({
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


def _format_structure_payload(fmt: str, details: dict[str, Any]) -> dict[str, Any]:
    if fmt in {"7z", "seven_zip"}:
        return dict(details.get("seven_zip_structure") or details.get("7z_structure") or details.get("structure") or {})
    return dict(details.get("zip_structure_features") or details.get("structure") or {})


def _format_container_tags(fmt: str, details: dict[str, Any]) -> list[str]:
    raw = details.get("container_tags")
    if fmt not in {"7z", "seven_zip"}:
        raw = details.get("zip_container_tags") or raw
    return [str(item) for item in raw or [] if str(item)] if isinstance(raw, list) else []


def _seven_zip_route_flags_from_details(details: dict[str, Any]) -> list[str]:
    structure = dict(details.get("seven_zip_structure") or details.get("7z_structure") or details.get("structure") or {})
    tags = {str(item).lower() for item in details.get("container_tags") or [] if str(item)}
    flags: list[str] = []
    if structure or details:
        flags.append("seven_zip_signature_found")
    if structure.get("has_carrier_prefix") or structure.get("carrier_prefix_bytes") or tags & {"carrier_prefix", "carrier_archive", "embedded_archive", "sfx"}:
        flags.extend(["carrier_prefix", "carrier_archive", "embedded_archive"])
    if int(structure.get("trailing_bytes") or 0) > 0:
        flags.append("trailing_junk")
    if structure.get("start_crc_ok") is False:
        flags.append("start_header_crc_bad")
    if structure.get("next_header_crc_ok") is False:
        flags.append("next_header_crc_bad")
    if structure.get("next_header_out_of_range") or structure.get("next_header_range_valid") is False:
        flags.append("next_header_out_of_range")
    if structure.get("encoded_header_candidate_found"):
        flags.append("encoded_header_candidate_found")
    if structure.get("encoded_header_present"):
        flags.append("encoded_header_present")
    if structure.get("encoded_header_decodable"):
        flags.append("encoded_header_decodable")
    if structure.get("encoded_header_stream_crc_bad"):
        flags.append("encoded_header_stream_crc_bad")
    if structure.get("next_header_nid_valid") is False:
        flags.append("encoded_header_unreadable")
    for key, flag in (
        ("pack_stream_offset_bad", "pack_stream_offset_bad"),
        ("pack_stream_size_bad", "pack_stream_size_bad"),
        ("unpack_size_bad", "unpack_size_bad"),
        ("stream_crc_bad", "stream_crc_bad"),
        ("substream_crc_bad", "substream_crc_bad"),
        ("empty_stream_flags_bad", "empty_stream_flags_bad"),
        ("empty_file_flags_bad", "empty_file_flags_bad"),
        ("anti_item_flags_bad", "anti_item_flags_bad"),
        ("folder_bind_pairs_bad", "folder_bind_pairs_bad"),
        ("folder_stream_counts_bad", "folder_stream_counts_bad"),
        ("file_count_metadata_bad", "file_count_metadata_bad"),
        ("signature_header_version_bad", "signature_header_version_bad"),
        ("file_names_utf16_bad", "file_names_utf16_bad"),
        ("names_utf16_bad", "names_utf16_bad"),
        ("file_name_metadata_bad", "file_name_metadata_bad"),
        ("unreferenced_folder", "unreferenced_folder"),
        ("unreferenced_folder_record", "unreferenced_folder_record"),
        ("unreferenced_file_record", "unreferenced_file_record"),
        ("file_record_unreferenced", "file_record_unreferenced"),
        ("invalid_stream_crc_defined_flag", "invalid_stream_crc_defined_flag"),
        ("stream_crc_defined_flag_bad", "stream_crc_defined_flag_bad"),
        ("bad_folder_detected", "bad_folder_detected"),
        ("verified_folder_available", "verified_folder_available"),
    ):
        if structure.get(key):
            flags.append(flag)
    if structure.get("solid_archive"):
        flags.append("solid_archive")
    if structure.get("non_solid_archive"):
        flags.append("non_solid_archive")
    return _dedupe(flags)


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _evidence_payload(evidence: ArchiveFormatEvidence) -> dict[str, Any]:
    return {
        "format": evidence.format,
        "confidence": float(evidence.confidence or 0.0),
        "status": evidence.status,
        "warnings": list(evidence.warnings),
        "details": dict(evidence.details),
        "segments": [asdict(segment) for segment in evidence.segments],
    }


def _best_selected(report: ArchiveAnalysisReport) -> ArchiveFormatEvidence | None:
    if not report.selected:
        return None
    return max(report.selected, key=lambda item: float(getattr(item, "confidence", 0.0) or 0.0))
