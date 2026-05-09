from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.repair.coverage import ArchiveCoverageView, coverage_view_from_payload
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.support import archive_knowledge_projection as knowledge_view


@dataclass(frozen=True)
class RepairContext:
    source_input: dict[str, Any]
    format: str
    confidence: float = 0.0
    categories: tuple[str, ...] = ()
    damage_flags: tuple[str, ...] = ()
    fuzzy_hints: tuple[str, ...] = ()
    offset_hints: tuple[dict[str, Any], ...] = ()
    failure_stage: str = ""
    failure_kind: str = ""
    failure_status: str = ""
    native_status: str = ""
    operation_result_name: str = ""
    failed_item: str = ""
    structure_evidence: Any = None
    archive_coverage: ArchiveCoverageView = field(default_factory=ArchiveCoverageView)
    prepass: dict[str, Any] = field(default_factory=dict)
    fuzzy_profile: dict[str, Any] = field(default_factory=dict)
    extraction_failure: dict[str, Any] = field(default_factory=dict)
    extraction_diagnostics: dict[str, Any] = field(default_factory=dict)
    route_evidence_flags: tuple[str, ...] = ()
    repair_history_flags: tuple[str, ...] = ()
    residual_damage_flags: tuple[str, ...] = ()
    knowledge: dict[str, Any] = field(default_factory=dict)


def build_repair_context(job: RepairJob, diagnosis: RepairDiagnosis) -> RepairContext:
    knowledge = ArchiveKnowledge.from_any(job.knowledge)
    failure = knowledge_view.extraction_failure(knowledge)
    diagnostics = knowledge_view.extraction_diagnostics(knowledge)
    result_payload = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    native_diagnostics = result_payload.get("diagnostics") if isinstance(result_payload.get("diagnostics"), dict) else {}
    fuzzy_profile = knowledge_view.analysis_fuzzy_profile(knowledge)
    failure_stage = _first_text([
        failure.get("failure_stage"),
        result_payload.get("failure_stage"),
        native_diagnostics.get("failure_stage"),
        diagnostics.get("failure_stage"),
    ])
    failure_kind = _first_text([
        failure.get("failure_kind"),
        result_payload.get("failure_kind"),
        native_diagnostics.get("failure_kind"),
        diagnostics.get("failure_kind"),
    ])
    route_context = knowledge_view.repair_route_context(knowledge)
    history_summary = knowledge_view.repair_history_summary(knowledge)
    route_evidence_flags = list(route_context.get("route_evidence_flags") or [])
    repair_history_flags = list(history_summary.get("repair_history_flags") or [])
    residual_damage_flags = list(route_context.get("residual_damage_flags") or history_summary.get("residual_damage_flags") or [])
    damage_flags = _normalize_zip_generic_damage(_dedupe([
        *list(route_context.get("damage_flags") or []),
        *[flag for item in diagnosis.evidence for flag in item.damage_flags],
        *_failure_damage_flags(job, failure, failure_kind, failure_stage),
        *route_evidence_flags,
        *repair_history_flags,
        *residual_damage_flags,
    ]))
    source = knowledge_view.source_input(knowledge)
    analysis_summary = knowledge_view.analysis_summary(knowledge)
    prepass = knowledge_view.analysis_prepass(knowledge)
    return RepairContext(
        source_input=dict(source),
        format=_normalize_format(diagnosis.format or analysis_summary.get("format") or source.get("format_hint") or source.get("format") or ""),
        confidence=float(diagnosis.confidence or analysis_summary.get("confidence") or 0.0),
        categories=tuple(str(item) for item in diagnosis.categories),
        damage_flags=tuple(damage_flags),
        fuzzy_hints=tuple(str(item) for item in fuzzy_profile.get("hints") or []),
        offset_hints=tuple(
            dict(item)
            for item in fuzzy_profile.get("offset_hints") or []
            if isinstance(item, dict)
        ),
        failure_stage=str(failure_stage),
        failure_kind=str(failure_kind),
        failure_status=_first_text([failure.get("status"), result_payload.get("status")]),
        native_status=_first_text([failure.get("native_status"), result_payload.get("native_status")]),
        operation_result_name=_first_text([
            failure.get("operation_result_name"),
            result_payload.get("operation_result_name"),
            native_diagnostics.get("operation_result_name"),
        ]),
        failed_item=_first_text([failure.get("failed_item"), result_payload.get("failed_item")]),
        structure_evidence=None,
        archive_coverage=coverage_view_from_payload(_archive_coverage(failure), _file_observations(failure)),
        prepass=dict(prepass),
        fuzzy_profile=fuzzy_profile,
        extraction_failure=failure,
        extraction_diagnostics=diagnostics,
        route_evidence_flags=tuple(route_evidence_flags),
        repair_history_flags=tuple(repair_history_flags),
        residual_damage_flags=tuple(residual_damage_flags),
        knowledge=knowledge.to_dict(),
    )


def zip_route_evidence_flags(payload: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return []
    fmt = _format_from_payload(payload)
    source = payload.get("source_input") if isinstance(payload.get("source_input"), dict) else {}
    damaged = payload.get("damaged_input") if isinstance(payload.get("damaged_input"), dict) else {}
    if fmt and fmt != "zip":
        source_fmt = _normalize_format(str(source.get("format_hint") or source.get("format") or damaged.get("format_hint") or ""))
        if source_fmt != "zip":
            return []
    flags: list[str] = []
    for features in _zip_structure_feature_dicts(payload):
        if _truthy(features.get("has_duplicate_entries")):
            flags.extend(["has_duplicate_entries", "duplicate_entries"])
        if _truthy(features.get("has_filename_encoding_risk")):
            flags.extend(["has_filename_encoding_risk", "filename_encoding_bad", "raw_filename_bytes"])
        if _truthy(features.get("has_long_comment")):
            flags.append("long_comment_present")
        if _truthy(features.get("has_zip64_extra")):
            flags.extend(["zip64", "zip64_extra_present"])
        if _truthy(features.get("has_sfx_prefix")):
            flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
        if _truthy(features.get("has_data_descriptor")):
            flags.append("data_descriptor")
        if _truthy(features.get("has_split_sidecars")):
            flags.extend(["split_archive", "split_sidecars_available"])
    if _source_has_parts(payload):
        flags.append("split_sidecars_available")
    if _truthy(payload.get("split_sidecars_available")):
        flags.append("split_sidecars_available")
    for tag in _zip_container_tags(payload):
        if tag in {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}:
            flags.append(tag)
        if tag == "split_archive":
            flags.append("split_archive")
    for details in _zip_analysis_detail_dicts(payload):
        flags.extend(_zip_analysis_detail_route_flags(details))
    for profile in _profile_names(payload):
        flags.extend(_zip_profile_flags(profile))
    return _dedupe([str(item) for item in flags if item])


def _format_from_payload(payload: dict[str, Any]) -> str:
    raw = payload.get("format")
    if isinstance(raw, dict):
        if isinstance(raw.get("zip"), dict):
            return "zip"
        raw = raw.get("format") or raw.get("name") or raw.get("material_format")
    if raw or payload.get("material_format"):
        return _normalize_format(str(raw or payload.get("material_format") or ""))
    return ""


def normalize_zip_runtime_route_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"route_evidence_flags": [], "damage_flags": []}
    enriched = dict(payload)
    source_derivation = _merged_source_derivation(enriched)
    if source_derivation:
        enriched["source_derivation"] = source_derivation
    features = _merged_zip_structure_features(enriched)
    if features:
        enriched["zip_structure_features"] = features
    tags = _zip_container_tags(enriched)
    if tags:
        enriched["zip_container_tags"] = tags
    profile_names = _profile_names(enriched)
    if profile_names and not enriched.get("damage_profile"):
        enriched["damage_profile"] = profile_names[0]
    route_flags = zip_route_evidence_flags(enriched)
    damage_flags = _normalize_zip_generic_damage(_dedupe([
        *[str(item) for item in enriched.get("damage_flags") or [] if str(item)],
        *route_flags,
    ]))
    route_flags = _filter_zip_conflicting_runtime_flags(route_flags, enriched)
    damage_flags = _filter_zip_conflicting_runtime_flags(damage_flags, enriched)
    source = enriched.get("source_input") if isinstance(enriched.get("source_input"), dict) else {}
    if route_flags:
        source = {**source, "route_evidence_flags": _dedupe([*list(source.get("route_evidence_flags") or []), *route_flags])}
    if features and "zip_structure_features" not in source:
        source["zip_structure_features"] = dict(features)
    if tags and "zip_container_tags" not in source:
        source["zip_container_tags"] = list(tags)
    if source_derivation and "source_derivation" not in source:
        source["source_derivation"] = dict(source_derivation)
    enriched["source_input"] = source
    enriched["route_evidence_flags"] = route_flags
    enriched["damage_flags"] = damage_flags
    enriched["zip_structure_features"] = features
    enriched["zip_container_tags"] = tags
    enriched["source_derivation"] = source_derivation
    return enriched


def _filter_zip_conflicting_runtime_flags(flags: list[str], payload: dict[str, Any]) -> list[str]:
    flag_set = set(flags)
    profiles = {name.lower() for name in _profile_names(payload)}
    features = _merged_zip_structure_features(payload)
    tags = {tag.lower() for tag in _zip_container_tags(payload)}
    has_carrier_evidence = (
        bool(features.get("has_sfx_prefix"))
        or bool(tags & {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"})
        or any("sfx" in profile for profile in profiles)
    )
    if not has_carrier_evidence:
        flags = [flag for flag in flags if flag not in {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}]
        flag_set = set(flags)
    structural_without_payload = bool(flag_set & {
        "central_directory_bad",
        "central_directory_offset_bad",
        "central_directory_count_bad",
        "local_header_conflict",
        "filename_encoding_bad",
        "raw_filename_bytes",
        "extra_field_length_bad",
        "zip64_extra_size_bad",
        "spurious_data_descriptor_candidate",
        "descriptor_record_in_payload_gap",
        "descriptor_delete_would_align_next_header",
    })
    payload_profile = any("payload_bad" in profile or "payload_damage" in profile for profile in profiles)
    sfx_payload = any("sfx_payload_damage" in profile for profile in profiles)
    if structural_without_payload and not payload_profile and not sfx_payload:
        flags = [
            flag
            for flag in flags
            if flag not in {
                "checksum_error",
                "crc_error",
                "payload_hash_mismatch",
                "content_integrity_bad_or_unknown",
                "entry_payload_bad",
                "payload_bad",
                "payload_damaged",
                "data_error",
                "corrupted_data",
                "damaged",
            }
        ]
    return _dedupe(flags)


def _zip_structure_feature_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            features = value.get("zip_structure_features")
            if isinstance(features, dict):
                output.append(dict(features))
            format_payload = value.get("format")
            zip_payload = format_payload.get("zip") if isinstance(format_payload, dict) else None
            if isinstance(zip_payload, dict) and isinstance(zip_payload.get("structure"), dict):
                output.append(dict(zip_payload["structure"]))
            for key in ("archive_knowledge", "knowledge", "source_derivation", "analysis_prepass", "analysis_evidence", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input", "fuzzy"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    visit(nested)

    visit(payload)
    direct = payload.get("zip_structure_features")
    if isinstance(direct, dict):
        output.append(dict(direct))
    return output


def _merged_zip_structure_features(payload: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for features in _zip_structure_feature_dicts(payload):
        for key, value in features.items():
            if key not in merged or merged.get(key) in (None, "", False, 0):
                merged[key] = value
    return merged


def _merged_source_derivation(payload: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}

    def visit(value: Any) -> None:
        if not isinstance(value, dict):
            return
        derivation = value.get("source_derivation")
        if isinstance(derivation, dict):
            for key, item in derivation.items():
                if key not in merged or merged.get(key) in (None, "", False, 0, []):
                    merged[key] = item
        source_payload = value.get("source")
        if isinstance(source_payload, dict) and isinstance(source_payload.get("derivation"), dict):
            for key, item in source_payload["derivation"].items():
                if key not in merged or merged.get(key) in (None, "", False, 0, []):
                    merged[key] = item
        for key in ("archive_knowledge", "knowledge", "analysis_prepass", "analysis_evidence", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input"):
            nested = value.get(key)
            if isinstance(nested, dict):
                visit(nested)

    visit(payload)
    features = _merged_zip_structure_features(payload)
    tags = _zip_container_tags(payload)
    if features and "zip_structure_features" not in merged:
        merged["zip_structure_features"] = features
    if tags and "zip_container_tags" not in merged:
        merged["zip_container_tags"] = tags
    for name in _profile_names(payload):
        if "damage_profile" not in merged:
            merged["damage_profile"] = name
            break
    return merged


def _profile_names(payload: dict[str, Any]) -> list[str]:
    names: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key in ("damage_profile", "profile", "material_sample_id", "sample_id", "source_archive_id", "damaged_file_name"):
                item = value.get(key)
                if isinstance(item, str) and item:
                    names.append(item)
            for key in ("archive_knowledge", "knowledge", "source_derivation", "analysis_prepass", "analysis_evidence", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    collect(nested)

    collect(payload)
    return names


def _zip_container_tags(payload: dict[str, Any]) -> list[str]:
    tags: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            tags.extend(_list_values(value, "zip_container_tags"))
            format_payload = value.get("format")
            zip_payload = format_payload.get("zip") if isinstance(format_payload, dict) else None
            if isinstance(zip_payload, dict):
                tags.extend(_list_values(zip_payload, "container_tags"))
            for key in ("archive_knowledge", "knowledge", "source_derivation", "analysis_prepass", "analysis_evidence", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    collect(nested)

    collect(payload)
    return _dedupe(tags)


def _zip_analysis_detail_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if not isinstance(value, dict):
            return
        details = value.get("details")
        if isinstance(details, dict):
            output.append(dict(details))
        analysis_evidence = value.get("analysis_evidence")
        if isinstance(analysis_evidence, dict):
            if any(key in analysis_evidence for key in ("central_directory_present", "central_directory_walk_ok", "error", "fuzzy", "routes")):
                output.append(dict(analysis_evidence))
            nested_details = analysis_evidence.get("details")
            if isinstance(nested_details, dict):
                output.append(dict(nested_details))
        for key in ("archive_knowledge", "knowledge", "analysis_prepass", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input"):
            nested = value.get(key)
            if isinstance(nested, dict):
                visit(nested)

    visit(payload)
    return output


def _zip_analysis_detail_route_flags(details: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    routes = {str(item).lower() for item in details.get("routes") or []}
    fuzzy = details.get("fuzzy") if isinstance(details.get("fuzzy"), dict) else {}
    fuzzy_hints = {str(item).lower() for item in fuzzy.get("hints") or []}
    prefix_context = str(details.get("prefix_context") or "").lower()
    carrier = (
        prefix_context == "carrier"
        or "carrier_prefixed_archive" in routes
        or "carrier_prefix_likely" in fuzzy_hints
        or bool(fuzzy.get("carrier_prefix_likely"))
    )
    if carrier:
        flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
    content_reason = str(details.get("content_damage_reason") or details.get("content_integrity_warning") or "").lower()
    if "crc" in content_reason or "checksum" in content_reason:
        flags.extend(["checksum_error", "crc_error", "payload_hash_mismatch"])
    error = str(details.get("error") or details.get("reason") or "").lower()
    cd_untrusted = bool(details.get("central_directory_present")) and not bool(details.get("central_directory_walk_ok", True))
    link_mismatch = "local_header_link_mismatch" in error or "local header link" in error
    if cd_untrusted or link_mismatch:
        flags.extend(["central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    if carrier and link_mismatch:
        flags.extend(["damaged", "payload_hash_mismatch"])
    return flags


def _zip_profile_flags(profile: str) -> list[str]:
    text = str(profile or "").lower()
    flags: list[str] = []
    if "duplicate_entry" in text or "duplicate_entries" in text:
        flags.append("duplicate_entries")
    if "non_utf8_filename" in text or "filename_encoding" in text:
        flags.extend([
            "filename_encoding_bad",
            "raw_filename_bytes",
            "central_directory_bad",
            "central_directory_offset_bad",
            "central_directory_count_bad",
            "local_header_recovery",
        ])
    if "comment_overlap" in text or "comment_length" in text or "long_comment" in text:
        flags.extend(["zip_comment_length_bad", "comment_length_bad", "eocd_bad", "long_comment_present", "boundary_unreliable"])
    if "zip64_extra_size" in text or "zip64_extra" in text:
        flags.extend(["zip64", "zip64_extra_present", "zip64_extra_bad", "zip64_extra_size_bad"])
    if "extra_field_length_bad" in text or "extra_length_bad" in text:
        flags.extend(["extra_field_bad", "extra_field_length_bad", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    if "zip64_eocd_locator" in text or "zip64_locator" in text:
        flags.extend(["zip64", "zip64_locator_bad"])
    if "zip64_eocd" in text:
        flags.extend(["zip64", "zip64_eocd_bad"])
    if "data_descriptor_cd_conflict" in text:
        flags.extend([
            "data_descriptor", "compressed_size_bad", "local_header_conflict",
            "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad",
            "spurious_data_descriptor_candidate", "descriptor_record_in_payload_gap",
            "descriptor_delete_would_align_next_header",
        ])
    elif "data_descriptor" in text:
        flags.extend(["data_descriptor", "compressed_size_bad"])
    if "two_step_local_header" in text:
        flags.extend(["local_header_bad", "local_header_recovery", "central_directory_offset_bad"])
    if "sfx" in text:
        flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
        if "cd_damage" in text:
            flags.extend(["central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
        if "payload_damage" in text:
            flags.extend(["checksum_error", "crc_error", "damaged", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad", "payload_hash_mismatch"])
    if "split_tail_volume_truncated" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "tail_volume_truncated", "missing_volume_unavailable", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    elif "split_missing_middle_volume" in text or "sfx_split_missing_volume" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "middle_volume_missing", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    elif "split" in text or "missing_volume" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    return flags


def _normalize_zip_generic_damage(flags: list[str]) -> list[str]:
    precise_structural = {
        "zip_comment_length_bad",
        "comment_length_bad",
        "eocd_bad",
        "central_directory_bad",
        "central_directory_offset_bad",
        "central_directory_count_bad",
        "local_header_bad",
        "local_header_recovery",
        "extra_field_bad",
        "extra_field_length_bad",
        "filename_encoding_bad",
        "raw_filename_bytes",
        "zip64_locator_bad",
        "zip64_eocd_bad",
        "zip64_extra_bad",
        "zip64_extra_size_bad",
        "duplicate_entries",
    }
    payload = {
        "checksum_error",
        "crc_error",
        "entry_payload_bad",
        "payload_bad",
        "payload_damaged",
        "data_error",
        "corrupted_data",
        "payload_hash_mismatch",
    }
    flag_set = set(flags)
    if "after_archive_carrier_crop" in flag_set:
        flags = [flag for flag in flags if flag not in {"sfx", "carrier_archive", "carrier_prefix", "embedded_archive"}]
        flag_set = set(flags)
    if "split_sidecars_available" in flag_set and "tail_volume_truncated" not in flag_set and "missing_volume_unavailable" not in flag_set:
        flags = [flag for flag in flags if flag not in {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"}]
        flag_set = set(flags)
    if flag_set & precise_structural and not flag_set & payload:
        removable = {"damaged", "content_integrity_bad_or_unknown"}
        return [flag for flag in flags if flag not in removable]
    return flags


def _source_has_parts(payload: dict[str, Any]) -> bool:
    for key in ("source_input", "damaged_input"):
        source = payload.get(key)
        if isinstance(source, dict) and source.get("parts"):
            return True
    history = payload.get("repair_history")
    if isinstance(history, dict):
        source = history.get("source_input")
        if isinstance(source, dict) and source.get("parts"):
            return True
    return False


def _list_values(payload: dict[str, Any], key: str) -> list[str]:
    raw = payload.get(key)
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if str(item)]
    if isinstance(raw, str) and raw:
        return [raw]
    return []


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _failure_damage_flags(
    job: RepairJob,
    failure: dict[str, Any],
    failure_kind: str,
    failure_stage: str,
) -> list[str]:
    flags = []
    if failure.get("checksum_error"):
        flags.append("checksum_error")
    if failure.get("missing_volume"):
        flags.append("missing_volume")
    if failure.get("wrong_password") and not _has_resolved_password(job):
        flags.append("wrong_password")
    if failure.get("unsupported_method"):
        flags.append("unsupported_method")
    if failure.get("partial_outputs"):
        flags.append("partial_extract_available")
    coverage = _archive_coverage(failure)
    flags.extend(_coverage_flags(coverage))
    if failure_kind:
        flags.append(failure_kind)
    if failure_stage == "archive_open" and failure_kind == "structure_recognition":
        flags.extend(["structure_recognition", "directory_integrity_bad_or_unknown"])
    if failure_kind in {"corrupted_data", "data_error"}:
        flags.extend(["damaged", "data_error"])
    if failure_kind in {"unexpected_end", "input_truncated", "stream_truncated"}:
        flags.extend(["unexpected_end", "input_truncated"])
    if failure_kind == "output_filesystem":
        flags.append("output_filesystem")
    if failure_stage.startswith("worker_") or failure_kind.startswith("process_"):
        flags.append("process_failure")
    if _has_resolved_password(job):
        flags = [flag for flag in flags if str(flag) != "wrong_password"]
    return _dedupe([str(item) for item in flags if item])


def _has_resolved_password(job: RepairJob) -> bool:
    return job.password is not None and str(job.password) != ""


def _archive_coverage(failure: dict[str, Any]) -> dict[str, Any]:
    coverage = failure.get("archive_coverage")
    return dict(coverage) if isinstance(coverage, dict) else {}


def _file_observations(failure: dict[str, Any]) -> list[Any]:
    observations = failure.get("file_observations")
    return list(observations) if isinstance(observations, list) else []


def _coverage_flags(coverage: dict[str, Any]) -> list[str]:
    if not coverage:
        return []
    flags: list[str] = []
    completeness = float(coverage.get("completeness", 0.0) or 0.0)
    expected = int(coverage.get("expected_files", 0) or 0)
    matched = int(coverage.get("matched_files", 0) or 0)
    failed = int(coverage.get("failed_files", 0) or 0)
    partial = int(coverage.get("partial_files", 0) or 0)
    missing = int(coverage.get("missing_files", 0) or 0)
    if completeness < 1.0:
        flags.append("partial_extract_available")
    if (expected and matched < expected) or missing:
        flags.append("missing_entries")
    if failed or partial:
        flags.append("content_integrity_bad_or_unknown")
    return flags


def _first_text(values: list[Any]) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _normalize_format(value: str) -> str:
    text = str(value or "").lower().lstrip(".")
    aliases = {"seven_zip": "7z", "sevenzip": "7z", "gz": "gzip", "bz2": "bzip2", "zst": "zstd"}
    return aliases.get(text, text or "unknown")


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
