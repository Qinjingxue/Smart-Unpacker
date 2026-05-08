from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.repair.coverage import ArchiveCoverageView, coverage_view_from_payload
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob


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


def build_repair_context(job: RepairJob, diagnosis: RepairDiagnosis) -> RepairContext:
    failure = dict(job.extraction_failure or {})
    diagnostics = _diagnostics_from(job, failure)
    result_payload = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    native_diagnostics = result_payload.get("diagnostics") if isinstance(result_payload.get("diagnostics"), dict) else {}
    fuzzy_profile = _fuzzy_profile(job)
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
    route_evidence_flags = zip_route_evidence_flags({
        "format": diagnosis.format or job.format,
        "source_input": job.source_input,
        "analysis_prepass": job.analysis_prepass,
        "analysis_evidence": _analysis_evidence_details(job),
        "extraction_failure": failure,
        "extraction_diagnostics": diagnostics,
        "repair_history": job.repair_history,
    })
    repair_history_flags = _repair_history_flags(job)
    residual_damage_flags = _residual_damage_flags(job, failure)
    damage_flags = _normalize_zip_generic_damage(_dedupe([
        *_damage_flags(job, diagnosis, failure, failure_kind, failure_stage),
        *route_evidence_flags,
        *repair_history_flags,
        *residual_damage_flags,
    ]))
    return RepairContext(
        source_input=dict(job.source_input or {}),
        format=_normalize_format(diagnosis.format or job.format),
        confidence=float(diagnosis.confidence or job.confidence or 0.0),
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
        structure_evidence=job.analysis_evidence,
        archive_coverage=coverage_view_from_payload(_archive_coverage(failure), _file_observations(failure)),
        prepass=dict(job.analysis_prepass or {}),
        fuzzy_profile=fuzzy_profile,
        extraction_failure=failure,
        extraction_diagnostics=diagnostics,
        route_evidence_flags=tuple(route_evidence_flags),
        repair_history_flags=tuple(repair_history_flags),
        residual_damage_flags=tuple(residual_damage_flags),
    )


def zip_route_evidence_flags(payload: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return []
    fmt = _normalize_format(str(payload.get("format") or payload.get("material_format") or ""))
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
    for profile in _profile_names(payload):
        flags.extend(_zip_profile_flags(profile))
    return _dedupe([str(item) for item in flags if item])


def _diagnostics_from(job: RepairJob, failure: dict[str, Any]) -> dict[str, Any]:
    if isinstance(job.extraction_diagnostics, dict) and job.extraction_diagnostics:
        return dict(job.extraction_diagnostics)
    diagnostics = failure.get("diagnostics")
    return dict(diagnostics) if isinstance(diagnostics, dict) else {}


def _analysis_evidence_details(job: RepairJob) -> dict[str, Any]:
    evidence = job.analysis_evidence
    details = getattr(evidence, "details", {}) if evidence is not None else {}
    return dict(details) if isinstance(details, dict) else {}


def _zip_structure_feature_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            features = value.get("zip_structure_features")
            if isinstance(features, dict):
                output.append(dict(features))
            for key in ("source_derivation", "analysis_prepass", "analysis_evidence", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input", "fuzzy"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    visit(nested)

    visit(payload)
    direct = payload.get("zip_structure_features")
    if isinstance(direct, dict):
        output.append(dict(direct))
    return output


def _profile_names(payload: dict[str, Any]) -> list[str]:
    names: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key in ("damage_profile", "profile", "material_sample_id", "sample_id", "source_archive_id", "damaged_file_name"):
                item = value.get(key)
                if isinstance(item, str) and item:
                    names.append(item)
            for key in ("source_derivation", "analysis_prepass", "analysis_evidence", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input"):
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
            for key in ("source_derivation", "analysis_prepass", "analysis_evidence", "extraction_failure", "extraction_diagnostics", "repair_history", "source_input", "damaged_input"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    collect(nested)

    collect(payload)
    return _dedupe(tags)


def _zip_profile_flags(profile: str) -> list[str]:
    text = str(profile or "").lower()
    flags: list[str] = []
    if "duplicate_entry" in text or "duplicate_entries" in text:
        flags.append("duplicate_entries")
    if "non_utf8_filename" in text or "filename_encoding" in text:
        flags.extend(["filename_encoding_bad", "raw_filename_bytes", "central_directory_bad", "local_header_recovery"])
    if "comment_overlap" in text or "comment_length" in text or "long_comment" in text:
        flags.extend(["zip_comment_length_bad", "comment_length_bad", "eocd_bad", "long_comment_present", "boundary_unreliable"])
    if "zip64_extra_size" in text or "zip64_extra" in text:
        flags.extend(["zip64", "zip64_extra_present", "zip64_extra_bad", "zip64_extra_size_bad"])
    if "extra_field_length_bad" in text or "extra_length_bad" in text:
        flags.extend(["extra_field_bad", "extra_field_length_bad"])
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
            flags.append("central_directory_bad")
        if "payload_damage" in text:
            flags.extend(["checksum_error", "crc_error", "damaged"])
    if "split_tail_volume_truncated" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "tail_volume_truncated", "missing_volume_unavailable"])
    elif "split_missing_middle_volume" in text or "sfx_split_missing_volume" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "middle_volume_missing"])
    elif "split" in text or "missing_volume" in text:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery"])
    return flags


def _repair_history_flags(job: RepairJob) -> list[str]:
    history = job.repair_history if isinstance(job.repair_history, dict) else {}
    modules = [*(_list_values(history, "previous_modules")), *(_list_values(history, "path_modules"))]
    actions = [*(_list_values(history, "previous_actions")), *(_list_values(history, "path_actions"))]
    patch_facts = _list_values(history, "applied_patch_facts")
    flags: list[str] = []
    for module in modules:
        flags.append(f"already_tried:{module}")
        if module == "archive_carrier_crop_deep_recovery" or module.endswith("_carrier_crop_deep_recovery"):
            flags.append("after_archive_carrier_crop")
        if module in {"zip_fix_eocd_comment_length", "zip_fix_eocd_record"}:
            flags.append("after_eocd_repair")
        if module in {"zip_rebuild_cd_from_local_headers", "zip_rebuild_cd_preserve_raw_names", "zip_rebuild_cd_from_data_descriptors"}:
            flags.append("after_cd_rebuild")
        if module in {"zip_fix_local_header_fields", "zip_local_header_partial_scan"}:
            flags.append("after_local_header_repair")
    for action in actions:
        if "carrier" in action and "crop" in action:
            flags.append("after_archive_carrier_crop")
        if "eocd" in action:
            flags.append("after_eocd_repair")
        if "central_directory" in action or "rebuild_cd" in action:
            flags.append("after_cd_rebuild")
        if "local_header" in action:
            flags.append("after_local_header_repair")
    for fact in patch_facts:
        if fact == "after_archive_carrier_crop" or fact == "fixed_field=carrier_prefix_crop":
            flags.append("after_archive_carrier_crop")
        if fact.startswith("fixed_field=eocd"):
            flags.append("after_eocd_repair")
        if fact in {"after_cd_rebuild", "raw_name_bytes_preserved"}:
            flags.append("after_cd_rebuild")
    flags.extend(_list_values(history, "repair_history_flags"))
    return _dedupe(flags)


def _residual_damage_flags(job: RepairJob, failure: dict[str, Any]) -> list[str]:
    history = job.repair_history if isinstance(job.repair_history, dict) else {}
    flags = [*_list_values(history, "residual_damage_flags"), *_list_values(failure, "residual_damage_flags")]
    coverage = _archive_coverage(failure)
    if coverage:
        completeness = float(coverage.get("completeness", 0.0) or 0.0)
        expected = int(coverage.get("expected_files", 0) or 0)
        matched = int(coverage.get("matched_files", coverage.get("complete_files", 0)) or 0)
        failed = int(coverage.get("failed_files", 0) or 0)
        if completeness < 0.999:
            flags.append("exact_match_failed")
        if expected and matched < expected:
            flags.append("partial_entries_remaining")
        if failed:
            flags.append("content_integrity_bad_or_unknown")
    source_integrity = str(failure.get("source_integrity") or "")
    assessment = str(failure.get("assessment_status") or "")
    if assessment == "complete" and source_integrity not in {"complete", "trusted"}:
        flags.extend(["content_integrity_bad_or_unknown", "exact_match_failed"])
    return _dedupe(flags)


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


def _fuzzy_profile(job: RepairJob) -> dict[str, Any]:
    if isinstance(job.fuzzy_profile, dict) and job.fuzzy_profile:
        return dict(job.fuzzy_profile)
    fuzzy = job.analysis_prepass.get("fuzzy") if isinstance(job.analysis_prepass, dict) else {}
    if isinstance(fuzzy, dict) and isinstance(fuzzy.get("binary_profile"), dict):
        return dict(fuzzy["binary_profile"])
    evidence = job.analysis_evidence
    details = getattr(evidence, "details", {}) if evidence is not None else {}
    route = details.get("fuzzy") if isinstance(details, dict) else {}
    profile = route.get("profile") if isinstance(route, dict) else {}
    return dict(profile) if isinstance(profile, dict) else {}


def _damage_flags(
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    failure: dict[str, Any],
    failure_kind: str,
    failure_stage: str,
) -> list[str]:
    flags = []
    flags.extend(job.damage_flags)
    for evidence in diagnosis.evidence:
        flags.extend(evidence.damage_flags)
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
