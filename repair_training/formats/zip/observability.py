from __future__ import annotations

from typing import Any


UNCERTAIN_REFERENCE_MISSING = "uncertain_reference_missing"
UNCERTAIN_VERIFICATION_MISSING = "uncertain_verification_missing"
UNCERTAIN_AMBIGUOUS_OVERLAP = "uncertain_ambiguous_overlap"
OBSERVED = "observed"


def apply_zip_observability(target: dict[str, Any], knowledge_payload: dict[str, Any]) -> dict[str, Any]:
    oracle = sorted({str(label) for label in target.get("damage_labels") or [] if str(label).startswith(("zone:", "field:"))})
    structure = _structure(knowledge_payload)
    summary = _graph_summary(structure)
    runtime = structure.get("runtime") if isinstance(structure.get("runtime"), dict) else {}
    observed: set[str] = set()
    uncertain: set[str] = set()
    observability: dict[str, dict[str, Any]] = {}

    field_labels = [label for label in oracle if label.startswith("field:")]
    for label in field_labels:
        field = label.split(":", 1)[1]
        status, reason, evidence = _field_observability(field, summary, runtime)
        observability[label] = {"status": status, "reason": reason, "evidence": evidence}
        if status == OBSERVED:
            observed.add(label)
        else:
            uncertain.add(label)

    for label in [item for item in oracle if item.startswith("zone:")]:
        zone = label.split(":", 1)[1]
        zone_fields = [field_label for field_label in field_labels if _zone_for_field(field_label.split(":", 1)[1]) == zone]
        if zone_fields:
            if any(field in observed for field in zone_fields):
                observed.add(label)
                observability[label] = {"status": OBSERVED, "reason": "observed_field_in_zone", "evidence": {"fields": sorted(set(zone_fields) & observed)}}
            elif all(field in uncertain for field in zone_fields):
                uncertain.add(label)
                reasons = sorted({str((observability.get(field) or {}).get("reason") or "") for field in zone_fields})
                observability[label] = {"status": _zone_uncertain_status(reasons), "reason": ",".join(reason for reason in reasons if reason), "evidence": {"fields": zone_fields}}
            else:
                observed.add(label)
                observability[label] = {"status": OBSERVED, "reason": "mixed_zone_defaults_observed", "evidence": {"fields": zone_fields}}
        else:
            observed.add(label)
            observability[label] = {"status": OBSERVED, "reason": "coarse_zone_or_structural_label", "evidence": {}}

    metadata = dict(target.get("metadata") or {})
    metadata["observability"] = observability
    metadata["oracle_labels"] = oracle
    metadata["observed_label_count"] = len(observed)
    metadata["uncertain_label_count"] = len(uncertain)
    return {
        **target,
        "damage_labels": oracle,
        "observed_labels": sorted(observed),
        "uncertain_labels": sorted(uncertain),
        "metadata": metadata,
    }


def _field_observability(field: str, summary: dict[str, Any], runtime: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    if field == "local_header.crc":
        mismatch = _int(summary.get("central_local_crc_mismatch_count"))
        checked = _int(summary.get("cd_entries_checked") or summary.get("cd_entry_count"))
        if checked > 0 and mismatch > 0:
            return OBSERVED, "cd_local_crc_mismatch", {"cd_entries_checked": checked, "mismatch_count": mismatch}
        return UNCERTAIN_REFERENCE_MISSING, "reference_missing:central_directory", {"cd_entries_checked": checked, "mismatch_count": mismatch}
    if field == "local_header.compressed_size":
        mismatch = max(
            _int(summary.get("central_local_compressed_size_mismatch_count")),
            _int(summary.get("central_local_uncompressed_size_mismatch_count")),
        )
        checked = _int(summary.get("cd_entries_checked") or summary.get("cd_entry_count"))
        if checked > 0 and mismatch > 0:
            return OBSERVED, "cd_local_size_mismatch", {"cd_entries_checked": checked, "mismatch_count": mismatch}
        return UNCERTAIN_REFERENCE_MISSING, "reference_missing:central_directory", {"cd_entries_checked": checked, "mismatch_count": mismatch}
    if field == "payload.compressed_data":
        direct_crc = bool(runtime.get("payload_direct_crc_or_hash_failure_observed"))
        size_or_content = bool(runtime.get("payload_size_or_content_mismatch_observed"))
        strict_content = bool(runtime.get("payload_content_failure_observed"))
        if direct_crc or size_or_content or strict_content:
            return OBSERVED, "payload_content_failure_observed", {
                "payload_direct_crc_or_hash_failure_observed": direct_crc,
                "payload_size_or_content_mismatch_observed": size_or_content,
                "payload_content_failure_observed": strict_content,
                "extraction_crc_error_count": _int(runtime.get("extraction_crc_error_count")),
                "extraction_data_error_count": _int(runtime.get("extraction_data_error_count")),
            }
        if (
            runtime.get("payload_failure_explained_by_missing_range")
            or runtime.get("payload_failure_explained_by_cd_pointer")
            or runtime.get("payload_failure_explained_by_sfx_or_split")
            or runtime.get("missing_range_likely_structural_cause")
            or runtime.get("payload_partial_explained_by_missing_range")
        ):
            return UNCERTAIN_AMBIGUOUS_OVERLAP, "ambiguous:missing_range_or_cd_pointer", {
                "payload_failure_explained_by_missing_range": bool(runtime.get("payload_failure_explained_by_missing_range")),
                "payload_failure_explained_by_cd_pointer": bool(runtime.get("payload_failure_explained_by_cd_pointer")),
                "payload_failure_explained_by_sfx_or_split": bool(runtime.get("payload_failure_explained_by_sfx_or_split")),
                "extraction_item_failure_observed": bool(runtime.get("extraction_item_failure_observed")),
            }
        return UNCERTAIN_VERIFICATION_MISSING, "verification_missing:payload", {
            "payload_verification_observed": bool(runtime.get("payload_verification_observed")),
            "payload_unverified_but_no_failure": bool(runtime.get("payload_unverified_but_no_failure")),
        }
    return OBSERVED, "direct_or_structural_observed_by_default", {}


def _structure(payload: dict[str, Any]) -> dict[str, Any]:
    fmt = payload.get("format") if isinstance(payload.get("format"), dict) else {}
    zip_payload = fmt.get("zip") if isinstance(fmt.get("zip"), dict) else {}
    structure = zip_payload.get("structure") if isinstance(zip_payload.get("structure"), dict) else {}
    if structure:
        return structure
    runtime_context = payload.get("runtime_context") if isinstance(payload.get("runtime_context"), dict) else {}
    probe = runtime_context.get("analysis_native_probe") if isinstance(runtime_context.get("analysis_native_probe"), dict) else {}
    structure = probe.get("structure") if isinstance(probe.get("structure"), dict) else {}
    return structure


def _graph_summary(structure: dict[str, Any]) -> dict[str, Any]:
    graph = structure.get("graph") if isinstance(structure.get("graph"), dict) else {}
    summary = graph.get("summary") if isinstance(graph.get("summary"), dict) else {}
    fallback = structure.get("summary") if isinstance(structure.get("summary"), dict) else {}
    return {**fallback, **summary}


def _zone_for_field(field: str) -> str:
    head = str(field or "").split(".", 1)[0]
    if head in {"sfx_prefix", "split_volume", "zip64"}:
        return head
    return head


def _zone_uncertain_status(reasons: list[str]) -> str:
    if any("ambiguous" in reason for reason in reasons):
        return UNCERTAIN_AMBIGUOUS_OVERLAP
    if any("verification_missing" in reason for reason in reasons):
        return UNCERTAIN_VERIFICATION_MISSING
    return UNCERTAIN_REFERENCE_MISSING


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
