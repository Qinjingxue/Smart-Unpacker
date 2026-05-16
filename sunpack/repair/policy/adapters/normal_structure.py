from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any


QUERY_SCHEMA_VERSION = 1
NEGATIVE_DELTAS = (-64, -16, -4, -1, 1, 4, 16, 64)
TOP_COMPACT_QUERIES = 16
COMPACT_FEATURE_ALLOWLIST = {
    "abs_delta_to_expected_bucket",
    "bit3_descriptor_flag_set",
    "both_fields_present",
    "candidate_inside_archive",
    "candidate_comment_end_after_file_end",
    "candidate_comment_end_before_file_end",
    "candidate_comment_end_equals_file_end",
    "candidate_points_to_expected_signature",
    "candidate_points_to_local_header_signature",
    "candidate_points_to_local_header_signature",
    "count_delta_bucket",
    "delta_equals_sfx_prefix_len",
    "delta_explained",
    "delta_matches_deleted_range",
    "direct_field_violation_present",
    "eocd_comment_tail_bytes_present",
    "explanation_applies",
    "explanation_present",
    "graph_violation_present",
    "mismatch_count_bucket",
    "mismatch_ratio_bucket",
    "missing_range_explanation_applies",
    "available_comment_bytes_delta_bucket",
    "crc_mismatch_count",
    "data_error_count",
    "entry_failed_count",
    "no_payload_hash_crc_failure",
    "payload_content_failure_observed",
    "payload_crc_observed",
    "payload_hash_mismatch_count",
    "payload_unverified_but_no_failure",
    "payload_verification_observed",
    "payload_verified_intact",
    "inside_descriptor_span",
    "inside_payload_span",
    "only_valid_with_missing_range",
    "only_valid_with_sfx_prefix",
    "payload_end_after_descriptor",
    "payload_end_after_next_local",
    "payload_end_before_next_local",
    "payload_end_equals_descriptor_start",
    "payload_end_equals_next_local",
    "payload_end_inside_archive",
    "payload_end_inside_descriptor",
    "payload_failure_without_match_violation",
    "points_to_expected_signature",
    "points_to_other_entry",
    "relative_delta_to_expected_bucket",
    "span_present",
    "span_conflict_count_bucket",
    "tail_bytes_after_eocd_bucket",
    "unexpected_end_count",
    "valid_with_missing_range",
    "valid_with_sfx_prefix",
    "values_equal",
    "verification_crc_failure",
    "sfx_prefix_present",
    "split_missing_range_present",
    "zip64_extra_mismatch_present",
    "zip64_extra_overrides_field",
    "zip64_extra_present",
}
CONFLICT_PAIR_SPECS = {
    "eocd_cd_offset": ("eocd.cd_offset", "points_to"),
    "eocd_cd_size": ("eocd.cd_size", "owns_span"),
    "eocd_entry_count": ("eocd.entry_count", "field_value"),
    "cd_local_offset": ("central_directory.local_header_offset", "points_to"),
    "cd_local_crc": ("local_header.crc", "should_match"),
    "cd_local_flags": ("local_header.flags", "should_match"),
    "cd_local_name": ("central_directory.filename", "should_match"),
    "cd_compressed_size_span": ("central_directory.compressed_size", "owns_span"),
    "payload_descriptor_span": ("data_descriptor.record", "owns_span"),
    "sfx_cd_offset": ("sfx_prefix.bytes", "sfx_prefix_adjustment"),
    "missing_range_payload_span": ("split_volume.missing_range", "missing_range_adjustment"),
    "zip64_extra_override": ("zip64.extra", "zip64_extra_resolution"),
}


def get_normal_structure_adapter(fmt: str) -> "ZipNormalStructureAdapter | None":
    normalized = str(fmt or "").lower().strip().replace("-", "_")
    if normalized in {"zip", ".zip"}:
        return ZipNormalStructureAdapter()
    return None


@dataclass(frozen=True)
class ZipNormalStructureAdapter:
    format: str = "zip"

    def rows_from_request_payload(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        runtime = payload.get("runtime_context") if isinstance(payload.get("runtime_context"), dict) else {}
        probe = runtime.get("analysis_native_probe") if isinstance(runtime.get("analysis_native_probe"), dict) else {}
        structure = probe.get("structure") if isinstance(probe.get("structure"), dict) else {}
        if not isinstance(structure.get("graph"), dict):
            raw = probe.get("raw_structure") if isinstance(probe.get("raw_structure"), dict) else {}
            if isinstance(raw.get("graph"), dict):
                structure = raw
        return ZipNormalQueryBuilder().build_runtime_queries(structure)

    def rows_from_graph(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        return ZipNormalQueryBuilder().build_runtime_queries({"graph": graph})

    def training_rows_from_graph(
        self,
        graph: dict[str, Any],
        *,
        sample_id: str,
        source_identity: dict[str, Any] | None = None,
        rng: random.Random | None = None,
    ) -> list[dict[str, Any]]:
        return ZipNormalQueryBuilder(rng=rng).build_training_queries(
            {"graph": graph},
            sample_id=sample_id,
            source_identity=source_identity,
        )

    def build_anomaly_payload(self, rows: list[dict[str, Any]], normal_scores: list[float]) -> dict[str, Any]:
        queries: list[dict[str, Any]] = []
        compact_sources: list[dict[str, Any]] = []
        field_scores: dict[str, list[float]] = {}
        zone_scores: dict[str, list[float]] = {}
        trusted_explanations: dict[str, float] = {}
        unexplained_payload = 0
        for index, row in enumerate(rows):
            score = float(normal_scores[index]) if index < len(normal_scores) else 1.0
            normal = max(0.0, min(1.0, score))
            anomaly = 1.0 - normal
            field = str(row.get("target_field") or "")
            zone = str(row.get("target_zone") or _zone_for_field(field))
            explanation = str(row.get("explanation_kind") or row.get("relation_kind") or "")
            if field:
                field_scores.setdefault(field, []).append(anomaly)
            if zone:
                zone_scores.setdefault(zone, []).append(anomaly)
            if str(row.get("query_type") or "") == "explanation" and explanation:
                trusted_explanations[explanation] = max(trusted_explanations.get(explanation, 0.0), normal)
            if zone == "payload" and anomaly >= 0.5 and not trusted_explanations:
                unexplained_payload += 1
            query = {
                "query_id": row.get("query_id") or f"query:{index}",
                "query_type": row.get("query_type"),
                "target_field": field,
                "target_zone": zone,
                "relation_kind": _semantic_relation_kind(field, row.get("relation_kind") or row.get("query_type")),
                "raw_relation_kind": row.get("relation_kind"),
                "candidate_source": row.get("candidate_source"),
                "normal_confidence": normal,
                "anomaly_score": anomaly,
            }
            queries.append(query)
            compact_sources.append({
                **query,
                "features": _compact_features(row.get("features") if isinstance(row.get("features"), dict) else {}),
            })
        compact = _compact_attribution(compact_sources, trusted_explanations)
        return {
            "schema_version": QUERY_SCHEMA_VERSION,
            "queries": queries,
            "compact_attribution": compact,
            "summary": {
                "query_count": len(queries),
                "max_anomaly": max((item["anomaly_score"] for item in queries), default=0.0),
                "max_anomaly_by_field": {key: max(values) for key, values in sorted(field_scores.items())},
                "mean_anomaly_by_zone": {key: sum(values) / max(1, len(values)) for key, values in sorted(zone_scores.items())},
                "trusted_explanations": dict(sorted(trusted_explanations.items())),
                "explained_by_sfx_ratio": _trusted_ratio(trusted_explanations, "sfx_prefix_adjustment"),
                "explained_by_missing_range_ratio": _trusted_ratio(trusted_explanations, "missing_range_adjustment"),
                "unexplained_payload_span_anomaly_count": unexplained_payload,
            },
        }

    def inject_anomaly_payload(self, damage_analysis_input: dict[str, Any], anomaly: dict[str, Any]) -> dict[str, Any]:
        payload = dict(damage_analysis_input or {})
        runtime = dict(payload.get("runtime_context") or {})
        probe = dict(runtime.get("analysis_native_probe") or {})
        structure = dict(probe.get("structure") or {})
        raw_structure = dict(probe.get("raw_structure") or {})
        structure["anomaly"] = dict(anomaly or {})
        raw_structure["anomaly"] = dict(anomaly or {})
        probe["structure"] = structure
        probe["raw_structure"] = raw_structure
        runtime["analysis_native_probe"] = probe
        payload["runtime_context"] = runtime
        return payload


class ZipNormalQueryBuilder:
    def __init__(self, *, rng: random.Random | None = None, negatives_per_positive: int = 5):
        self.rng = rng or random.Random(0)
        self.negatives_per_positive = max(0, int(negatives_per_positive or 0))

    def build_runtime_queries(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        return self._build_queries(graph, sample_id="", source_identity=None, include_negatives=False)

    def build_training_queries(
        self,
        graph: dict[str, Any],
        *,
        sample_id: str,
        source_identity: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        return self._build_queries(graph, sample_id=sample_id, source_identity=source_identity, include_negatives=True)

    def _build_queries(
        self,
        graph: dict[str, Any],
        *,
        sample_id: str,
        source_identity: dict[str, Any] | None,
        include_negatives: bool,
    ) -> list[dict[str, Any]]:
        ctx = _GraphContext(graph)
        rows: list[dict[str, Any]] = []
        positives = [
            *self._eocd_queries(ctx),
            *self._cd_local_offset_queries(ctx),
            *self._compressed_size_queries(ctx),
            *self._field_match_queries(ctx),
            *self._span_relation_queries(ctx),
            *self._explanation_queries(ctx),
            *self._targeted_field_queries(ctx),
            *self._violation_queries(ctx),
        ]
        for query in positives:
            rows.append(self._with_identity(query, sample_id, source_identity, normal_label=1))
            if include_negatives:
                rows.extend(
                    self._with_identity(item, sample_id, source_identity, normal_label=0)
                    for item in self._negative_queries(query, ctx)
                )
        if not rows:
            rows.append(self._with_identity(_base_query(
                query_type="span_relation",
                target_zone="unknown",
                target_field="unknown",
                target_node_kind="graph",
                relation_kind="graph_parseable",
                candidate_source="empty_graph",
                features={"graph_parseable": False},
            ), sample_id, source_identity, normal_label=0 if include_negatives else 1))
        return rows

    def _eocd_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        return [
            _base_query(
                query_type="field_value",
                target_zone="eocd",
                target_field="eocd.cd_offset",
                target_node_kind="eocd",
                candidate_source="declared_field",
                features=ctx.offset_features(
                    candidate=ctx.declared_cd_offset,
                    expected=ctx.physical_cd_offset,
                    field="eocd.cd_offset",
                ),
            ),
            _base_query(
                query_type="field_value",
                target_zone="eocd",
                target_field="eocd.cd_size",
                target_node_kind="eocd",
                candidate_source="declared_field",
                features=ctx.size_features(
                    candidate=ctx.declared_cd_size,
                    expected=ctx.physical_cd_size,
                    field="eocd.cd_size",
                ),
            ),
            _base_query(
                query_type="field_value",
                target_zone="eocd",
                target_field="eocd.entry_count",
                target_node_kind="eocd",
                candidate_source="declared_field",
                features={
                    **ctx.count_features(ctx.declared_entry_count, ctx.cd_entry_count),
                    "cd_parse_truncated": bool(ctx.summary.get("truncated") or ctx.summary.get("cd_entries_checked") != ctx.summary.get("cd_entry_count")),
                },
            ),
            _base_query(
                query_type="field_value",
                target_zone="eocd",
                target_field="eocd.comment_length",
                target_node_kind="eocd",
                candidate_source="declared_field",
                features=ctx.comment_features(),
            ),
        ]

    def _cd_local_offset_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        edges = [edge for edge in ctx.edges if edge.get("field") == "local_header_offset"]
        if not edges and ctx.cd_entry_count:
            edges = [{} for _ in range(min(ctx.cd_entry_count, 8))]
        for index, edge in enumerate(edges[:32]):
            rows.append(_base_query(
                query_type="field_value",
                target_zone="central_directory",
                target_field="central_directory.local_header_offset",
                target_node_kind="cd_entry",
                source_node_kind="cd_entry",
                relation_kind="points_to",
                entry_index_bucket=_entry_bucket(index, max(1, len(edges))),
                candidate_source="declared_field",
                features=ctx.local_offset_features(edge=edge, index=index),
            ))
        return rows

    def _compressed_size_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        count = max(1, min(ctx.cd_entry_count or len(ctx.payload_nodes), 32))
        for index in range(count):
            rows.append(_base_query(
                query_type="field_value",
                target_zone="central_directory",
                target_field="central_directory.compressed_size",
                target_node_kind="cd_entry",
                source_node_kind="cd_entry",
                relation_kind="owns_span",
                entry_index_bucket=_entry_bucket(index, count),
                candidate_source="declared_field",
                features=ctx.compressed_size_features(index=index),
            ))
        if ctx.local_header_candidate_count:
            rows.append(_base_query(
                query_type="field_value",
                target_zone="local_header",
                target_field="local_header.compressed_size",
                target_node_kind="local_header_candidate",
                relation_kind="owns_span",
                candidate_source="declared_field",
                features=ctx.compressed_size_features(index=0),
            ))
        return rows

    def _field_match_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        mapping = (
            ("cd_local_crc_match", "local_header.crc", "central_local_crc_mismatch_count"),
            ("cd_local_flags_match", "local_header.flags", "central_local_flags_mismatch_count"),
            ("cd_local_method_match", "local_header.method", "central_local_method_mismatch_count"),
            ("cd_local_name_match", "central_directory.filename", "central_local_name_mismatch_count"),
            ("cd_local_size_match", "local_header.compressed_size", "central_local_compressed_size_mismatch_count"),
        )
        rows: list[dict[str, Any]] = []
        for relation, field, count_key in mapping:
            mismatch = _int(ctx.summary.get(count_key))
            rows.append(_base_query(
                query_type="field_match",
                target_zone=_zone_for_field(field),
                target_field=field,
                target_node_kind="cd_entry",
                source_node_kind="cd_entry",
                relation_kind=relation,
                candidate_source="observed_relation",
                features={
                    "both_fields_present": ctx.cd_entry_count > 0 and ctx.local_header_candidate_count > 0,
                    "values_equal": mismatch == 0,
                    "mismatch_count_bucket": _count_bucket(mismatch),
                    "mismatch_ratio_bucket": _ratio_bucket(mismatch / max(1, ctx.cd_entry_count)),
                    "bit3_descriptor_flag_set": ctx.descriptor_present_count > 0,
                    "zip64_extra_overrides_field": ctx.zip64_present,
                    "payload_crc_observed": bool(ctx.runtime.get("payload_content_failure_observed")),
                    "verification_crc_failure": bool(ctx.runtime.get("no_payload_hash_crc_failure") is False),
                },
            ))
        return rows

    def _span_relation_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        return [
            _base_query(
                query_type="span_relation",
                target_zone="payload",
                target_field="payload.compressed_data",
                target_node_kind="payload_span",
                relation_kind="payload_span_valid",
                candidate_source="observed_span",
                features=ctx.span_features(kind="payload"),
            ),
            _base_query(
                query_type="span_relation",
                target_zone="data_descriptor",
                target_field="data_descriptor.record",
                target_node_kind="descriptor_candidate",
                relation_kind="descriptor_span_valid",
                candidate_source="observed_span",
                features=ctx.span_features(kind="descriptor"),
            ),
            _base_query(
                query_type="span_relation",
                target_zone="central_directory",
                target_field="central_directory.header",
                target_node_kind="central_directory",
                relation_kind="central_directory_span_valid",
                candidate_source="observed_span",
                features=ctx.span_features(kind="central_directory"),
            ),
            _base_query(
                query_type="span_relation",
                target_zone="eocd",
                target_field="eocd.comment_length",
                target_node_kind="eocd",
                relation_kind="eocd_tail_span_valid",
                candidate_source="observed_span",
                features=ctx.comment_features(),
            ),
        ]

    def _explanation_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        explanation_kinds = {
            str(item.get("kind") or ""): item
            for item in ctx.explanations
            if isinstance(item, dict)
        }
        specs = (
            ("sfx_prefix_adjustment", "sfx_prefix", "sfx_prefix.bytes"),
            ("missing_range_adjustment", "split_volume", "split_volume.missing_range"),
            ("zip64_extra_resolution", "zip64", "zip64.extra"),
            ("descriptor_span_adjustment", "data_descriptor", "data_descriptor.record"),
        )
        rows: list[dict[str, Any]] = []
        for relation, zone, field in specs:
            item = explanation_kinds.get(relation) or {}
            rows.append(_base_query(
                query_type="explanation",
                target_zone=zone,
                target_field=field,
                target_node_kind=zone,
                relation_kind=relation,
                explanation_kind=relation,
                candidate_source="observed_explanation",
                features=ctx.explanation_features(relation, item),
            ))
        return rows

    def _targeted_field_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        specs = (
            ("eocd", "eocd.comment_length", "field_value", "eocd_comment_length", ctx.comment_target_features()),
            ("sfx_prefix", "sfx_prefix.bytes", "explanation", "sfx_prefix_field", ctx.sfx_prefix_target_features()),
            ("split_volume", "split_volume.missing_range", "explanation", "missing_range_field", ctx.missing_range_target_features()),
            ("payload", "payload.compressed_data", "span_relation", "payload_content_field", ctx.payload_content_target_features()),
            ("central_directory", "central_directory.crc", "field_match", "central_directory_crc_field", ctx.field_match_target_features("central_directory.crc", "central_local_crc_mismatch_count")),
            ("central_directory", "central_directory.flags", "field_match", "central_directory_flags_field", ctx.field_match_target_features("central_directory.flags", "central_local_flags_mismatch_count")),
            ("local_header", "local_header.crc", "field_match", "local_header_crc_field", ctx.field_match_target_features("local_header.crc", "central_local_crc_mismatch_count")),
            ("local_header", "local_header.compressed_size", "field_match", "local_header_compressed_size_field", ctx.field_match_target_features("local_header.compressed_size", "central_local_compressed_size_mismatch_count")),
            ("zip64", "zip64.extra_length", "field_value", "zip64_extra_length_field", ctx.zip64_target_features("zip64.extra_length")),
            ("zip64", "zip64.uncompressed_size", "field_value", "zip64_uncompressed_size_field", ctx.zip64_target_features("zip64.uncompressed_size")),
        )
        return [
            _base_query(
                query_type=query_type,
                target_zone=zone,
                target_field=field,
                target_node_kind=zone,
                relation_kind=relation,
                candidate_source="targeted_field",
                features=features,
            )
            for zone, field, query_type, relation, features in specs
        ]

    def _violation_queries(self, ctx: "_GraphContext") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for index, violation in enumerate(ctx.violations[:64]):
            field = _normal_target_field(str(violation.get("field") or "unknown"))
            kind = str(violation.get("kind") or "graph_violation")
            rows.append(_base_query(
                query_type="field_match" if kind == "field_mismatch" else "span_relation" if "span" in kind or field.startswith("tail.") else "field_value",
                target_zone=_zone_for_field(field),
                target_field=field,
                target_node_kind=_node_kind(violation.get("source_node")) or _zone_for_field(field),
                source_node_kind=_node_kind(violation.get("source_node")),
                relation_kind=kind,
                entry_index_bucket=_entry_bucket(index, max(1, len(ctx.violations))),
                candidate_source="observed_graph_violation",
                features={
                    "graph_violation_present": True,
                    "abs_delta_to_expected_bucket": _abs_delta_bucket(abs(_int(violation.get("delta")))),
                    "relative_delta_to_expected_bucket": _relative_delta_bucket(abs(_int(violation.get("delta"))), ctx.file_size),
                    "points_to_expected_signature": False,
                    "candidate_points_to_expected_signature": False,
                    "values_equal": False,
                    "span_present": True,
                },
            ))
        return rows

    def _negative_queries(self, query: dict[str, Any], ctx: "_GraphContext") -> list[dict[str, Any]]:
        features = query.get("features") if isinstance(query.get("features"), dict) else {}
        candidates: list[dict[str, Any]] = []
        target = str(query.get("target_field") or "")
        for index, delta in enumerate(NEGATIVE_DELTAS):
            negative = dict(query)
            negative["candidate_kind"] = "counterfactual"
            negative["candidate_source"] = f"anchor_delta:{delta}"
            mutated = dict(features)
            mutated.update({
                "graph_violation_present": True,
                "candidate_inside_archive": True,
                "points_to_expected_signature": False,
                "candidate_points_to_expected_signature": False,
                "values_equal": False,
                "abs_delta_to_expected_bucket": _abs_delta_bucket(abs(delta)),
                "relative_delta_to_expected_bucket": _relative_delta_bucket(abs(delta), ctx.file_size),
            })
            if "local_header_offset" in target:
                mutated.update(self._local_offset_negative_features(ctx, index))
            elif "compressed_size" in target:
                mutated.update(self._compressed_size_negative_features(index))
            elif "entry_count" in target:
                mutated.update({
                    "candidate_count_equals_walked": False,
                    "candidate_count_less_than_walked": delta < 0,
                    "candidate_count_greater_than_walked": delta > 0,
                    "count_delta_bucket": _count_bucket(abs(delta)),
                })
            elif "comment" in target:
                mutated.update({
                    "candidate_comment_end_equals_file_end": False,
                    "candidate_comment_end_before_file_end": delta < 0,
                    "candidate_comment_end_after_file_end": delta > 0,
                    "eocd_comment_tail_bytes_present": True,
                    "available_comment_bytes_delta_bucket": _abs_delta_bucket(abs(delta)),
                })
            elif target == "sfx_prefix.bytes":
                mutated.update({
                    "sfx_prefix_present": True,
                    "explanation_applies": False,
                    "delta_explained": False,
                    "only_valid_with_sfx_prefix": False,
                    "delta_equals_sfx_prefix_len": True,
                })
            elif target == "split_volume.missing_range":
                mutated.update({
                    "split_missing_range_present": True,
                    "missing_range_explanation_applies": False,
                    "explanation_applies": False,
                    "only_valid_with_missing_range": False,
                    "delta_matches_deleted_range": True,
                })
            elif target == "payload.compressed_data":
                mutated.update(self._payload_negative_features(index))
            elif target in {"central_directory.crc", "central_directory.flags", "local_header.crc"}:
                mutated.update({
                    "both_fields_present": True,
                    "values_equal": False,
                    "direct_field_violation_present": True,
                    "mismatch_count_bucket": "one",
                    "mismatch_ratio_bucket": "large",
                })
            elif target.startswith("zip64."):
                mutated.update({
                    "zip64_extra_present": True,
                    "zip64_extra_mismatch_present": True,
                    "zip64_extra_overrides_field": False,
                    "direct_field_violation_present": True,
                })
            elif query.get("query_type") == "explanation":
                mutated.update({
                    "explanation_applies": False,
                    "delta_explained": False,
                    "only_valid_with_sfx_prefix": False,
                    "only_valid_with_missing_range": False,
                })
            negative["features"] = mutated
            candidates.append(negative)
            if len(candidates) >= self.negatives_per_positive:
                break
        return candidates

    def _with_identity(
        self,
        query: dict[str, Any],
        sample_id: str,
        source_identity: dict[str, Any] | None,
        *,
        normal_label: int,
    ) -> dict[str, Any]:
        row = dict(query)
        row.setdefault("schema_version", QUERY_SCHEMA_VERSION)
        row.setdefault("row_type", "normal_structure_query")
        row.setdefault("format", "zip")
        row["sample_id"] = sample_id
        row["source_identity"] = dict(source_identity or {})
        row["normal_label"] = int(normal_label)
        row.setdefault("metadata", {})
        return row

    @staticmethod
    def _local_offset_negative_features(ctx: "_GraphContext", index: int) -> dict[str, Any]:
        variants = (
            {"points_to_other_entry": True, "inside_payload_span": False, "inside_descriptor_span": False},
            {"points_to_other_entry": False, "inside_payload_span": True, "inside_descriptor_span": False},
            {"points_to_other_entry": False, "inside_payload_span": False, "inside_descriptor_span": True},
            {"candidate_inside_archive": False, "points_to_other_entry": False},
            {"valid_with_sfx_prefix": ctx.sfx_prefix_len > 0, "only_valid_with_sfx_prefix": ctx.sfx_prefix_len > 0},
        )
        return dict(variants[index % len(variants)])

    @staticmethod
    def _payload_negative_features(index: int) -> dict[str, Any]:
        variants = (
            {"payload_content_failure_observed": True, "payload_failure_without_match_violation": True},
            {"payload_end_inside_archive": False, "span_present": True},
            {"payload_end_after_next_local": True, "span_conflict_count_bucket": "one"},
            {"valid_with_missing_range": True, "only_valid_with_missing_range": True},
            {"payload_end_inside_descriptor": True},
        )
        return dict(variants[index % len(variants)])

    @staticmethod
    def _compressed_size_negative_features(index: int) -> dict[str, Any]:
        variants = (
            {"payload_end_before_next_local": True, "payload_end_equals_next_local": False},
            {"payload_end_inside_descriptor": True, "payload_end_equals_descriptor_start": False},
            {"payload_end_after_descriptor": True},
            {"payload_end_after_next_local": True},
            {"payload_end_inside_archive": False},
        )
        return dict(variants[index % len(variants)])


class _GraphContext:
    def __init__(self, structure: dict[str, Any]):
        payload = structure if isinstance(structure, dict) else {}
        graph = payload.get("graph") if isinstance(payload.get("graph"), dict) else payload
        self.graph = graph if isinstance(graph, dict) else {}
        graph_summary = self.graph.get("summary") if isinstance(self.graph.get("summary"), dict) else {}
        structure_summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        self.summary = graph_summary or structure_summary
        self.runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
        self.extraction_outcomes = self.runtime.get("extraction_entry_outcomes") if isinstance(self.runtime.get("extraction_entry_outcomes"), dict) else {}
        self.coverage_breakdown = self.runtime.get("verification_coverage_breakdown") if isinstance(self.runtime.get("verification_coverage_breakdown"), dict) else {}
        self.nodes = [item for item in self.graph.get("nodes") or [] if isinstance(item, dict)]
        self.edges = [item for item in self.graph.get("edges") or [] if isinstance(item, dict)]
        self.violations = [item for item in self.graph.get("violations") or [] if isinstance(item, dict)]
        self.explanations = [item for item in self.graph.get("explanations") or [] if isinstance(item, dict)]
        self.nodes_by_kind: dict[str, list[dict[str, Any]]] = {}
        for node in self.nodes:
            self.nodes_by_kind.setdefault(str(node.get("kind") or ""), []).append(node)
        self.file_size = max(1, _int(self.summary.get("file_size")))
        self.physical_cd_offset = _int(self.summary.get("physical_central_directory_offset"))
        self.declared_cd_offset = _int(self.summary.get("declared_central_directory_offset"))
        self.physical_cd_size = max(0, _span_size(self.nodes_by_kind.get("central_directory", [{}])[0]))
        self.declared_cd_size = max(0, self.physical_cd_size + _int(self.summary.get("central_directory_size_delta")))
        self.cd_entry_count = _int(self.summary.get("cd_entry_count"))
        self.declared_entry_count = max(0, self.cd_entry_count - _int(self.summary.get("entry_count_delta")))
        self.local_header_candidate_count = _int(self.summary.get("local_header_candidate_count"))
        self.sfx_prefix_len = _int(self.summary.get("sfx_prefix_len"))
        self.descriptor_present_count = _int(self.summary.get("descriptor_conflict_count")) + len(self.nodes_by_kind.get("descriptor_candidate", []))
        self.zip64_present = bool(self.summary.get("zip64_eocd_present") or self.summary.get("zip64_locator_present") or _int(self.summary.get("zip64_extra_present_count")) > 0)
        self.payload_nodes = self.nodes_by_kind.get("payload_span", [])
        self.descriptor_nodes = self.nodes_by_kind.get("descriptor_candidate", [])
        self.explanations_by_kind = {
            str(item.get("kind") or ""): item
            for item in self.explanations
            if isinstance(item, dict)
        }

    def offset_features(self, *, candidate: int, expected: int, field: str) -> dict[str, Any]:
        delta = int(candidate) - int(expected)
        return {
            "candidate_inside_archive": 0 <= candidate < self.file_size,
            "candidate_points_to_expected_signature": delta == 0,
            "points_to_expected_signature": delta == 0,
            "candidate_points_to_cd_signature": field == "eocd.cd_offset" and delta == 0,
            "valid_with_sfx_prefix": self.sfx_prefix_len > 0 and abs(delta) == self.sfx_prefix_len,
            "only_valid_with_sfx_prefix": self.sfx_prefix_len > 0 and delta != 0 and abs(delta) == self.sfx_prefix_len,
            "delta_equals_sfx_prefix_len": self.sfx_prefix_len > 0 and abs(delta) == self.sfx_prefix_len,
            "valid_with_missing_range": False,
            "only_valid_with_missing_range": False,
            "delta_matches_deleted_range": False,
            "abs_delta_to_expected_bucket": _abs_delta_bucket(abs(delta)),
            "relative_delta_to_expected_bucket": _relative_delta_bucket(abs(delta), self.file_size),
            "candidate_value_ratio_bucket": _ratio_bucket(candidate / max(1, self.file_size)),
        }

    def size_features(self, *, candidate: int, expected: int, field: str) -> dict[str, Any]:
        delta = int(candidate) - int(expected)
        return {
            "candidate_inside_archive": candidate <= self.file_size,
            "size_matches_expected": delta == 0,
            "abs_delta_to_expected_bucket": _abs_delta_bucket(abs(delta)),
            "relative_delta_to_expected_bucket": _relative_delta_bucket(abs(delta), self.file_size),
            "size_ratio_bucket": _ratio_bucket(candidate / max(1, self.file_size)),
            "payload_end_inside_archive": True,
            "payload_end_after_next_local": False,
            "payload_end_inside_descriptor": False,
            "payload_end_equals_descriptor_start": delta == 0,
        }

    def count_features(self, candidate: int, expected: int) -> dict[str, Any]:
        delta = int(candidate) - int(expected)
        return {
            "candidate_count_equals_walked": delta == 0,
            "candidate_count_less_than_walked": delta < 0,
            "candidate_count_greater_than_walked": delta > 0,
            "count_delta_bucket": _count_bucket(abs(delta)),
            "disk_entry_count_equals_total": True,
        }

    def comment_features(self) -> dict[str, Any]:
        trailing = _int(self.summary.get("trailing_bytes_after_eocd"))
        return {
            "candidate_comment_end_equals_file_end": trailing == 0,
            "candidate_comment_end_before_file_end": trailing > 0,
            "candidate_comment_end_after_file_end": False,
            "available_comment_bytes_delta_bucket": _abs_delta_bucket(trailing),
            "tail_bytes_after_eocd_bucket": _abs_delta_bucket(trailing),
        }

    def comment_target_features(self) -> dict[str, Any]:
        trailing = _int(self.summary.get("trailing_bytes_after_eocd"))
        direct = self.has_violation_field("eocd.comment_length") or self.has_violation_field("tail.trailing_bytes")
        return {
            **self.comment_features(),
            "direct_field_violation_present": direct,
            "eocd_comment_tail_bytes_present": trailing > 0,
            "graph_violation_present": direct,
        }

    def local_offset_features(self, *, edge: dict[str, Any], index: int) -> dict[str, Any]:
        valid = bool(edge.get("valid", True))
        target = str(edge.get("target_node") or "")
        return {
            "candidate_inside_archive": valid,
            "candidate_points_to_expected_signature": valid,
            "points_to_expected_signature": valid,
            "candidate_points_to_local_header_signature": valid,
            "points_to_other_entry": "other" in target,
            "candidate_points_to_other_entry": "other" in target,
            "inside_payload_span": False,
            "inside_descriptor_span": False,
            "candidate_inside_payload_span": False,
            "candidate_inside_descriptor_span": False,
            "candidate_outside_archive": not valid,
            "valid_with_sfx_prefix": self.sfx_prefix_len > 0 and valid,
            "only_valid_with_sfx_prefix": bool(self.summary.get("local_offset_only_valid_with_prefix_count")),
            "delta_equals_sfx_prefix_len": bool(self.summary.get("cd_offset_delta_equals_prefix_len") or self.sfx_prefix_len > 0),
            "valid_with_missing_range": bool(self.summary.get("missing_range_likely_structural_cause")),
            "only_valid_with_missing_range": bool(self.summary.get("local_offset_error_explained_by_missing_range")),
            "delta_matches_deleted_range": bool(self.summary.get("cd_offset_delta_matches_deleted_range")),
            "abs_delta_to_expected_bucket": "exact" if valid else "large",
            "relative_delta_to_expected_bucket": "exact" if valid else "large",
            "entry_index_bucket": _entry_bucket(index, max(1, self.cd_entry_count)),
        }

    def compressed_size_features(self, *, index: int) -> dict[str, Any]:
        span_conflicts = _int(self.summary.get("span_conflict_count"))
        descriptor_conflicts = _int(self.summary.get("descriptor_conflict_count"))
        return {
            "candidate_payload_end_inside_archive": span_conflicts == 0,
            "payload_end_inside_archive": span_conflicts == 0,
            "payload_end_equals_descriptor_start": descriptor_conflicts == 0,
            "payload_end_inside_descriptor": bool(self.summary.get("compressed_size_ends_inside_descriptor_count")),
            "payload_end_after_descriptor": bool(self.summary.get("compressed_size_ends_after_descriptor_count")),
            "payload_end_before_next_local": bool(self.summary.get("compressed_size_ends_before_next_local_gap_count")),
            "payload_end_equals_next_local": span_conflicts == 0,
            "payload_end_after_next_local": span_conflicts > 0,
            "delta_to_descriptor_start_bucket": "exact" if descriptor_conflicts == 0 else "medium",
            "delta_to_next_local_header_bucket": "exact" if span_conflicts == 0 else "medium",
            "size_ratio_bucket": "small",
            "entry_index_bucket": _entry_bucket(index, max(1, self.cd_entry_count)),
        }

    def span_features(self, *, kind: str) -> dict[str, Any]:
        if kind == "descriptor":
            conflicts = _int(self.summary.get("descriptor_conflict_count"))
            present = bool(self.descriptor_nodes)
            return {
                "span_present": present,
                "span_conflict_count_bucket": _count_bucket(conflicts),
                "descriptor_span_valid": conflicts == 0,
                "descriptor_bit3_explanation_valid": present and conflicts == 0,
            }
        if kind == "central_directory":
            delta = _int(self.summary.get("central_directory_size_delta"))
            return {
                "span_present": self.physical_cd_size > 0,
                "central_directory_span_valid": delta == 0,
                "declared_cd_end_before_eocd": delta <= 0,
                "declared_cd_end_after_eocd": delta > 0,
                "abs_delta_to_expected_bucket": _abs_delta_bucket(abs(delta)),
            }
        conflicts = _int(self.summary.get("span_conflict_count"))
        return {
            "span_present": bool(self.payload_nodes),
            "payload_span_valid": conflicts == 0,
            "span_conflict_count_bucket": _count_bucket(conflicts),
            "payload_end_inside_archive": conflicts == 0,
        }

    def sfx_prefix_target_features(self) -> dict[str, Any]:
        item = self.explanations_by_kind.get("sfx_prefix_adjustment") or {}
        applies = bool(item.get("applies", item.get("valid", False)))
        direct = self.has_violation_field("sfx_prefix.bytes") or self.sfx_prefix_len > 0
        return {
            **self.explanation_features("sfx_prefix_adjustment", item),
            "sfx_prefix_present": self.sfx_prefix_len > 0,
            "direct_field_violation_present": direct,
            "graph_violation_present": direct,
            "delta_equals_sfx_prefix_len": bool(self.summary.get("central_directory_offset_delta")) and self.sfx_prefix_len > 0,
            "only_valid_with_sfx_prefix": applies,
        }

    def missing_range_target_features(self) -> dict[str, Any]:
        item = self.explanations_by_kind.get("missing_range_adjustment") or {}
        applies = bool(item.get("applies", item.get("valid", False)))
        direct = self.has_violation_field("split_volume.missing_range") or applies
        return {
            **self.explanation_features("missing_range_adjustment", item),
            "split_missing_range_present": applies,
            "missing_range_explanation_applies": applies,
            "direct_field_violation_present": direct,
            "graph_violation_present": direct,
            "valid_with_missing_range": applies,
            "only_valid_with_missing_range": applies,
            "delta_matches_deleted_range": applies,
        }

    def payload_content_target_features(self) -> dict[str, Any]:
        span = self.span_features(kind="payload")
        content_failure = bool(self.runtime.get("payload_content_failure_observed"))
        verification_observed = bool(self.runtime.get("payload_verification_observed"))
        verified_intact = bool(self.runtime.get("payload_verified_intact"))
        unverified_no_failure = bool(self.runtime.get("payload_unverified_but_no_failure"))
        no_payload_hash_crc_failure = bool(self.runtime.get("no_payload_hash_crc_failure", True))
        crc_mismatch_count = self._crc_mismatch_count()
        payload_hash_mismatch_count = _int(self.coverage_breakdown.get("payload_hash_mismatch_count"))
        entry_failed_count = _int(self.extraction_outcomes.get("entry_failed_count"))
        data_error_count = _int(self.extraction_outcomes.get("data_error_count"))
        unexpected_end_count = _int(self.extraction_outcomes.get("unexpected_end_count"))
        crc_failure = (not no_payload_hash_crc_failure) or crc_mismatch_count > 0 or payload_hash_mismatch_count > 0
        extraction_payload_failure = data_error_count > 0 or unexpected_end_count > 0
        direct = self.has_violation_field("payload.compressed_data") or content_failure or crc_failure or extraction_payload_failure
        match_violation = any(
            self.has_violation_field(field)
            for field in ("local_header.crc", "central_directory.crc", "local_header.compressed_size", "central_directory.compressed_size")
        )
        return {
            **span,
            "payload_content_failure_observed": content_failure,
            "payload_verification_observed": verification_observed,
            "payload_verified_intact": verified_intact,
            "payload_unverified_but_no_failure": unverified_no_failure,
            "no_payload_hash_crc_failure": no_payload_hash_crc_failure,
            "crc_mismatch_count": crc_mismatch_count,
            "payload_hash_mismatch_count": payload_hash_mismatch_count,
            "entry_failed_count": entry_failed_count,
            "data_error_count": data_error_count,
            "unexpected_end_count": unexpected_end_count,
            "verification_crc_failure": crc_failure,
            "payload_failure_without_match_violation": (direct or extraction_payload_failure) and not match_violation,
            "direct_field_violation_present": direct,
            "graph_violation_present": direct,
        }

    def field_match_target_features(self, field: str, count_key: str) -> dict[str, Any]:
        mismatch = _int(self.summary.get(count_key))
        direct = self.has_violation_field(field) or mismatch > 0
        crc_mismatch_count = self._crc_mismatch_count()
        payload_hash_mismatch_count = _int(self.coverage_breakdown.get("payload_hash_mismatch_count"))
        data_error_count = _int(self.extraction_outcomes.get("data_error_count"))
        unexpected_end_count = _int(self.extraction_outcomes.get("unexpected_end_count"))
        no_payload_hash_crc_failure = bool(self.runtime.get("no_payload_hash_crc_failure", True))
        return {
            "both_fields_present": self.cd_entry_count > 0 and self.local_header_candidate_count > 0,
            "values_equal": mismatch == 0 and not self.has_violation_field(field),
            "mismatch_count_bucket": _count_bucket(mismatch),
            "mismatch_ratio_bucket": _ratio_bucket(mismatch / max(1, self.cd_entry_count)),
            "bit3_descriptor_flag_set": self.descriptor_present_count > 0,
            "zip64_extra_overrides_field": self.zip64_present,
            "payload_crc_observed": bool(self.runtime.get("payload_content_failure_observed")),
            "payload_verification_observed": bool(self.runtime.get("payload_verification_observed")),
            "payload_verified_intact": bool(self.runtime.get("payload_verified_intact")),
            "no_payload_hash_crc_failure": no_payload_hash_crc_failure,
            "crc_mismatch_count": crc_mismatch_count,
            "payload_hash_mismatch_count": payload_hash_mismatch_count,
            "entry_failed_count": _int(self.extraction_outcomes.get("entry_failed_count")),
            "data_error_count": data_error_count,
            "unexpected_end_count": unexpected_end_count,
            "verification_crc_failure": (not no_payload_hash_crc_failure) or crc_mismatch_count > 0 or payload_hash_mismatch_count > 0,
            "direct_field_violation_present": direct,
            "graph_violation_present": direct,
        }

    def zip64_target_features(self, field: str) -> dict[str, Any]:
        item = self.explanations_by_kind.get("zip64_extra_resolution") or {}
        mismatch = _int(self.summary.get("zip64_extra_mismatch_count"))
        direct = self.has_violation_field(field) or mismatch > 0
        return {
            **self.explanation_features("zip64_extra_resolution", item),
            "zip64_extra_present": _int(self.summary.get("zip64_extra_present_count")) > 0,
            "zip64_extra_mismatch_present": mismatch > 0,
            "zip64_extra_overrides_field": bool(item.get("applies", item.get("valid", False))),
            "direct_field_violation_present": direct,
            "graph_violation_present": direct,
        }

    def explanation_features(self, relation: str, item: dict[str, Any]) -> dict[str, Any]:
        applies = bool(item.get("applies", item.get("valid", False)))
        delta = abs(_int(item.get("delta")))
        return {
            "explanation_present": bool(item),
            "explanation_applies": applies,
            "delta_explained": applies and delta == 0 or applies,
            "only_valid_with_sfx_prefix": relation == "sfx_prefix_adjustment" and applies,
            "only_valid_with_missing_range": relation == "missing_range_adjustment" and applies,
            "zip64_extra_overrides_field": relation == "zip64_extra_resolution" and applies,
            "descriptor_bit3_explanation_valid": relation == "descriptor_span_adjustment" and applies,
            "abs_delta_to_expected_bucket": _abs_delta_bucket(delta),
        }

    def has_violation_field(self, field: str) -> bool:
        return any(str(item.get("field") or "") == field for item in self.violations)

    def _crc_mismatch_count(self) -> int:
        return (
            _int(self.coverage_breakdown.get("crc_mismatch_count"))
            + _int(self.coverage_breakdown.get("archive_crc_test_failed_count"))
            + _int(self.coverage_breakdown.get("archive_crc_file_missing_count"))
        )


def _base_query(
    *,
    query_type: str,
    target_zone: str,
    target_field: str,
    target_node_kind: str,
    candidate_source: str,
    features: dict[str, Any],
    source_node_kind: str = "",
    relation_kind: str = "",
    explanation_kind: str = "",
    entry_index_bucket: str = "",
) -> dict[str, Any]:
    query_id = "|".join([
        query_type,
        target_field,
        relation_kind,
        candidate_source,
        entry_index_bucket,
    ])
    return {
        "schema_version": QUERY_SCHEMA_VERSION,
        "row_type": "normal_structure_query",
        "format": "zip",
        "query_id": query_id,
        "query_type": query_type,
        "target_zone": target_zone,
        "target_field": target_field,
        "target_node_kind": target_node_kind,
        "source_node_kind": source_node_kind,
        "relation_kind": relation_kind,
        "explanation_kind": explanation_kind,
        "candidate_kind": "observed",
        "candidate_source": candidate_source,
        "entry_index_bucket": entry_index_bucket,
        "features": dict(features or {}),
    }


def _span_size(node: dict[str, Any]) -> int:
    if not isinstance(node, dict):
        return 0
    if node.get("size") is not None:
        return _int(node.get("size"))
    return max(0, _int(node.get("end")) - _int(node.get("start")))


def _compact_features(features: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in sorted(COMPACT_FEATURE_ALLOWLIST):
        if key in features:
            output[key] = features[key]
    return output


def _compact_attribution(queries: list[dict[str, Any]], trusted_explanations: dict[str, float]) -> dict[str, Any]:
    ranked = sorted(queries, key=lambda item: float(item.get("anomaly_score") or 0.0), reverse=True)
    top_queries = [
        {
            "rank": index + 1,
            "query_id": item.get("query_id"),
            "query_type": item.get("query_type"),
            "target_field": item.get("target_field"),
            "target_zone": item.get("target_zone") or _zone_for_field(str(item.get("target_field") or "")),
            "relation_kind": item.get("relation_kind") or item.get("query_type"),
            "anomaly_score": float(item.get("anomaly_score") or 0.0),
            "normal_confidence": float(item.get("normal_confidence") or 0.0),
            "features": dict(item.get("features") or {}),
        }
        for index, item in enumerate(ranked[:TOP_COMPACT_QUERIES])
    ]
    return {
        "schema_version": QUERY_SCHEMA_VERSION,
        "top_queries": top_queries,
        "by_field": _compact_by_field(queries, trusted_explanations),
        "by_relation": _compact_by_relation(queries),
        "by_zone_relation": _compact_by_zone_relation(queries),
        "conflict_pairs": _compact_conflict_pairs(queries, trusted_explanations),
    }


def _compact_by_field(queries: list[dict[str, Any]], trusted_explanations: dict[str, float]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for query in queries:
        field = str(query.get("target_field") or "")
        if field:
            grouped.setdefault(field, []).append(query)
    output: dict[str, Any] = {}
    for field, items in sorted(grouped.items()):
        ranked = sorted(items, key=lambda item: float(item.get("anomaly_score") or 0.0), reverse=True)
        scores = [float(item.get("anomaly_score") or 0.0) for item in ranked]
        top = ranked[0] if ranked else {}
        features = _merged_features(ranked[:3])
        output[field] = {
            "max": max(scores, default=0.0),
            "mean_top3": sum(scores[:3]) / max(1, min(3, len(scores))),
            "count_ge_50": sum(1 for score in scores if score >= 0.5),
            "count_ge_80": sum(1 for score in scores if score >= 0.8),
            "top_relation": str(top.get("relation_kind") or top.get("query_type") or ""),
            "top_query_type": str(top.get("query_type") or ""),
            "has_direct_violation": bool(features.get("graph_violation_present")),
            "explained_by_sfx": _field_explained_by_sfx(field, features, trusted_explanations),
            "explained_by_missing_range": _field_explained_by_missing_range(field, features, trusted_explanations),
        }
    return output


def _compact_by_relation(queries: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for query in queries:
        relation = str(query.get("relation_kind") or query.get("query_type") or "")
        if relation:
            grouped.setdefault(relation, []).append(query)
    output: dict[str, Any] = {}
    for relation, items in sorted(grouped.items()):
        ranked = sorted(items, key=lambda item: float(item.get("anomaly_score") or 0.0), reverse=True)
        scores = [float(item.get("anomaly_score") or 0.0) for item in ranked]
        output[relation] = {
            "max": max(scores, default=0.0),
            "mean_top3": sum(scores[:3]) / max(1, min(3, len(scores))),
            "count_ge_80": sum(1 for score in scores if score >= 0.8),
            "top_field": str(ranked[0].get("target_field") or "") if ranked else "",
        }
    return output


def _compact_by_zone_relation(queries: list[dict[str, Any]]) -> dict[str, float]:
    output: dict[str, float] = {}
    for query in queries:
        field = str(query.get("target_field") or "")
        zone = str(query.get("target_zone") or _zone_for_field(field))
        relation = str(query.get("relation_kind") or query.get("query_type") or "")
        if not zone or not relation:
            continue
        key = f"{zone}|{relation}"
        output[key] = max(output.get(key, 0.0), float(query.get("anomaly_score") or 0.0))
    return dict(sorted(output.items()))


def _compact_conflict_pairs(queries: list[dict[str, Any]], trusted_explanations: dict[str, float]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name, (field, relation) in CONFLICT_PAIR_SPECS.items():
        candidates = [
            query for query in queries
            if _pair_field_match(str(query.get("target_field") or ""), field)
            or _pair_relation_match(str(query.get("relation_kind") or query.get("query_type") or ""), relation)
        ]
        ranked = sorted(candidates, key=lambda item: float(item.get("anomaly_score") or 0.0), reverse=True)
        top = ranked[0] if ranked else {}
        features = _merged_features(ranked[:3])
        output[name] = {
            "score": float(top.get("anomaly_score") or 0.0),
            "explained": _pair_explained(name, features, trusted_explanations),
            "top_field": str(top.get("target_field") or field),
            "top_relation": str(top.get("relation_kind") or top.get("query_type") or relation),
        }
    return output


def _merged_features(queries: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for query in queries:
        features = query.get("features") if isinstance(query.get("features"), dict) else {}
        for key, value in features.items():
            if isinstance(value, bool):
                output[key] = bool(output.get(key, False) or value)
            elif key not in output:
                output[key] = value
    return output


def _pair_field_match(actual: str, expected: str) -> bool:
    if actual == expected:
        return True
    if expected == "zip64.extra":
        return actual.startswith("zip64.")
    return False


def _pair_relation_match(actual: str, expected: str) -> bool:
    return bool(actual and expected and actual == expected)


def _pair_explained(name: str, features: dict[str, Any], trusted_explanations: dict[str, float]) -> bool:
    if name == "sfx_cd_offset":
        return bool(features.get("only_valid_with_sfx_prefix") or features.get("delta_equals_sfx_prefix_len") or trusted_explanations.get("sfx_prefix_adjustment", 0.0) >= 0.5)
    if name == "missing_range_payload_span":
        return bool(features.get("only_valid_with_missing_range") or features.get("delta_matches_deleted_range") or trusted_explanations.get("missing_range_adjustment", 0.0) >= 0.5)
    if name == "zip64_extra_override":
        return bool(features.get("zip64_extra_overrides_field") or trusted_explanations.get("zip64_extra_resolution", 0.0) >= 0.5)
    if name == "payload_descriptor_span":
        return bool(features.get("inside_descriptor_span") or features.get("payload_end_inside_descriptor") or trusted_explanations.get("descriptor_span_adjustment", 0.0) >= 0.5)
    return False


def _semantic_relation_kind(field: str, relation: Any) -> str:
    text = str(relation or "")
    if text in {
        "points_to",
        "owns_span",
        "should_match",
        "field_value",
        "span_relation",
        "sfx_prefix_adjustment",
        "missing_range_adjustment",
        "descriptor_span_adjustment",
        "zip64_extra_resolution",
    }:
        return text
    field_text = str(field or "")
    if any(part in field_text for part in ("offset", "zip64.locator")):
        return "points_to"
    if any(part in field_text for part in ("compressed_size", "uncompressed_size", "payload", "record", "tail", "missing_range")):
        return "owns_span"
    if any(part in field_text for part in ("crc", "flags", "method", "filename", "header")):
        return "should_match"
    return "field_value"


def _field_explained_by_sfx(field: str, features: dict[str, Any], trusted_explanations: dict[str, float]) -> bool:
    return bool(
        field in {"eocd.cd_offset", "central_directory.local_header_offset", "sfx_prefix.bytes"}
        and (
            features.get("only_valid_with_sfx_prefix")
            or features.get("delta_equals_sfx_prefix_len")
            or trusted_explanations.get("sfx_prefix_adjustment", 0.0) >= 0.5
        )
    )


def _field_explained_by_missing_range(field: str, features: dict[str, Any], trusted_explanations: dict[str, float]) -> bool:
    return bool(
        field in {"payload.compressed_data", "split_volume.missing_range", "central_directory.local_header_offset"}
        and (
            features.get("only_valid_with_missing_range")
            or features.get("delta_matches_deleted_range")
            or trusted_explanations.get("missing_range_adjustment", 0.0) >= 0.5
        )
    )


def _zone_for_field(field: str) -> str:
    text = str(field or "")
    if "." not in text:
        return text
    head = text.split(".", 1)[0]
    if head in {"sfx_prefix", "split_volume", "zip64"}:
        return head
    if head == "data_descriptor":
        return "data_descriptor"
    if head == "central_directory":
        return "central_directory"
    if head == "local_header":
        return "local_header"
    return head


def _normal_target_field(field: str) -> str:
    text = str(field or "").strip()
    if not text:
        return "unknown"
    lowered = text.lower()
    if lowered in {"eocd"}:
        return "eocd.cd_offset"
    if lowered in {"central_directory", "cd"}:
        return "central_directory.header"
    if lowered in {"local_header", "local"}:
        return "local_header.compressed_size"
    if lowered in {"payload", "payload_span"}:
        return "payload.compressed_data"
    if lowered in {"descriptor", "data_descriptor", "descriptor_candidate"}:
        return "data_descriptor.record"
    if lowered in {"tail", "trailing_bytes", "unexpected_tail"}:
        return "tail.trailing_bytes"
    if lowered in {"zip64", "zip64_eocd", "zip64_locator"}:
        return "zip64.eocd"
    if lowered in {"sfx", "sfx_prefix", "prefix"}:
        return "sfx_prefix.bytes"
    if lowered in {"split", "split_volume", "missing_range"}:
        return "split_volume.missing_range"
    return lowered


def _node_kind(node_id: Any) -> str:
    text = str(node_id or "").strip()
    if not text:
        return ""
    return text.split(":", 1)[0]


def _entry_bucket(index: int, total: int) -> str:
    if total <= 1:
        return "only"
    if index <= 0:
        return "first"
    if index >= total - 1:
        return "last"
    return "middle"


def _abs_delta_bucket(delta: int | float) -> str:
    value = abs(float(delta or 0))
    if value == 0:
        return "exact"
    if value <= 3:
        return "1-3"
    if value <= 15:
        return "4-15"
    if value <= 63:
        return "16-63"
    if value <= 255:
        return "64-255"
    if value <= 1023:
        return "256-1023"
    return "1024+"


def _relative_delta_bucket(delta: int | float, file_size: int) -> str:
    value = abs(float(delta or 0)) / max(1.0, float(file_size or 1))
    if value == 0:
        return "exact"
    if value <= 0.001:
        return "tiny"
    if value <= 0.01:
        return "small"
    if value <= 0.1:
        return "medium"
    if value <= 1.0:
        return "large"
    return "out_of_archive"


def _ratio_bucket(value: float) -> str:
    try:
        ratio = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if ratio < 0 or ratio > 1:
        return "out_of_archive"
    if ratio == 0:
        return "zero"
    if ratio <= 0.01:
        return "tiny"
    if ratio <= 0.1:
        return "small"
    if ratio <= 0.75:
        return "medium"
    return "large"


def _count_bucket(value: int | float) -> str:
    count = abs(int(value or 0))
    if count == 0:
        return "zero"
    if count == 1:
        return "one"
    if count <= 3:
        return "few"
    if count <= 16:
        return "many"
    return "huge"


def _trusted_ratio(explanations: dict[str, float], key: str) -> float:
    value = float(explanations.get(key, 0.0) or 0.0)
    return max(0.0, min(1.0, value))


def _int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0
