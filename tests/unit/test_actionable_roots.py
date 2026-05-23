from repair_training.build_actionable_diagnosis_rows import annotate_rows_with_actionable_roots
from repair_training.core.diagnosis_gnn.actionable_roots import (
    actionable_roots_for_module,
    modules_for_root,
    unmapped_zip_modules,
)
from sunpack.repair.config import DEFAULT_REPAIR_CONFIG


def test_actionable_roots_narrow_module_roots_by_injected_roots():
    roots = actionable_roots_for_module(
        "zip_fix_local_header_fields",
        ["local_header.signature", "local_header.method", "eocd.cd_size"],
    )

    assert roots == ["local_header.signature", "compression_method"]


def test_actionable_root_mapping_covers_default_zip_policy_modules():
    names = [
        str(item.get("name") or "")
        for item in DEFAULT_REPAIR_CONFIG["modules"]
        if str(item.get("name") or "").startswith("zip_")
        or str(item.get("name") or "") in {"archive_carrier_crop_deep_recovery", "archive_nested_payload_salvage"}
    ]

    assert unmapped_zip_modules(names) == []


def test_modules_for_root_can_recover_first_step_module_candidates():
    assert "zip_fix_eocd_record" in modules_for_root("eocd.cd_size")
    assert "zip_fix_local_header_fields" in modules_for_root("compression_method")
    assert "archive_carrier_crop_deep_recovery" in modules_for_root("sfx_prefix.bytes")


def test_annotate_rows_with_actionable_roots_from_best_module_q():
    rows = [{
        "sample_id": "sample-a",
        "format": "zip",
        "damage_analysis_target": {
            "damage_labels": [
                "field:eocd.cd_size",
                "field:local_header.signature",
                "field:local_header.method",
            ]
        },
    }]
    transitions = [{
        "sample_id": "sample-a:step:1",
        "step_index": 1,
        "source": {"row_index": 0, "sample_id": "sample-a"},
        "available_actions": [
            {"action_type": "module", "module_name": "zip_fix_eocd_record", "action_q_value": 0.9},
            {"action_type": "module", "module_name": "zip_fix_local_header_fields", "action_q_value": 0.4},
            {"action_type": "stop", "action_id": "stop", "action_q_value": 0.1},
        ],
    }]

    annotated, summary = annotate_rows_with_actionable_roots(rows, transitions)

    assert annotated[0]["actionable_root_labels"] == ["eocd.cd_size"]
    assert annotated[0]["actionable_label_metadata"]["best_module"] == "zip_fix_eocd_record"
    assert summary["actionable_covered_rows"] == 1
