import json
from pathlib import Path

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import config_fields, get_config_value
from sunpack.detection.pipeline.rules.metadata import discover_rule_metadata


ROOT = Path(__file__).resolve().parents[2]


def _advanced_config() -> dict:
    return json.loads((ROOT / "sunpack_advanced_config.json").read_text(encoding="utf-8"))


def test_registered_config_defaults_are_sourced_from_advanced_config():
    payload = _advanced_config()

    for field in config_fields().values():
        if field.default is None:
            continue
        assert field.default == get_config_value(payload, field.path)


def test_required_detection_rule_fields_are_declared_in_advanced_config():
    payload = _advanced_config()
    configured = {
        item["name"]: item
        for layer in payload["detection"]["rule_pipeline"].values()
        for item in layer
    }

    for name, metadata in discover_rule_metadata().items():
        for field, schema in metadata["config_schema"].items():
            if schema.get("required"):
                assert field in configured[name], f"missing detection rule config: {name}.{field}"


def test_advanced_default_values_are_returned_as_independent_copies():
    first = advanced_config_value(("watch",))
    second = advanced_config_value(("watch",))

    first["roots"].append("changed")

    assert second["roots"] == []
