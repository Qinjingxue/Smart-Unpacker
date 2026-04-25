from typing import Any

from smart_unpacker.detection import validate_detection_contracts


def validate_config_payload(payload: dict) -> dict[str, Any]:
    detection_result = validate_detection_contracts(payload)
    errors = detection_result["errors"]
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": detection_result["warnings"],
        "configured_rules": detection_result["configured_rules"],
        "available_rules": detection_result["available_rules"],
        "registered_facts": detection_result["registered_facts"],
    }
