import json
from pathlib import Path


def load_scene_rules() -> list[dict]:
    config_path = Path(__file__).resolve().parents[2] / "sunpack_advanced_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for item in config["filesystem"]["scan_filters"]:
        if isinstance(item, dict) and item.get("name") == "scene_semantics":
            return item.get("scene_rules") or []
    return []


RECOMMENDED_SCENE_RULES_PAYLOAD = load_scene_rules()
