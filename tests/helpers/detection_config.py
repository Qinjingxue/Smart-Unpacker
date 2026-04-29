CARRIER_EXTS = [".jpg", ".jpeg", ".png", ".pdf", ".gif", ".webp"]
AMBIGUOUS_RESOURCE_EXTS = [
    ".dat", ".bin", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tga",
    ".mp3", ".wav", ".ogg", ".flac", ".aac",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm",
    ".txt", ".log", ".csv", ".pdf",
]
SEMANTIC_RESOURCE_EXTS = [
    ".dll", ".save", ".py", ".pyc", ".json", ".xml", ".cfg", ".ini", ".sys", ".db",
    ".msi", ".cur", ".ani", ".ttf", ".woff", ".ico", ".pak", ".obb", ".unitypackage",
    ".jar", ".apk", ".ipa", ".epub", ".odt", ".ods", ".odp", ".docx", ".xlsx",
    ".pptx", ".whl", ".xpi", ".war", ".ear", ".aab",
]
LIKELY_RESOURCE_EXTS = [
    ".dat", ".bin", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tga",
    ".mp3", ".wav", ".ogg", ".flac", ".aac",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm",
    ".txt", ".log", ".csv", ".pdf",
]


def with_detection_pipeline(
    config: dict | None = None,
    *,
    precheck: list[dict] | None = None,
    scoring: list[dict] | None = None,
    confirmation: list[dict] | None = None,
) -> dict:
    result = dict(config or {})
    scan_filters = []
    remaining_precheck = []
    uses_scene = False
    scene_filter_config = {
        "name": "scene_semantics",
        "enabled": True,
        "protect_runtime_resources": True,
    }
    for rule in precheck or []:
        if isinstance(rule, dict) and rule.get("name") == "scene_protect":
            uses_scene = True
            if isinstance(rule.get("scene_rules"), list):
                scene_filter_config["scene_rules"] = rule["scene_rules"]
            continue
        if isinstance(rule, dict) and rule.get("name") in {"blacklist", "size_minimum"}:
            scan_filters.append(dict(rule))
        else:
            remaining_precheck.append(rule)
    remaining_scoring = []
    for rule in scoring or []:
        if isinstance(rule, dict) and rule.get("name") == "scene_penalty":
            uses_scene = True
            if isinstance(rule.get("scene_rules"), list):
                scene_filter_config["scene_rules"] = rule["scene_rules"]
            continue
        remaining_scoring.append(rule)
    if uses_scene:
        scan_filters.insert(0, scene_filter_config)
    if scan_filters:
        filesystem = dict(result.get("filesystem") or {})
        filesystem["scan_filters"] = scan_filters
        result["filesystem"] = filesystem
    result["detection"] = {
        "rule_pipeline": {
            "precheck": remaining_precheck,
            "scoring": [_complete_rule(rule) for rule in remaining_scoring],
            "confirmation": confirmation or [],
        }
    }
    return result


def _complete_rule(rule: dict) -> dict:
    result = dict(rule)
    name = result.get("name")
    if name == "embedded_payload_identity":
        result.setdefault("carrier_exts", list(CARRIER_EXTS))
        result.setdefault("ambiguous_resource_exts", list(AMBIGUOUS_RESOURCE_EXTS))
    elif name == "scene_penalty":
        result.setdefault("semantic_resource_exts", list(SEMANTIC_RESOURCE_EXTS))
        result.setdefault("likely_resource_exts", list(LIKELY_RESOURCE_EXTS))
    return result
