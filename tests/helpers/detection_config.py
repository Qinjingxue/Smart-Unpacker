def with_detection_pipeline(
    config: dict | None = None,
    *,
    precheck: list[dict] | None = None,
    scoring: list[dict] | None = None,
    confirmation: list[dict] | None = None,
) -> dict:
    result = dict(config or {})
    result.setdefault("verification", {})
    scan_filters = []
    remaining_precheck = []
    for rule in precheck or []:
        if isinstance(rule, dict) and rule.get("name") in {"blacklist", "size_range"}:
            scan_filters.append(dict(rule))
        else:
            remaining_precheck.append(rule)
    if scan_filters:
        filesystem = dict(result.get("filesystem") or {})
        filesystem["scan_filters"] = scan_filters
        result["filesystem"] = filesystem
    result["detection"] = {
        "rule_pipeline": {
            "precheck": remaining_precheck,
            "scoring": [dict(rule) for rule in (scoring or [])],
            "confirmation": confirmation or [],
        }
    }
    return result
