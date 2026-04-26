import os
from dataclasses import asdict
from typing import Any

from smart_unpacker.app.cli_constants import EXIT_USAGE
from smart_unpacker.app.cli_types import CliCommandResult, CliPasswordSummary
from smart_unpacker.config.schema import normalize_config_value
from smart_unpacker.config.detection_view import directory_scan_mode, rule_pipeline_config, scan_filter_config
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.passwords import dedupe_passwords, get_builtin_passwords, PasswordStore, read_password_file


def build_effective_config(config: dict) -> dict[str, Any]:
    thresholds = config.get("thresholds", {}) if isinstance(config.get("thresholds"), dict) else {}
    pipeline_config = rule_pipeline_config(config)
    size_rule = scan_filter_config(config, "size_minimum")
    size_minimum = None
    if isinstance(size_rule, dict):
        if "min_inspection_size_bytes" in size_rule:
            size_minimum = size_rule["min_inspection_size_bytes"]
    return {
        "thresholds": {
            "archive_score_threshold": thresholds.get("archive_score_threshold", 6),
            "maybe_archive_threshold": thresholds.get("maybe_archive_threshold", 3),
        },
        "min_inspection_size_bytes": size_minimum,
        "scheduler_profile": config.get("performance", {}).get("scheduler_profile"),
        "scheduler": ExtractionScheduler.scheduler_profile_config(
            config.get("performance", {}).get("scheduler_profile", "auto")
        ),
        "detection": {
            "rule_pipeline": {
                layer: [
                    {"name": rule.get("name"), "enabled": rule.get("enabled", False)}
                    for rule in pipeline_config.get(layer, [])
                    if isinstance(rule, dict)
                ]
                for layer in ("precheck", "scoring", "confirmation")
            }
        },
        "filesystem": {
            "directory_scan_mode": directory_scan_mode(config),
            "scan_filters": [
                {"name": item.get("name"), "enabled": item.get("enabled", False)}
                for item in config.get("filesystem", {}).get("scan_filters", [])
                if isinstance(item, dict)
            ]
        },
    }

def resolve_target_paths(paths: list[str]) -> tuple[list[str], list[str]]:
    target_paths = []
    missing_paths = []
    for raw_path in paths:
        norm_path = os.path.normpath(raw_path)
        if os.path.exists(norm_path):
            target_paths.append(norm_path)
        else:
            missing_paths.append(raw_path)
    return target_paths, missing_paths


def resolve_common_root(paths: list[str]) -> str:
    normalized_paths = [os.path.normpath(path) for path in paths if path]
    if not normalized_paths:
        return os.getcwd()
    try:
        common_root = os.path.commonpath(normalized_paths)
    except ValueError:
        first = normalized_paths[0]
        common_root = first if os.path.isdir(first) else os.path.dirname(first)
    if os.path.isfile(common_root):
        common_root = os.path.dirname(common_root)
    return common_root or os.getcwd()


def collect_cli_passwords(
    args,
    prompt_text: str = "[CLI] Enter passwords, one per line. Submit an empty line to finish.",
    input_prompt: str = "password> ",
) -> list[str]:
    passwords = list(getattr(args, "password", []) or [])
    if getattr(args, "password_file", None):
        passwords.extend(read_password_file(args.password_file))
    if getattr(args, "prompt_passwords", False):
        print(prompt_text, flush=True)
        while True:
            line = input(input_prompt)
            if not line:
                break
            passwords.append(line)
    return dedupe_passwords(passwords)


def build_password_summary(
    user_passwords: list[str],
    use_builtin_passwords: bool,
    recent_passwords: list[str] | None = None,
) -> CliPasswordSummary:
    recent = dedupe_passwords(recent_passwords or [])
    builtin = get_builtin_passwords() if use_builtin_passwords else []
    store = PasswordStore.from_sources(
        cli_passwords=user_passwords,
        recent_passwords=recent,
        builtin_passwords=builtin,
    )
    return CliPasswordSummary(
        user_passwords=store.user_passwords,
        recent_passwords=store.recent_passwords,
        builtin_passwords=store.builtin_passwords,
        combined_passwords=store.candidates(),
        use_builtin_passwords=use_builtin_passwords,
    )


def apply_runtime_config_overrides(config: dict, args) -> dict:
    overrides = {}
    if getattr(args, "recursive_extract", None) is not None:
        overrides["recursive_extract"] = args.recursive_extract
        config["recursive_extract"] = normalize_config_value(("recursive_extract",), args.recursive_extract)
    if getattr(args, "scheduler_profile", None) is not None:
        overrides["scheduler_profile"] = args.scheduler_profile
        performance = config.setdefault("performance", {})
        performance["scheduler_profile"] = args.scheduler_profile
    if getattr(args, "archive_cleanup_mode", None) is not None:
        overrides["archive_cleanup_mode"] = args.archive_cleanup_mode
        config.setdefault("post_extract", {})["archive_cleanup_mode"] = normalize_config_value(
            ("post_extract", "archive_cleanup_mode"),
            args.archive_cleanup_mode,
        )
    if getattr(args, "flatten_single_directory", None) is not None:
        overrides["flatten_single_directory"] = args.flatten_single_directory
        config.setdefault("post_extract", {})["flatten_single_directory"] = args.flatten_single_directory
    return overrides


def result_for_missing(command: str, args, missing_paths: list[str]) -> tuple[int, CliCommandResult]:
    errors = [f"Target not found: {path}" for path in missing_paths]
    return EXIT_USAGE, CliCommandResult(
        command=command,
        inputs={"paths": list(getattr(args, "paths", []) or [])},
        summary={"missing_count": len(missing_paths)},
        errors=errors,
    )


def _fact_dict(res) -> dict:
    facts = getattr(res, "facts", None)
    if isinstance(facts, dict):
        return facts
    bag = getattr(res, "fact_bag", None)
    if bag is not None and hasattr(bag, "to_dict"):
        result = bag.to_dict()
        errors = bag.get_errors() if hasattr(bag, "get_errors") else {}
        if errors:
            result["_fact_errors"] = errors
        return result
    return {}


def _validation_state(facts: dict) -> tuple[bool, bool, bool]:
    validation = facts.get("7z.validation") or {}
    return (
        bool(validation.get("ok")),
        bool(validation.get("skipped")),
        bool(validation.get("encrypted")),
    )


def scan_result_to_item(res) -> dict[str, Any]:
    facts = _fact_dict(res)
    validation_ok, validation_skipped, validation_encrypted = _validation_state(facts)
    main_path = res.main_path
    all_parts = list(res.all_parts or [])
    return {
        "main_path": main_path,
        "all_parts": all_parts,
        "decision": res.decision,
        "score": res.score,
        "scene_role": getattr(res, "scene_type", facts.get("scene.context", {}).get("scene_type") if isinstance(facts.get("scene.context"), dict) else None),
        "detected_ext": res.detected_ext,
        "split_role": getattr(res, "split_role", facts.get("file.split_role")),
        "validation_ok": validation_ok,
        "validation_skipped": validation_skipped,
        "validation_encrypted": validation_encrypted,
        "reasons": list(res.matched_rules or []),
        "facts": facts,
    }


def inspect_result_to_item(res) -> dict[str, Any]:
    facts = _fact_dict(res)
    path_info = facts.get("path") or {}
    size = facts.get("file.size", 0)
    ext = facts.get("file.ext") or path_info.get("ext") or ""
    validation_ok, validation_skipped, validation_encrypted = _validation_state(facts)
    fact_errors = facts.get("_fact_errors") or []
    probe = facts.get("7z.probe") or {}
    return {
        "path": res.path,
        "decision": getattr(res, "decision", "archive" if res.should_extract else "not_archive"),
        "decision_stage": getattr(res, "decision_stage", ""),
        "discarded_at": getattr(res, "discarded_at", "") or None,
        "deciding_rule": getattr(res, "deciding_rule", "") or None,
        "stop_reason": getattr(res, "stop_reason", "") or None,
        "should_extract": res.should_extract,
        "score": res.score,
        "score_breakdown": list(getattr(res, "score_breakdown", []) or []),
        "confirmation": dict(getattr(res, "confirmation", {}) or {}),
        "size": facts.get("file.size", size),
        "ext": ext,
        "detected_ext": res.detected_ext or facts.get("file.detected_ext") or None,
        "container_type": facts.get("file.container_type") or probe.get("type") or "unknown",
        "scene_role": res.scene_type,
        "validation_ok": validation_ok,
        "validation_skipped": validation_skipped,
        "validation_encrypted": validation_encrypted,
        "probe_detected_archive": bool(facts.get("file.probe_detected_archive") or probe.get("is_archive")),
        "probe_offset": int(facts.get("file.probe_offset") or probe.get("offset") or 0),
        "is_split_candidate": bool(res.split_role or facts.get("file.is_split_candidate")),
        "skipped_by_size_limit": bool(res.stop_reason and "size below" in res.stop_reason.lower()),
        "reasons": list(res.matched_rules or []),
        "fact_errors": fact_errors,
    }


def password_summary_item(summary: CliPasswordSummary) -> dict[str, Any]:
    return asdict(summary)
