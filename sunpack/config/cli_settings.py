from typing import Any

from sunpack.config.paths import get_config_path
from sunpack.support.json_format import load_json_file


DEFAULT_CLI_LANG = "en"


def normalize_cli_language(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return "zh" if normalized == "zh" else DEFAULT_CLI_LANG


def load_cli_language_from_config() -> str:
    config_path = get_config_path()
    if not config_path.exists():
        return DEFAULT_CLI_LANG
    try:
        payload = load_json_file(config_path)
    except Exception:
        return DEFAULT_CLI_LANG
    cli_settings = payload.get("cli") if isinstance(payload, dict) else None
    if not isinstance(cli_settings, dict):
        return DEFAULT_CLI_LANG
    return normalize_cli_language(cli_settings.get("language"))
