from dataclasses import dataclass
from typing import Any

from sunpack.i18n.catalog import CATALOG

DEFAULT_LANGUAGE = "en"


def normalize_language(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return "zh" if normalized == "zh" else DEFAULT_LANGUAGE


@dataclass(frozen=True)
class I18nContext:
    language: str = DEFAULT_LANGUAGE

    def __post_init__(self) -> None:
        object.__setattr__(self, "language", normalize_language(self.language))

    def t(self, key: str, **params: Any) -> str:
        text = CATALOG.get(self.language, {}).get(key)
        if text is None:
            text = CATALOG[DEFAULT_LANGUAGE].get(key, key)
        return text.format(**params) if params else text

    def format_duration(self, seconds: float) -> str:
        total_seconds = int(max(0.0, seconds))
        minutes, secs = divmod(total_seconds, 60)
        if minutes:
            return self.t("duration.minutes_seconds", minutes=minutes, seconds=secs)
        return self.t("duration.seconds", seconds=secs)


def validate_catalog() -> None:
    base_keys = set(CATALOG[DEFAULT_LANGUAGE])
    for language, texts in CATALOG.items():
        missing = sorted(base_keys - set(texts))
        extra = sorted(set(texts) - base_keys)
        if missing or extra:
            raise ValueError(f"Catalog key mismatch for {language}: missing={missing} extra={extra}")
