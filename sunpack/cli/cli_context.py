from dataclasses import dataclass, field
from types import ModuleType

from sunpack.cli.cli_reporter import CliReporter
from sunpack.config.cli_settings import DEFAULT_CLI_LANG
from sunpack.i18n import I18nContext


@dataclass
class CliContext:
    language: str = DEFAULT_CLI_LANG
    reporter: CliReporter | None = None
    commands: dict[str, ModuleType] | None = None
    i18n: I18nContext = field(init=False)

    def __post_init__(self) -> None:
        self.i18n = I18nContext(self.language)
        self.language = self.i18n.language

    def t(self, key: str, **params) -> str:
        return self.i18n.t(key, **params)
