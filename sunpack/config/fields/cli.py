from sunpack.config.schema import ConfigField
from sunpack.i18n import normalize_language


DEFAULT_CLI_LANGUAGE = "en"


CONFIG_FIELDS = (
    ConfigField(
        path=("cli", "language"),
        default=DEFAULT_CLI_LANGUAGE,
        normalize=normalize_language,
        owner=__name__,
    ),
)
