from sunpack_native import flatten_single_branch_directories as _native_flatten_single_branch_directories
from sunpack.i18n import I18nContext


class DirectoryFlattener:
    def __init__(self, language: str = "en"):
        self.i18n = I18nContext(language)

    def flatten_dirs(self, base: str):
        print(self.i18n.t("cleanup.flatten"))
        result = _native_flatten_single_branch_directories(str(base))
        if isinstance(result, dict):
            for error in result.get("errors") or []:
                print(self.i18n.t("cleanup.flatten_failed", error=str(error)))
        return result
