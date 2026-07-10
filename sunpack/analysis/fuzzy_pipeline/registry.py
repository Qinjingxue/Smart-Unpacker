from sunpack.analysis.fuzzy_pipeline.module import FuzzyAnalysisModule
from sunpack.support.module_discovery import discover_package_modules
from sunpack.support.registry import NamedRegistry


class FuzzyAnalysisModuleRegistry(NamedRegistry[FuzzyAnalysisModule]):
    def __init__(self):
        super().__init__()

    def register(self, module: FuzzyAnalysisModule):
        self.register_named(module.spec.name, module)

    def get(self, name: str) -> FuzzyAnalysisModule | None:
        return self.get_named(name)

    def all(self) -> dict[str, FuzzyAnalysisModule]:
        return self.all_named()


_global_registry = FuzzyAnalysisModuleRegistry()


def register_fuzzy_analysis_module(module: FuzzyAnalysisModule):
    _global_registry.register(module)
    return module


def get_fuzzy_analysis_module_registry() -> FuzzyAnalysisModuleRegistry:
    return _global_registry


def discover_fuzzy_analysis_modules():
    discover_package_modules("sunpack.analysis.fuzzy_pipeline.modules")
