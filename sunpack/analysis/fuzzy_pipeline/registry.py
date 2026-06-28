from typing import Dict

from sunpack.analysis.fuzzy_pipeline.module import FuzzyAnalysisModule
from sunpack.support.module_discovery import discover_package_modules


class FuzzyAnalysisModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, FuzzyAnalysisModule] = {}

    def register(self, module: FuzzyAnalysisModule):
        self._modules[module.spec.name] = module

    def get(self, name: str) -> FuzzyAnalysisModule | None:
        return self._modules.get(name)

    def all(self) -> dict[str, FuzzyAnalysisModule]:
        return dict(self._modules)


_global_registry = FuzzyAnalysisModuleRegistry()


def register_fuzzy_analysis_module(module: FuzzyAnalysisModule):
    _global_registry.register(module)
    return module


def get_fuzzy_analysis_module_registry() -> FuzzyAnalysisModuleRegistry:
    return _global_registry


def discover_fuzzy_analysis_modules():
    discover_package_modules("sunpack.analysis.fuzzy_pipeline.modules")
