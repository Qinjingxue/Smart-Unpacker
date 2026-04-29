import importlib
import pkgutil
from typing import Dict

from packrelic.analysis.structure_pipeline.module import AnalysisModule


class AnalysisModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, AnalysisModule] = {}

    def register(self, module: AnalysisModule):
        self._modules[module.spec.name] = module

    def get(self, name: str) -> AnalysisModule | None:
        return self._modules.get(name)

    def all(self) -> dict[str, AnalysisModule]:
        return dict(self._modules)


_global_registry = AnalysisModuleRegistry()
_discovered = False


def register_analysis_module(module: AnalysisModule):
    _global_registry.register(module)
    return module


def get_analysis_module_registry() -> AnalysisModuleRegistry:
    return _global_registry


def discover_analysis_modules():
    global _discovered
    if _discovered:
        return

    package = importlib.import_module("packrelic.analysis.structure_pipeline.modules")
    for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        importlib.import_module(module_info.name)

    _discovered = True
