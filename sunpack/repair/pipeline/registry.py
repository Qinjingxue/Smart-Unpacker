from typing import Dict

from sunpack.repair.pipeline.module import RepairModule
from sunpack.support.module_discovery import discover_package_modules


class RepairModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, RepairModule] = {}

    def register(self, module: RepairModule):
        name = module.spec.name
        self._modules[name] = module

    def get(self, name: str) -> RepairModule | None:
        return self._modules.get(name)

    def all(self) -> dict[str, RepairModule]:
        return dict(self._modules)


_global_registry = RepairModuleRegistry()


def register_repair_module(module: RepairModule):
    _global_registry.register(module)
    return module


def get_repair_module_registry() -> RepairModuleRegistry:
    return _global_registry


def discover_repair_modules():
    discover_package_modules("sunpack.repair.pipeline.modules", recursive=True)
