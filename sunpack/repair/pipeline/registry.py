import importlib
import pkgutil
from typing import Dict

from sunpack.repair.pipeline.module import RepairModule


REMOVED_ZIP_COARSE_MODULES = {
    "zip_fix_boundary",
    "zip_fix_pointers",
    "zip_fix_zip64",
    "zip_rebuild",
    "zip_salvage",
    "zip_resolve_conflicts",
}


class RepairModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, RepairModule] = {}

    def register(self, module: RepairModule):
        name = module.spec.name
        if name in REMOVED_ZIP_COARSE_MODULES:
            raise ValueError(
                f"ZIP repair module {name!r} has been removed. "
                "Register one atomic ZIP module instead."
            )
        self._modules[name] = module

    def get(self, name: str) -> RepairModule | None:
        return self._modules.get(name)

    def all(self) -> dict[str, RepairModule]:
        return dict(self._modules)


_global_registry = RepairModuleRegistry()
_discovered = False


def register_repair_module(module: RepairModule):
    _global_registry.register(module)
    return module


def get_repair_module_registry() -> RepairModuleRegistry:
    return _global_registry


def discover_repair_modules():
    global _discovered
    if _discovered:
        return

    package = importlib.import_module("sunpack.repair.pipeline.modules")
    for module_info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        importlib.import_module(module_info.name)

    _discovered = True
