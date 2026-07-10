from sunpack.repair.pipeline.module import RepairModule
from sunpack.support.module_discovery import discover_package_modules
from sunpack.support.registry import NamedRegistry


class RepairModuleRegistry(NamedRegistry[RepairModule]):
    def __init__(self):
        super().__init__()

    def register(self, module: RepairModule):
        self.register_named(module.spec.name, module)

    def get(self, name: str) -> RepairModule | None:
        return self.get_named(name)

    def all(self) -> dict[str, RepairModule]:
        return self.all_named()


_global_registry = RepairModuleRegistry()


def register_repair_module(module: RepairModule):
    _global_registry.register(module)
    return module


def get_repair_module_registry() -> RepairModuleRegistry:
    return _global_registry


def discover_repair_modules():
    discover_package_modules("sunpack.repair.pipeline.modules", recursive=True)
