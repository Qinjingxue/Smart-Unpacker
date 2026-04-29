import importlib
import pkgutil
from types import ModuleType

from packrelic.app import commands


def discover_command_modules() -> list[ModuleType]:
    modules: list[ModuleType] = []
    seen: set[str] = set()
    for module_info in pkgutil.iter_modules(commands.__path__, commands.__name__ + "."):
        module = importlib.import_module(module_info.name)
        command = getattr(module, "COMMAND", None)
        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"CLI command module {module_info.name} must declare COMMAND")
        if command in seen:
            raise ValueError(f"Duplicate CLI command name: {command}")
        if not callable(getattr(module, "register", None)):
            raise ValueError(f"CLI command module {module_info.name} must declare register(subparsers, ctx)")
        if not callable(getattr(module, "handle", None)):
            raise ValueError(f"CLI command module {module_info.name} must declare handle(args, ctx)")
        seen.add(command)
        modules.append(module)
    modules.sort(key=lambda module: (getattr(module, "ORDER", 1000), getattr(module, "COMMAND")))
    return modules


def command_map(modules: list[ModuleType] | None = None) -> dict[str, ModuleType]:
    return {module.COMMAND: module for module in (modules or discover_command_modules())}

