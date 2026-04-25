import importlib
import pkgutil
from typing import Dict, Type
from smart_unpacker.detection.pipeline.rules.base import RuleBase

class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, Dict[str, Type[RuleBase]]] = {
            "hard_stop": {},
            "scoring": {},
            "confirmation": {},
        }

    def register(self, layer: str, name: str, rule_cls: Type[RuleBase]):
        if layer not in self._rules:
            raise ValueError(f"Unknown layer: {layer}")
        self._rules[layer][name] = rule_cls

    def get_rule(self, layer: str, name: str) -> Type[RuleBase]:
        return self._rules.get(layer, {}).get(name)

    def get_all_rules(self, layer: str) -> Dict[str, Type[RuleBase]]:
        return self._rules.get(layer, {})

_global_rule_registry = RuleRegistry()
_discovered = False

def register_rule(name: str, layer: str):
    def decorator(cls: Type[RuleBase]):
        _global_rule_registry.register(layer, name, cls)
        return cls
    return decorator

def get_rule_registry() -> RuleRegistry:
    return _global_rule_registry

def discover_rules():
    global _discovered
    if _discovered:
        return

    for package_name in (
        "smart_unpacker.detection.pipeline.rules.hard_stop",
        "smart_unpacker.detection.pipeline.rules.scoring",
        "smart_unpacker.detection.pipeline.rules.confirmation",
    ):
        package = importlib.import_module(package_name)
        for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
            importlib.import_module(module_info.name)

    _discovered = True
