from typing import Dict, Type
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.support.module_discovery import import_static_modules

_RULE_MODULES = (
    "sunpack.detection.pipeline.rules.precheck.rar_structure_accept",
    "sunpack.detection.pipeline.rules.precheck.seven_zip_structure_accept",
    "sunpack.detection.pipeline.rules.precheck.tar_structure_accept",
    "sunpack.detection.pipeline.rules.precheck.zip_structure_accept",
    "sunpack.detection.pipeline.rules.scoring.archive_container_identity",
    "sunpack.detection.pipeline.rules.scoring.compression_stream_identity",
    "sunpack.detection.pipeline.rules.scoring.embedded_payload_identity",
    "sunpack.detection.pipeline.rules.scoring.extension",
    "sunpack.detection.pipeline.rules.scoring.rar_structure_identity",
    "sunpack.detection.pipeline.rules.scoring.seven_zip_structure_identity",
    "sunpack.detection.pipeline.rules.scoring.structure_evidence_identity",
    "sunpack.detection.pipeline.rules.scoring.tar_structure_identity",
    "sunpack.detection.pipeline.rules.scoring.zip_structure_identity",
    "sunpack.detection.pipeline.rules.confirmation.executable_carrier_veto",
    "sunpack.detection.pipeline.rules.confirmation.archive_identity_consensus",
    "sunpack.detection.pipeline.rules.confirmation.archive_metadata_open",
)

class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, Dict[str, Type[RuleBase]]] = {
            "precheck": {},
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

    import_static_modules(_RULE_MODULES)

    _discovered = True
