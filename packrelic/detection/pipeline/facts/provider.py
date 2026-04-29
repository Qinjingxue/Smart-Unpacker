from typing import Any
from packrelic.detection.pipeline.facts.context import FactCollectorContext
from packrelic.contracts.detection import FactBag
from packrelic.detection.pipeline.facts.registry import get_registry
from packrelic.detection.pipeline.facts.schema import matches_schema_type
 
class FactProvider:
    def __init__(
        self,
        base_path: str,
        config: dict[str, Any] | None = None,
        fact_configs: dict[str, dict[str, Any]] | None = None,
        enabled_fact_modules: set[str] | None = None,
        scan_session: Any | None = None,
    ):
        self.base_path = base_path
        self.registry = get_registry()
        self.config = config or {}
        self.fact_configs = fact_configs or {}
        self.enabled_fact_modules = enabled_fact_modules
        self.scan_session = scan_session

    def _collect(self, collector, fact_bag: FactBag, fact_name: str) -> Any:
        if getattr(collector, "_fact_accepts_context", False):
            context = FactCollectorContext(
                base_path=self.base_path,
                fact_bag=fact_bag,
                fact_name=fact_name,
                config=self.config,
                fact_config=self.fact_configs.get(fact_name, {}),
                scan_session=self.scan_session,
            )
            return collector(context)
        return collector(self.base_path)

    def fill_fact(self, fact_bag: FactBag, fact_name: str) -> Any:
        if fact_bag.has(fact_name):
            return fact_bag.get(fact_name)

        if fact_bag.is_missing(fact_name):
            return None

        collector = self.registry.get_collector(fact_name)
        if not collector:
            fact_bag.mark_error(fact_name, "No collector registered")
            return None
        if self.enabled_fact_modules is not None:
            module_name = collector.__module__.rsplit(".", 1)[-1]
            if module_name not in self.enabled_fact_modules:
                fact_bag.mark_error(fact_name, f"Fact collector module disabled: {module_name}")
                return None

        try:
            value = self._collect(collector, fact_bag, fact_name)
            schema = self.registry.get_schema(fact_name) or {}
            expected_type = schema.get("type")
            if not matches_schema_type(value, expected_type):
                fact_bag.mark_error(
                    fact_name,
                    f"Collector returned {type(value).__name__}, expected {expected_type}",
                )
                return None
            fact_bag.set(fact_name, value)
            return value
        except Exception as exc:
            fact_bag.mark_error(fact_name, f"{type(exc).__name__}: {exc}")
            return None

    def ensure_facts(self, fact_bag: FactBag, fact_names: set[str]):
        for name in fact_names:
            self.fill_fact(fact_bag, name)
