from typing import Any

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.pipeline.facts.context import BatchFactCollectorContext
from smart_unpacker.detection.pipeline.facts.registry import get_registry
from smart_unpacker.detection.pipeline.facts.schema import matches_schema_type


class BatchFactProvider:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        fact_configs: dict[str, dict[str, Any]] | None = None,
        enabled_fact_modules: set[str] | None = None,
        scan_session: Any | None = None,
    ):
        self.registry = get_registry()
        self.config = config or {}
        self.fact_configs = fact_configs or {}
        self.enabled_fact_modules = enabled_fact_modules
        self.scan_session = scan_session

    def prefill_facts(self, fact_bags: list[FactBag], fact_names: set[str]):
        for fact_name in fact_names:
            self.prefill_fact(fact_bags, fact_name)

    def prefill_fact(self, fact_bags: list[FactBag], fact_name: str):
        collector = self.registry.get_batch_collector(fact_name)
        if collector is None:
            return
        if self.enabled_fact_modules is not None:
            module_name = collector.__module__.rsplit(".", 1)[-1]
            if module_name not in self.enabled_fact_modules:
                return

        pending = [
            bag
            for bag in fact_bags
            if not bag.has(fact_name) and not bag.is_missing(fact_name)
        ]
        if not pending:
            return

        context = BatchFactCollectorContext(
            fact_bags=pending,
            fact_name=fact_name,
            config=self.config,
            fact_configs=self.fact_configs,
            scan_session=self.scan_session,
        )
        try:
            collector(context)
        except Exception as exc:
            for bag in pending:
                if not bag.has(fact_name):
                    bag.mark_error(fact_name, f"{type(exc).__name__}: {exc}")
            return

        schema = self.registry.get_schema(fact_name) or {}
        expected_type = schema.get("type")
        for bag in pending:
            if not bag.has(fact_name):
                continue
            value = bag.get(fact_name)
            if not matches_schema_type(value, expected_type):
                bag.unset(fact_name)
                bag.mark_error(
                    fact_name,
                    f"Batch collector returned {type(value).__name__}, expected {expected_type}",
                )
