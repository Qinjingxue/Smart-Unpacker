from typing import Any

from sunpack.detection.pipeline.facts.provider import FactProvider
from sunpack.detection.pipeline.facts.schema import matches_schema_type
from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import ProcessorRegistry, get_processor_registry


class ProcessingCoordinator:
    def __init__(
        self,
        provider: FactProvider,
        config: dict[str, Any] | None = None,
        fact_configs: dict[str, dict[str, Any]] | None = None,
        registry: ProcessorRegistry | None = None,
        enabled_processors: set[str] | None = None,
    ):
        self.provider = provider
        self.config = config or {}
        self.fact_configs = fact_configs or {}
        self.registry = registry or get_processor_registry()
        self.enabled_processors = enabled_processors

    def ensure_facts(self, fact_bag: FactBag, fact_names: set[str]):
        for fact_name in fact_names:
            self.ensure_fact(fact_bag, fact_name, stack=[])

    def ensure_fact(self, fact_bag: FactBag, fact_name: str, stack: list[str]):
        if fact_bag.has(fact_name) or fact_bag.is_missing(fact_name):
            return fact_bag.get(fact_name)

        processor = self.registry.get_by_output(fact_name)
        if processor is None:
            return self.provider.fill_fact(fact_bag, fact_name)
        if self.enabled_processors is not None and processor.name not in self.enabled_processors:
            fact_bag.mark_error(fact_name, f"Processor disabled: {processor.name}")
            return None

        if fact_name in stack:
            cycle = " -> ".join(stack + [fact_name])
            fact_bag.mark_error(fact_name, f"Processor dependency cycle: {cycle}")
            return None

        dependency_stack = stack + [fact_name]
        for input_fact in processor.input_facts:
            self._inherit_fact_config(input_fact, fact_name)
            self.ensure_fact(fact_bag, input_fact, dependency_stack)
            if fact_bag.is_missing(input_fact) and not fact_bag.has(input_fact):
                dependency_error = fact_bag.get_error(input_fact)
                reason = f"Required processor input failed: {input_fact}"
                if dependency_error:
                    reason = f"{reason} ({dependency_error})"
                fact_bag.mark_error(fact_name, reason)
                return None

        context = FactProcessorContext(
            fact_bag=fact_bag,
            output_fact=fact_name,
            config=self.config,
            fact_config=self.fact_configs.get(fact_name, {}),
            scan_session=self.provider.scan_session,
        )
        try:
            value = processor.processor(context)
        except Exception as exc:
            fact_bag.mark_error(fact_name, f"{type(exc).__name__}: {exc}")
            return None

        schema = self.provider.registry.get_schema(fact_name) or {}
        expected_type = schema.get("type")
        if not matches_schema_type(value, expected_type):
            fact_bag.mark_error(
                fact_name,
                f"Processor returned {type(value).__name__}, expected {expected_type}",
            )
            return None
        fact_bag.set(fact_name, value)
        return value

    def _inherit_fact_config(self, fact_name: str, parent_fact_name: str):
        parent_config = self.fact_configs.get(parent_fact_name)
        if parent_config is None:
            return
        inherited = dict(parent_config)
        inherited.update(self.fact_configs.get(fact_name, {}))
        self.fact_configs[fact_name] = inherited
