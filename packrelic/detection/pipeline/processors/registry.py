import importlib
import pkgutil
from dataclasses import dataclass
from typing import Any, Callable

from packrelic.detection.pipeline.facts.schema import get_fact_schema, register_fact_schema
from packrelic.detection.pipeline.processors.context import FactProcessorContext


FactProcessorFunc = Callable[[FactProcessorContext], Any]


@dataclass(frozen=True)
class ProcessorSpec:
    name: str
    input_facts: tuple[str, ...]
    output_facts: tuple[str, ...]
    processor: FactProcessorFunc


class ProcessorRegistry:
    def __init__(self):
        self._processors: dict[str, ProcessorSpec] = {}
        self._output_index: dict[str, str] = {}

    def register(
        self,
        name: str,
        input_facts: tuple[str, ...],
        output_facts: tuple[str, ...],
        processor: FactProcessorFunc,
        schemas: dict[str, dict[str, Any]] | None = None,
    ):
        spec = ProcessorSpec(
            name=name,
            input_facts=tuple(input_facts),
            output_facts=tuple(output_facts),
            processor=processor,
        )
        self._processors[name] = spec
        for fact_name in output_facts:
            self._output_index[fact_name] = name
            schema = dict(get_fact_schema(fact_name) or {})
            schema.update((schemas or {}).get(fact_name, {}))
            schema.setdefault("producer", f"processors.{name}")
            if "type" not in schema:
                raise ValueError(f"Processor output {fact_name} must declare schema type")
            if "description" not in schema:
                raise ValueError(f"Processor output {fact_name} must declare schema description")
            register_fact_schema(fact_name, schema)

    def get_by_output(self, fact_name: str) -> ProcessorSpec | None:
        processor_name = self._output_index.get(fact_name)
        if not processor_name:
            return None
        return self._processors.get(processor_name)

    def all(self) -> dict[str, ProcessorSpec]:
        return dict(self._processors)


_global_registry = ProcessorRegistry()
_discovered = False


def register_processor(
    name: str,
    *,
    input_facts: set[str] | list[str] | tuple[str, ...],
    output_facts: set[str] | list[str] | tuple[str, ...],
    schemas: dict[str, dict[str, Any]] | None = None,
):
    def decorator(func: FactProcessorFunc):
        _global_registry.register(
            name,
            tuple(input_facts),
            tuple(output_facts),
            func,
            schemas=schemas,
        )
        return func
    return decorator


def get_processor_registry() -> ProcessorRegistry:
    return _global_registry


def discover_processors():
    global _discovered
    if _discovered:
        return

    package = importlib.import_module("packrelic.detection.pipeline.processors.modules")
    for module_info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        importlib.import_module(module_info.name)

    _discovered = True
