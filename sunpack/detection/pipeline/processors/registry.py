from dataclasses import dataclass
from typing import Any, Callable

from sunpack.detection.pipeline.facts.schema import get_fact_schema, register_fact_schema
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.support.module_discovery import import_static_modules

_PROCESSOR_MODULES = (
    "sunpack.detection.pipeline.processors.modules.embedded_payload.embedded_archive",
    "sunpack.detection.pipeline.processors.modules.embedded_payload.executable_carrier",
    "sunpack.detection.pipeline.processors.modules.embedded_payload.pe_overlay",
    "sunpack.detection.pipeline.processors.modules.format_structure.compression_stream",
    "sunpack.detection.pipeline.processors.modules.format_structure.rar",
    "sunpack.detection.pipeline.processors.modules.format_structure.seven_zip",
    "sunpack.detection.pipeline.processors.modules.format_structure.tar_header",
    "sunpack.detection.pipeline.processors.modules.format_structure.zip_directory_consistency",
    "sunpack.detection.pipeline.processors.modules.format_structure.zip_eocd",
    "sunpack.detection.pipeline.processors.modules.format_structure.zip_local_header",
    "sunpack.detection.pipeline.processors.modules.format_structure.zip_structure_graph",
)


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
    import_static_modules(_PROCESSOR_MODULES)
