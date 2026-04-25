from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.facts.registry import register_fact
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.detection.pipeline.processors.runner import ProcessingCoordinator


@register_fact(
    "processor_contract.dependency_fact",
    type="str",
    description="A basic fact used by processor contract tests.",
    context=True,
)
def collect_processor_contract_dependency_fact(context):
    context.fact_bag.set("processor_contract.order", ["dependency"])
    return context.fact_config.get("fact_value", "dependency")


@register_processor(
    "processor_contract.aggregate",
    input_facts={"processor_contract.dependency_fact"},
    output_facts={"processor_contract.aggregate_fact"},
    schemas={
        "processor_contract.aggregate_fact": {
            "type": "dict",
            "description": "A derived fact produced by a processor contract test.",
        },
    },
)
def process_processor_contract_aggregate(context):
    order = list(context.fact_bag.get("processor_contract.order", []))
    order.append("aggregate")
    context.fact_bag.set("processor_contract.order", order)
    return {
        "dependency": context.fact_bag.get("processor_contract.dependency_fact"),
        "fact_value": context.fact_config.get("fact_value"),
    }


@register_processor(
    "processor_contract.cycle_a",
    input_facts={"processor_contract.cycle_b"},
    output_facts={"processor_contract.cycle_a"},
    schemas={
        "processor_contract.cycle_a": {
            "type": "str",
            "description": "A cyclic processor output.",
        },
    },
)
def process_processor_contract_cycle_a(context):
    return "a"


@register_processor(
    "processor_contract.cycle_b",
    input_facts={"processor_contract.cycle_a"},
    output_facts={"processor_contract.cycle_b"},
    schemas={
        "processor_contract.cycle_b": {
            "type": "str",
            "description": "A cyclic processor output.",
        },
    },
)
def process_processor_contract_cycle_b(context):
    return "b"


def test_processing_coordinator_collects_inputs_before_processor():
    bag = FactBag()
    provider = FactProvider(
        "ctx-path",
        fact_configs={"processor_contract.aggregate_fact": {"fact_value": "inherited"}},
    )
    coordinator = ProcessingCoordinator(provider, fact_configs=provider.fact_configs)

    value = coordinator.ensure_fact(bag, "processor_contract.aggregate_fact", stack=[])

    assert value == {"dependency": "inherited", "fact_value": "inherited"}
    assert bag.get("processor_contract.order") == ["dependency", "aggregate"]


def test_processing_coordinator_records_dependency_cycles():
    bag = FactBag()
    provider = FactProvider("unused")
    coordinator = ProcessingCoordinator(provider)

    value = coordinator.ensure_fact(bag, "processor_contract.cycle_a", stack=[])

    assert value is None
    assert bag.is_missing("processor_contract.cycle_a")
    errors = " ".join(str(error) for error in bag.get_errors().values())
    assert "Processor dependency cycle" in errors
