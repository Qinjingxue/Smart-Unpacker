import pytest

from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.facts.registry import register_fact
from smart_unpacker.detection.pipeline.facts.schema import get_fact_schema
from smart_unpacker.contracts.detection import FactBag


@register_fact(
    "contract.good_fact",
    type="str",
    description="A fact used to test collector plugin contracts.",
)
def collect_contract_good_fact(base_path: str) -> str:
    return "ok"


@register_fact(
    "contract.bad_type_fact",
    type="int",
    description="A fact that intentionally returns the wrong type.",
)
def collect_contract_bad_type_fact(base_path: str):
    return "not an int"


@register_fact(
    "contract.error_fact",
    type="str",
    description="A fact that intentionally raises.",
)
def collect_contract_error_fact(base_path: str):
    raise RuntimeError("boom")


@register_fact(
    "contract.context_fact",
    type="dict",
    description="A fact that verifies context-aware collector inputs.",
    context=True,
)
def collect_contract_context_fact(context):
    return {
        "base_path": context.base_path,
        "fact_name": context.fact_name,
        "global_value": context.config.get("global_value"),
        "fact_value": context.fact_config.get("fact_value"),
        "has_seed": context.fact_bag.has("seed"),
    }


def test_fact_collector_registers_schema():
    schema = get_fact_schema("contract.good_fact")

    assert schema["type"] == "str"
    assert schema["description"]
    assert schema["producer"] == __name__


def test_fact_provider_accepts_schema_matching_value():
    bag = FactBag()
    value = FactProvider("unused").fill_fact(bag, "contract.good_fact")

    assert value == "ok"
    assert bag.get("contract.good_fact") == "ok"
    assert bag.get_error("contract.good_fact") is None


def test_fact_provider_records_type_errors():
    bag = FactBag()
    value = FactProvider("unused").fill_fact(bag, "contract.bad_type_fact")

    assert value is None
    assert bag.is_missing("contract.bad_type_fact")
    assert "expected int" in bag.get_error("contract.bad_type_fact")


def test_fact_provider_records_collector_exceptions():
    bag = FactBag()
    value = FactProvider("unused").fill_fact(bag, "contract.error_fact")

    assert value is None
    assert bag.is_missing("contract.error_fact")
    assert "RuntimeError: boom" == bag.get_error("contract.error_fact")


def test_fact_collector_requires_schema():
    with pytest.raises(ValueError, match="must declare schema type"):
        register_fact("contract.no_schema")(lambda base_path: None)


def test_fact_provider_passes_context_to_context_collectors():
    bag = FactBag()
    bag.set("seed", True)
    value = FactProvider(
        "ctx-path",
        config={"global_value": "root"},
        fact_configs={"contract.context_fact": {"fact_value": "local"}},
    ).fill_fact(bag, "contract.context_fact")

    assert value == {
        "base_path": "ctx-path",
        "fact_name": "contract.context_fact",
        "global_value": "root",
        "fact_value": "local",
        "has_seed": True,
    }
