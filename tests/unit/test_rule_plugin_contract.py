import pytest

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.rules.registry import register_rule
from tests.helpers.detection_config import with_detection_pipeline


@register_rule(name="schema_contract_test", layer="scoring")
class SchemaContractTestRule(RuleBase):
    required_facts = set()
    config_schema = {
        "score": {"type": "int", "required": True, "default": 1, "description": "test score"},
        "labels": {"type": "list[str]", "required": False, "default": [], "description": "test labels"},
    }

    def evaluate(self, facts, config):
        return RuleEffect.add_score(config["score"], "schema contract")


def _config(rule):
    return with_detection_pipeline(scoring=[rule])


def test_rule_config_schema_accepts_declared_fields():
    manager = DetectionScheduler(_config({"name": "schema_contract_test", "enabled": True, "score": 1, "labels": ["x"]}))
    decision = manager.evaluate(FactBag())

    assert decision.total_score == 1


def test_rule_config_schema_rejects_unknown_fields():
    manager = DetectionScheduler(_config({"name": "schema_contract_test", "enabled": True, "score": 1, "oops": True}))

    with pytest.raises(ValueError, match="Unknown config field"):
        manager.evaluate(FactBag())


def test_rule_config_schema_rejects_missing_required_fields():
    manager = DetectionScheduler(_config({"name": "schema_contract_test", "enabled": True}))

    with pytest.raises(ValueError, match="Missing required config field"):
        manager.evaluate(FactBag())


def test_rule_config_schema_rejects_wrong_type():
    manager = DetectionScheduler(_config({"name": "schema_contract_test", "enabled": True, "score": "1"}))

    with pytest.raises(ValueError, match="Invalid type"):
        manager.evaluate(FactBag())
