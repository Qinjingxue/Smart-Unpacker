from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import ConfirmationEffect, RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.rules.registry import register_rule
from tests.helpers.detection_config import with_detection_pipeline


@register_rule(name="pool_blacklist_test", layer="hard_stop")
class PoolBlacklistTestRule(RuleBase):
    required_facts = {"blacklist.fact"}

    def evaluate(self, facts, config):
        if facts.get("file.path") == "drop":
            return RuleEffect.stop("drop requested")
        return RuleEffect.pass_()


@register_rule(name="pool_scene_test", layer="hard_stop")
class PoolSceneTestRule(RuleBase):
    required_facts = {"scene.fact"}

    def evaluate(self, facts, config):
        return RuleEffect.pass_()


@register_rule(name="pool_score_a_test", layer="scoring")
class PoolScoreATestRule(RuleBase):
    required_facts = {"score.a"}

    def evaluate(self, facts, config):
        return RuleEffect.add_score(1, "score a")


@register_rule(name="pool_score_b_test", layer="scoring")
class PoolScoreBTestRule(RuleBase):
    required_facts = {"score.b"}

    def evaluate(self, facts, config):
        return RuleEffect.add_score(2, "score b")


@register_rule(name="pool_confirmation_test", layer="confirmation")
class PoolConfirmationTestRule(RuleBase):
    required_facts = {"confirm.fact"}

    def evaluate(self, facts, config):
        if facts.get("confirm.fact"):
            return ConfirmationEffect.confirm("confirmed")
        return ConfirmationEffect.pass_()


def _bag(path: str) -> FactBag:
    bag = FactBag()
    bag.set("file.path", path)
    return bag


def test_pool_evaluation_filters_by_hard_stop_stage_then_collects_scoring_union(monkeypatch):
    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 3, "maybe_archive_threshold": 1},
    }, hard_stop=[
        {"name": "pool_blacklist_test", "enabled": True},
        {"name": "pool_scene_test", "enabled": True},
    ], scoring=[
        {"name": "pool_score_a_test", "enabled": True},
        {"name": "pool_score_b_test", "enabled": True},
    ])
    manager = DetectionScheduler(config)
    calls = []

    def fake_ensure_pool_facts(fact_bags, required_facts, fact_configs=None):
        calls.append(([bag.get("file.path") for bag in fact_bags], set(required_facts)))
        for bag in fact_bags:
            for fact in required_facts:
                bag.set(fact, True)

    monkeypatch.setattr(manager, "_ensure_pool_facts", fake_ensure_pool_facts)

    drop = _bag("drop")
    keep = _bag("keep")
    decisions = manager.evaluate_pool([drop, keep])

    assert calls == [
        (["drop", "keep"], {"blacklist.fact"}),
        (["keep"], {"scene.fact"}),
        (["keep"], {"score.a", "score.b"}),
    ]
    assert not decisions[drop].should_extract
    assert decisions[drop].matched_rules == ["pool_blacklist_test"]
    assert decisions[drop].decision_stage == "hard_stop"
    assert decisions[drop].discarded_at == "hard_stop"
    assert decisions[drop].deciding_rule == "pool_blacklist_test"
    assert decisions[keep].should_extract
    assert decisions[keep].total_score == 3
    assert decisions[keep].matched_rules == ["pool_score_a_test", "pool_score_b_test"]
    assert decisions[keep].decision_stage == "scoring"
    assert decisions[keep].discarded_at is None
    assert decisions[keep].score_breakdown == [
        {"rule": "pool_score_a_test", "score": 1, "reason": "score a"},
        {"rule": "pool_score_b_test", "score": 2, "reason": "score b"},
    ]


def test_confirmation_runs_only_for_maybe_score_window(monkeypatch):
    config = with_detection_pipeline({
        "thresholds": {
            "archive_score_threshold": 6,
            "maybe_archive_threshold": 3,
        },
    }, scoring=[
        {"name": "pool_score_a_test", "enabled": True},
        {"name": "pool_score_b_test", "enabled": True},
    ], confirmation=[{"name": "pool_confirmation_test", "enabled": True}])
    manager = DetectionScheduler(config)
    calls = []

    def fake_ensure_pool_facts(fact_bags, required_facts, fact_configs=None):
        calls.append(([bag.get("file.path") for bag in fact_bags], set(required_facts)))
        for bag in fact_bags:
            for fact in required_facts:
                bag.set(fact, True)

    monkeypatch.setattr(manager, "_ensure_pool_facts", fake_ensure_pool_facts)

    bag = _bag("maybe")
    decision = manager.evaluate_pool([bag])[bag]

    assert calls == [
        (["maybe"], {"score.a", "score.b"}),
        (["maybe"], {"confirm.fact"}),
    ]
    assert decision.should_extract
    assert decision.decision == "archive"
    assert decision.decision_stage == "confirmation"
    assert decision.discarded_at is None
    assert decision.deciding_rule == "pool_confirmation_test"
    assert decision.confirmation["entered"] is True
    assert decision.confirmation["decision"] == "confirm"
    assert decision.matched_rules == ["pool_score_a_test", "pool_score_b_test", "pool_confirmation_test"]


def test_scoring_threshold_rejection_records_discard_stage(monkeypatch):
    config = with_detection_pipeline({
        "thresholds": {
            "archive_score_threshold": 10,
            "maybe_archive_threshold": 5,
        },
    }, scoring=[{"name": "pool_score_a_test", "enabled": True}])
    manager = DetectionScheduler(config)

    def fake_ensure_pool_facts(fact_bags, required_facts, fact_configs=None):
        for bag in fact_bags:
            for fact in required_facts:
                bag.set(fact, True)

    monkeypatch.setattr(manager, "_ensure_pool_facts", fake_ensure_pool_facts)

    bag = _bag("low")
    decision = manager.evaluate_pool([bag])[bag]

    assert not decision.should_extract
    assert decision.decision == "not_archive"
    assert decision.decision_stage == "scoring"
    assert decision.discarded_at == "scoring_threshold"
    assert decision.score_breakdown == [{"rule": "pool_score_a_test", "score": 1, "reason": "score a"}]
