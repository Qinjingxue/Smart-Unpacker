from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class RuleEffect:
    decision: str  # "reject", "accept", "pass", "score", "require"
    reason: Optional[str] = None
    score: int = 0
    required_facts: set[str] = field(default_factory=set)

    @classmethod
    def reject(cls, reason: str) -> "RuleEffect":
        return cls(decision="reject", reason=reason)

    @classmethod
    def accept(cls, reason: str) -> "RuleEffect":
        return cls(decision="accept", reason=reason)

    @classmethod
    def pass_(cls) -> "RuleEffect":
        return cls(decision="pass")

    @classmethod
    def add_score(cls, score: int, reason: str) -> "RuleEffect":
        return cls(decision="score", score=score, reason=reason)

    @classmethod
    def require_facts(cls, fact_names: set[str]) -> "RuleEffect":
        return cls(decision="require", required_facts=set(fact_names))

@dataclass
class RuleDecision:
    should_extract: bool
    total_score: int
    matched_rules: List[str]
    stop_reason: Optional[str] = None
    decision: str = "not_archive"
    decision_stage: str = ""
    discarded_at: Optional[str] = None
    deciding_rule: Optional[str] = None
    score_breakdown: List[Dict[str, Any]] = field(default_factory=list)
