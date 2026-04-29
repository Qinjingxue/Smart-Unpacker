from typing import List, Dict, Any
from dataclasses import dataclass

from sunpack.detection import DetectionScheduler

@dataclass
class InspectResult:
    path: str
    should_extract: bool
    score: int
    stop_reason: str
    matched_rules: List[str]
    detected_ext: str
    split_role: str
    scene_type: str
    fact_bag: object
    decision: str
    decision_stage: str
    discarded_at: str
    deciding_rule: str
    score_breakdown: list
    confirmation: dict

class InspectOrchestrator:
    def __init__(self, config: Dict[str, Any]):
        self.detector = DetectionScheduler(config)

    def inspect(self, paths: List[str]) -> List[InspectResult]:
        results = []

        for detection in self.detector.detect_targets(paths):
            bag = detection.fact_bag
            file_path_str = bag.get("file.path")
            if not file_path_str:
                continue
            split_role = bag.get("file.split_role") or ""

            decision = detection.decision

            scene_ctx = bag.get("scene.context", {})
            scene_type = scene_ctx.get("scene_type", "generic") if isinstance(scene_ctx, dict) else "generic"

            results.append(InspectResult(
                path=file_path_str,
                should_extract=decision.should_extract,
                score=decision.total_score,
                stop_reason=decision.stop_reason or "",
                matched_rules=decision.matched_rules,
                detected_ext=bag.get("file.detected_ext", ""),
                split_role=split_role or "",
                scene_type=scene_type,
                fact_bag=bag,
                decision=decision.decision,
                decision_stage=decision.decision_stage,
                discarded_at=decision.discarded_at or "",
                deciding_rule=decision.deciding_rule or "",
                score_breakdown=list(decision.score_breakdown or []),
                confirmation=dict(decision.confirmation or {}),
            ))
                
        return results
