from __future__ import annotations

from sunpack.verification.pipeline import _decision_hint
from sunpack.verification.result import (
    ASSESSMENT_COMPLETE,
    DECISION_REPAIR,
    SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
)


def test_payload_damaged_complete_assessment_still_enters_repair():
    assert _decision_hint(
        assessment_status=ASSESSMENT_COMPLETE,
        source_integrity=SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
        completeness=1.0,
        recoverable_upper_bound=0.99,
        decision_hints=[],
        complete_accept_threshold=0.999,
        partial_accept_threshold=0.25,
    ) == DECISION_REPAIR
