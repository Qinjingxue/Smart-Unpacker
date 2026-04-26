from types import SimpleNamespace

from smart_unpacker.verification.methods import _output_stats


def test_output_stats_for_evidence_reuses_result(monkeypatch):
    calls = []
    expected = _output_stats.OutputStats(exists=True, is_dir=True, file_count=1)

    def collect(output_dir):
        calls.append(output_dir)
        return expected

    evidence = SimpleNamespace(output_dir="out")
    monkeypatch.setattr(_output_stats, "collect_output_stats", collect)

    assert _output_stats.output_stats_for_evidence(evidence) is expected
    assert _output_stats.output_stats_for_evidence(evidence) is expected
    assert calls == ["out"]
