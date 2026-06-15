import pytest

from sunpack.model_runtime.diagnosis.graph_dispatcher import (
    UnsupportedDiagnosisGraphFormat,
    detect_graph_format,
)


def test_diagnosis_graph_dispatcher_detects_format_priority():
    assert detect_graph_format({"format": "zip", "knowledge_payload": {}}) == "zip"
    assert detect_graph_format({
        "knowledge_payload": {"analysis": {"summary": {"format": "zip"}}}
    }) == "zip"
    assert detect_graph_format({
        "knowledge_payload": {"source": {"input": {"format_hint": "zip"}}}
    }) == "zip"
    assert detect_graph_format({"knowledge_payload": {"format": {"zip": {}}}}) == "zip"
    assert detect_graph_format({
        "knowledge_payload": {"source": {"input": {"entry_path": "a/b/c.zip"}}}
    }) == "zip"


def test_diagnosis_graph_dispatcher_rejects_unknown_and_unsupported():
    assert detect_graph_format({"format": "7z"}) == "7z"

    with pytest.raises(UnsupportedDiagnosisGraphFormat):
        detect_graph_format({"knowledge_payload": {"source": {"input": {"entry_path": "a.bin"}}}})
