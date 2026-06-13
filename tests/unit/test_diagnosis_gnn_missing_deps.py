import importlib.util

import pytest

from repair_training.core.diagnosis_graph.dispatcher import build_diagnosis_graph_sample
from repair_training.core.diagnosis_gnn.tensorize import tensorize_sample


def test_diagnosis_gnn_missing_deps_error_is_clear():
    if importlib.util.find_spec("torch") and importlib.util.find_spec("torch_geometric"):
        pytest.skip("GNN dependencies are installed")
    sample = build_diagnosis_graph_sample({
        "sample_id": "missing-deps",
        "format": "zip",
        "knowledge_payload": {
            "analysis": {"summary": {"format": "zip"}},
            "source": {"input": {"entry_path": "a.zip"}},
            "format": {"zip": {"structure": {"graph": {"summary": {"file_size": 1}}}}},
        },
    })

    with pytest.raises(RuntimeError, match="torch and torch-geometric"):
        tensorize_sample(sample)
