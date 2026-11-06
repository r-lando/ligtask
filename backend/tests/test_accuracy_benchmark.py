"""Test benchmark bookkeeping without substituting for real scanner execution."""
import importlib.util
from pathlib import Path
import pytest

path = Path(__file__).resolve().parents[2] / "evaluation/mvp/run_accuracy_benchmark.py"
spec = importlib.util.spec_from_file_location("accuracy_benchmark", path)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_metrics_include_misses_and_false_alarms():
    result = benchmark.score([{"outcome": outcome} for outcome in ["TP", "TP", "FN", "FP", "TN"]])
    assert result == {"TP": 2, "FP": 1, "TN": 1, "FN": 1, "precision": 0.6667, "recall": 0.6667}


def test_empty_metrics_are_not_perfect_scores():
    assert benchmark.score([])["precision"] is None
    assert benchmark.score([])["recall"] is None


def test_every_category_has_positive_and_negative_examples():
    assert len({case[0] for case in benchmark.CASES}) == len(benchmark.CASES)
    for category in {case[1] for case in benchmark.CASES}:
        assert {case[2] for case in benchmark.CASES if case[1] == category} == {True, False}


def test_scanner_failure_cannot_produce_a_clean_score(monkeypatch):
    monkeypatch.setattr(benchmark, "run_semgrep", lambda folder: {"success": False})
    monkeypatch.setattr(benchmark, "scan_secrets", lambda folder: {"scan_status": "completed"})
    with pytest.raises(RuntimeError, match="no clean result"):
        benchmark.evaluate()
