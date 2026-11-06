"""Validation bookkeeping, independent of scanner behavior."""
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("external_validation", Path(__file__).resolve().parents[2] / "evaluation/mvp/run_external_validation.py")
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


def test_duplicates_do_not_inflate_detections_and_misses_remain():
    findings = [{"check_id": "shell", "start": {"line": line}} for line in (17, 17, 8)]
    rows = pilot.classify({17, 18}, findings)
    counts = {key: sum(row["outcome"] == key for row in rows) for key in ("TP", "FN", "FP", "TN")}
    assert counts == {"TP": 1, "FN": 1, "FP": 1, "TN": 6}


def test_unlabeled_lines_are_not_assumed_safe():
    assert len(pilot.classify({17}, [{"check_id": "shell", "start": {"line": 99}}])) == 8


def test_changed_labels_fail_closed():
    with pytest.raises(ValueError, match="disagree"):
        pilot.labels("cp.exec(cmd); // $ Alert", "#select\n")
