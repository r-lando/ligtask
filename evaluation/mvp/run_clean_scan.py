"""Run real scanners on a controlled clean fixture without saving an assessment.

Run from the project root using backend/.venv/Scripts/python.exe. This is a
smoke check, not a precision/recall benchmark or a guarantee of security.
"""

import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.repository_service import run_assessment_pipeline


def main():
    started = time.perf_counter()
    result = run_assessment_pipeline(Path(__file__).parent / "fixtures" / "clean-web")
    actual = {
        "fixture": "evaluation/mvp/fixtures/clean-web",
        "expected_status": "completed",
        "expected_findings": 0,
        "actual_status": result["assessment_status"],
        "actual_findings": len(result["raw_findings"]),
        "mechanisms": result["mechanism_statuses"],
        "finding_rules": [item.get("rule_id") for item in result["raw_findings"]],
        "duration_seconds": round(time.perf_counter() - started, 3),
        "limitations": [
            "Static JavaScript/HTML baseline only; no server-side routes.",
            "No third-party dependencies, so OSV has no packages to query.",
            "No supported configuration files, so configuration coverage is not exercised.",
            "No user accounts or live assessment database records are created.",
        ],
    }
    actual["passed"] = (
        actual["actual_status"] == "completed"
        and actual["actual_findings"] == 0
        and all(item["status"] == "completed" for item in actual["mechanisms"].values())
    )
    output = ROOT / "evaluation" / "results" / "mvp"
    output.mkdir(parents=True, exist_ok=True)
    (output / "clean-scan.json").write_text(json.dumps(actual, indent=2), encoding="utf-8")
    print(json.dumps(actual, indent=2))
    return 0 if actual["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
