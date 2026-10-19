"""Pinned CodeQL command-injection pilot. Never execute downloaded JavaScript."""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
REVISION = "ff3231c5ac4779befd8c8690bb04f447fc6a8d13"
DIRECTORY = "javascript/ql/test/query-tests/Security/CWE-078/CommandInjection"
BASE = f"https://raw.githubusercontent.com/github/codeql/{REVISION}/"
SOURCE = "child_process-test.js"
HASHES = {
    SOURCE: "845de16501e14432ad5b205b943d925ef876b726ab69fb9c660036df4591fb8f",
    "CommandInjection.expected": "a30d141d06e4ea50a35d8ce9fb84b400ecb9497811227d89fd427853b2608569",
}
# Fixed literal commands, manually adjudicated before the first TALGED run.
# No other unannotated upstream line is assumed safe.
NEGATIVE_LINES = set(range(8, 15))


def labels(source, expected):
    positives = {i for i, line in enumerate(source.splitlines(), 1)
                 if re.search(r"// \$ Alert(?:\s|$)", line)}
    selection = expected.split("#select\n", 1)[1].split("\nnodes\n", 1)[0]
    upstream = {int(match.group(1)) for line in selection.splitlines()
                if "This command line depends on" in line
                for match in [re.match(r"^\| child_process-test\.js:(\d+):", line)] if match}
    if not positives or positives != upstream:
        raise ValueError("Upstream annotations and expected results disagree; adjudication required.")
    lines = source.splitlines()
    if any(not re.fullmatch(r'\s*cp\.\w+\("foo"\);', lines[n - 1]) for n in NEGATIVE_LINES):
        raise ValueError("Negative controls changed; adjudication required.")
    return positives


def classify(positives, findings):
    rows = []
    for line in sorted(positives | NEGATIVE_LINES):
        # Require the match to start at the labeled call, not merely enclose it.
        matched = sorted({f["check_id"] for f in findings if f["start"]["line"] == line})
        expected = line in positives
        rows.append({"line": line, "expected_detection": expected, "matched_rules": matched,
                     "outcome": ("TP" if matched else "FN") if expected else ("FP" if matched else "TN")})
    return rows


def main():
    try:
        # Fixed HTTPS origin and immutable revision. No source code is imported/run.
        payloads = {}
        for name in (SOURCE, "CommandInjection.expected"):
            with urlopen(BASE + DIRECTORY + "/" + name, timeout=30) as response:
                payloads[name] = response.read(2_000_001)
            if len(payloads[name]) > 2_000_000:
                raise ValueError("Upstream file exceeds validation limit.")
            if hashlib.sha256(payloads[name]).hexdigest() != HASHES[name]:
                raise ValueError("Pinned upstream content hash mismatch.")
        source = payloads[SOURCE].decode("utf-8")
        positives = labels(source, payloads["CommandInjection.expected"].decode("utf-8"))
        rules = ROOT / "backend/semgrep_rules/v1"
        digest = hashlib.sha256()
        for path in sorted(rules.rglob("*.yaml")):
            digest.update(path.relative_to(rules).as_posix().encode())
            digest.update(path.read_bytes())
        version = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        with tempfile.TemporaryDirectory(prefix="talged-external-") as temp:
            fixture = Path(temp) / SOURCE
            fixture.write_bytes(payloads[SOURCE])
            process = subprocess.run(["semgrep", "--config", str(rules), "--json", "--no-git-ignore", str(fixture)],
                                     capture_output=True, text=True, encoding="utf-8", check=True, timeout=120)
            scan = json.loads(process.stdout)
            if scan.get("errors") or not scan.get("paths", {}).get("scanned"):
                raise ValueError("Scanner errors or no scanned files; no score produced.")
        # All TALGED rules are retained, but only command-related alerts count here.
        relevant = [f for f in scan["results"] if re.search(r"command|shell|child-process|child_process", f["check_id"], re.I)]
        rows = classify(positives, relevant)
        result = {"scope": "Externally sourced command-injection regression (now used for development), not overall accuracy or blind validation",
                  "upstream_revision": REVISION, "source_url": BASE + DIRECTORY + "/" + SOURCE,
                  "sha256": {k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
                  "rules_sha256": digest.hexdigest(), "semgrep_version": version,
                  "cases": rows, "counts": {key: sum(r["outcome"] == key for r in rows) for key in ("TP", "FN", "FP", "TN")},
                  "unscored_findings": [{"line": f["start"]["line"], "rule": f["check_id"]} for f in scan["results"] if f not in relevant or f["start"]["line"] not in positives | NEGATIVE_LINES],
                  "limitations": ["Positive labels are upstream CodeQL expectations, not proof of deployed exploitability.",
                                  "Seven fixed-command negative controls were manually adjudicated, not upstream safe labels.",
                                  "One file and one issue family; unsupported APIs remain visible as misses.",
                                  "Named command-rule IDs and exact start lines determine matches; inspect other alerts separately.",
                                  "Do not tune rules on these cases and continue calling them a holdout."]}
        output = ROOT / "evaluation/results/mvp/external-command-validation.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return int(bool(result["counts"]["FN"] or result["counts"]["FP"]))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f"Validation invalid: {detail}. No new score produced.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
