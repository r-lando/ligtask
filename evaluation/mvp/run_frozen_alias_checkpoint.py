"""Frozen check of another external file; never execute fixture JavaScript."""
import hashlib
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.request import urlopen

from run_external_validation import BASE, DIRECTORY, HASHES

ROOT = Path(__file__).resolve().parents[2]
FROZEN_LF_SHA256 = "eab38ad0a27f58819de75bc6ff0b65cf950e222809716a1385a46afb4eeb6115"
SOURCE = "other.js"
SOURCE_SHA256 = "9a88a88dd238a7b8613a3f18cf57842e02ceb9f0133db2c41a6fb414b5d41104"


def main(regression=False, *, source_name=SOURCE, source_hash=SOURCE_SHA256,
         frozen_fingerprint=FROZEN_LF_SHA256, result_name=None):
    rules = ROOT / "backend/semgrep_rules/v1"
    digest = hashlib.sha256()
    for path in sorted(rules.rglob("*.yaml")):
        digest.update(path.relative_to(rules).as_posix().encode())
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    if not regression and digest.hexdigest() != frozen_fingerprint:
        raise ValueError("Rules differ from the frozen LF-normalized checkpoint.")
    payloads = {}
    for name in (source_name, "CommandInjection.expected"):
        with urlopen(BASE + DIRECTORY + "/" + name, timeout=30) as response:
            payloads[name] = response.read(2_000_001)
        if len(payloads[name]) > 2_000_000:
            raise ValueError("External source exceeds limit.")
    if hashlib.sha256(payloads["CommandInjection.expected"]).hexdigest() != HASHES["CommandInjection.expected"]:
        raise ValueError("Pinned expectations changed.")
    if source_hash and hashlib.sha256(payloads[source_name]).hexdigest() != source_hash:
        raise ValueError("Pinned source changed.")
    source = payloads[source_name].decode("utf-8")
    positives = {n for n, line in enumerate(source.splitlines(), 1) if re.search(r"// \$ Alert(?:\s|$)", line)}
    spurious = {n for n, line in enumerate(source.splitlines(), 1) if "// $ SPURIOUS: Alert" in line}
    selection = payloads["CommandInjection.expected"].decode("utf-8").split("#select\n", 1)[1].split("\nnodes\n", 1)[0]
    upstream = {int(match.group(1)) for line in selection.splitlines() if "This command line depends on" in line
                for match in [re.match(r"^\| " + re.escape(source_name) + r":(\d+):", line)] if match}
    if not positives or positives | spurious != upstream or positives & spurious:
        raise ValueError("Reference annotations disagree; no score produced.")
    with tempfile.TemporaryDirectory(prefix="talged-alias-checkpoint-") as folder:
        path = Path(folder) / source_name
        path.write_bytes(payloads[source_name])
        run = subprocess.run(["semgrep", "--config", str(rules), "--json", "--no-git-ignore", str(path)],
                             capture_output=True, text=True, encoding="utf-8", timeout=120, check=True)
        output = json.loads(run.stdout)
        if output.get("errors") or not output.get("paths", {}).get("scanned"):
            raise ValueError("Invalid scanner execution; no score produced.")
    relevant = [f for f in output["results"] if re.search(r"command|shell|child-process|child_process", f["check_id"], re.I)]
    rows = [{"line": n, "matched_rules": sorted({f["check_id"] for f in relevant if f["start"]["line"] == n})}
            for n in sorted(positives)]
    result = {"scope": ("Development recheck of an inspected file; not a new holdout." if regression
                        else "First-use external file selected after freezing rules; not overall accuracy."),
              "source_url": BASE + DIRECTORY + "/" + source_name,
              "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()},
              "rules_lf_sha256": digest.hexdigest(), "cases": rows,
              "detected": sum(bool(row["matched_rules"]) for row in rows),
              "missed": sum(not row["matched_rules"] for row in rows),
              "spurious_unscored_lines": sorted(spurious),
              "unscored_findings": [{"line": f["start"]["line"], "rule": f["check_id"]}
                                    for f in output["results"] if f not in relevant or f["start"]["line"] not in positives],
              "limitations": ["No negative controls labeled; unlabeled lines are not assumed safe.",
                              "Warning start-line coverage only; generic warnings are not taint proofs.",
                              "This file is now inspected; later tuning makes it regression evidence."]}
    filename = result_name or ("other-command-regression" if regression else "frozen-other-command-checkpoint")
    target = ROOT / "evaluation/results/mvp" / (filename + ".json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return int(bool(result["missed"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--regression", action="store_true", help="Recheck inspected other.js under changed rules, keeping the frozen result separately.")
    args = parser.parse_args()
    try:
        raise SystemExit(main(args.regression))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Checkpoint invalid: {type(error).__name__}. No new result produced.", file=sys.stderr)
        raise SystemExit(2)
