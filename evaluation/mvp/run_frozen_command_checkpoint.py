"""First-use external promisification checkpoint; fixture code is never executed."""
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
FROZEN_RULES = "3d4cf2f5aea54fa1671f09268c50bb770799ef016bee729252d0c83d7cf30c45"
SOURCE = "promisification.js"
SOURCE_SHA256 = "65a281cf36d0fc685c55ede1a6f6a36ca025d7e5822568ce87e696c4243ffdd0"


def main(regression=False):
    rules = ROOT / "backend/semgrep_rules/v1"
    digest = hashlib.sha256()
    for path in sorted(rules.rglob("*.yaml")):
        digest.update(path.relative_to(rules).as_posix().encode())
        digest.update(path.read_bytes())
    if not regression and digest.hexdigest() != FROZEN_RULES:
        raise ValueError("Rules changed since fixture selection; this frozen checkpoint cannot be reused unchanged.")
    data = {}
    for name in (SOURCE, "CommandInjection.expected"):
        with urlopen(BASE + DIRECTORY + "/" + name, timeout=30) as response:
            data[name] = response.read(2_000_001)
        if len(data[name]) > 2_000_000:
            raise ValueError("External fixture exceeds size limit.")
    if hashlib.sha256(data["CommandInjection.expected"]).hexdigest() != HASHES["CommandInjection.expected"]:
        raise ValueError("Pinned upstream expectations changed.")
    if hashlib.sha256(data[SOURCE]).hexdigest() != SOURCE_SHA256:
        raise ValueError("Pinned external source changed.")
    source = data[SOURCE].decode("utf-8")
    positives = {line for line, text in enumerate(source.splitlines(), 1) if re.search(r"// \$ Alert(?:\s|$)", text)}
    spurious = {line for line, text in enumerate(source.splitlines(), 1) if "// $ SPURIOUS: Alert" in text}
    selection = data["CommandInjection.expected"].decode("utf-8").split("#select\n", 1)[1].split("\nnodes\n", 1)[0]
    upstream = {int(match.group(1)) for line in selection.splitlines() if "This command line depends on" in line
                for match in [re.match(r"^\| promisification\.js:(\d+):", line)] if match}
    if not positives or positives | spurious != upstream or positives & spurious:
        raise ValueError("External annotations disagree with upstream diagnostic locations.")
    with tempfile.TemporaryDirectory(prefix="talged-frozen-command-") as folder:
        fixture = Path(folder) / SOURCE
        fixture.write_bytes(data[SOURCE])
        run = subprocess.run(["semgrep", "--config", str(rules), "--json", "--no-git-ignore", str(fixture)],
                             capture_output=True, text=True, encoding="utf-8", timeout=120, check=True)
        output = json.loads(run.stdout)
        if output.get("errors") or not output.get("paths", {}).get("scanned"):
            raise ValueError("Scanner errors or no scanned files; no checkpoint result.")
    command = [f for f in output["results"] if re.search(r"command|shell|child-process|child_process", f["check_id"], re.I)]
    rows = [{"line": line, "matched_rules": sorted({f["check_id"] for f in command if f["start"]["line"] == line})}
            for line in sorted(positives)]
    result = {
        "scope": ("Development recheck of the inspected promisification file; not a new holdout."
                  if regression else "One newly selected external file after freezing rules; not overall accuracy or independent review of exploitability."),
        "source_url": BASE + DIRECTORY + "/" + SOURCE,
        "sha256": {name: hashlib.sha256(payload).hexdigest() for name, payload in data.items()},
        "rules_sha256": digest.hexdigest(), "cases": rows,
        "detected": sum(bool(row["matched_rules"]) for row in rows),
        "missed": sum(not row["matched_rules"] for row in rows),
        "upstream_spurious_unscored_lines": sorted(spurious),
        "negative_controls": "None labeled. Unannotated source lines are not assumed safe.",
        "unscored_findings": [{"line": f["start"]["line"], "rule": f["check_id"]}
                              for f in output["results"] if f not in command or f["start"]["line"] not in positives],
        "limitations": ["Source is now inspected; subsequent tuning makes it regression evidence.",
                        "Exact start-line command warnings count once; a generic warning is not a taint trace.",
                        "No runtime exploit test or aggregate precision score."]}
    destination = ROOT / "evaluation/results/mvp" / ("promisification-regression.json" if regression else "frozen-promisification-checkpoint.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return int(bool(result["missed"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--regression", action="store_true", help="Recheck the inspected file under changed rules; retain original checkpoint separately.")
    args = parser.parse_args()
    try:
        raise SystemExit(main(args.regression))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Checkpoint invalid: {type(error).__name__}. No new result produced.", file=sys.stderr)
        raise SystemExit(2)
