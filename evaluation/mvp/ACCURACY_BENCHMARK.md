# Controlled accuracy baseline

Run from the repository root in PowerShell:

```powershell
$env:PATH = "$PWD\backend\.venv\Scripts;$env:PATH"
.\backend\.venv\Scripts\python.exe evaluation/mvp/run_accuracy_benchmark.py
# Optional: live public package/version queries to OSV
.\backend\.venv\Scripts\python.exe evaluation/mvp/run_accuracy_benchmark.py --dependencies
```

The runner uses the production Semgrep rules and secret detector on temporary files. Fixture code is never executed. It creates no account or assessment and consumes no assessment quota. JSON is written to `evaluation/results/mvp/accuracy-benchmark.json` (ignored generated output). Nonzero exit indicates a mismatch or failed scanner; it is not a broken benchmark.

## What is scored

14 authored JavaScript cases cover SQL construction versus parameters, shell commands versus argument arrays, browser HTML writes versus text or sanitization, and literal versus runtime secrets. Labels apply only to the named issue family, not to whole-application security. Each case counts once regardless of duplicate rule matches. Other matches are listed separately for review. Both safe and vulnerable examples are included per category. Fixture and ruleset hashes identify the inputs used.

The first real-engine baseline on 2026-10-16 produced 5 detected positive cases, 7 correctly unflagged negative cases, 1 false alarm, and 1 miss. Case-level precision and recall are both 83.33% **on this tiny authored set only**, not TALGED's real-world accuracy.

Observed gaps to investigate next:

- `html-sanitized`: both browser HTML rules flag a direct `DOMPurify.sanitize(...)` result. Negative label assumes a maintained, correctly configured DOMPurify default sanitizer, HTML output context, and no post-sanitization mutation. This is not a blanket exemption for every function named sanitize.
- `shell-helper`: the targeted request-to-shell rule does not detect request input flowing through a separate helper into `exec`. Inspect `other_rules` before claiming the whole scanner produced no warning.

Do not remove these cases to get a green result. Fix detection narrowly, add bypass and safe counterexamples, and rerun unchanged baseline cases.

## Targeted detection fixes (2026-10-16)

The HTML rules now recognize direct, single-argument `sanitize` results from a default `dompurify` import (including aliases). Raw neighboring writes, appended unsanitized content, custom call options, unimported lookalikes, visible `setConfig`/`addHook` changes, sanitizer replacement, and tested named-function/arrow-parameter shadowing remain flagged. This is a bounded syntactic exemption, not proof of a secure DOMPurify version or configuration across files. Indirect mutations and other shadowing forms are not comprehensively modeled. Keep dependency scanning and review enabled. Rationale: [DOMPurify usage and configuration guidance](https://github.com/cure53/DOMPurify).

A separate `request-to-shell-exec-helper` rule recognizes a same-file named single-argument helper that directly concatenates its parameter into an explicitly imported `child_process.exec` command. It reports request input passed to that helper; fixed-command and argument-array helpers remain unflagged by this rule. Tested parameter-shadowed helper names are excluded. This is not general interprocedural analysis: multiple arguments, helper chains, cross-file calls, alternate declaration shapes, and dynamic dispatch remain outside the proven coverage.

The original 14 fixture sources and labels were retained; the helper rule is accepted as another detector for the same command-injection family. After these fixes, all 6 positive and 8 negative examples were classified as expected. That is a regression result, not a claim of 100% real-world accuracy. The full backend suite passed 170 tests; final shadowing guards also passed focused real-engine regression checks. Existing saved assessments are not recalculated; new scans use these rules.

## Dependency comparison

`--dependencies` reuses the existing 10-case npm evaluator without overwriting its archived formal report. Fresh results go into the benchmark JSON. Live advisories are compared to recorded 2026-09-04 labels. Network/partial failures invalidate that portion; new or missing advisory IDs require adjudication rather than automatic false-positive claims. Dependency results remain separate from code-case metrics. No deployed package reachability is established.

On 2026-10-16 the live run completed all 10 cases: 7 positive cases detected, 3 recorded negative cases unflagged, and all 45 expected advisory IDs found. Four additional IDs were returned, so this portion is marked `needs_review`, not an unconditional pass. IDs: `GHSA-4hqw-qxg8-jxx2`, `GHSA-9fr6-4gfg-395g`, `GHSA-j8rh-479h-cp32`, `GHSA-vh66-26gq-q6x8`. Their current applicability has not been independently adjudicated.

## Limits

These are developer-authored regression examples, not blind validation or a representative sample. They do not measure authentication, authorization, business logic, all frameworks, or runtime exploitability. The next expansion should use independently labeled cases and additional languages/frameworks without tuning labels to scanner output. Scanner availability is required; failures must never be reported as a clean scan.
