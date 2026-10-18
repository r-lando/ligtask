# Externally sourced validation pilot

## Scope and label policy

This is a small, externally sourced command-injection comparison, not blind
independent validation or an estimate of overall TALGED accuracy. No production
rules were changed during the initial pilot. These cases have subsequently been
used for development and are now regression cases, not a held-out validation set.
Do not tune rules against these examples
and continue describing them as a holdout set.

Source: GitHub CodeQL, revision
`ff3231c5ac4779befd8c8690bb04f447fc6a8d13`,
[`child_process-test.js`](https://github.com/github/codeql/blob/ff3231c5ac4779befd8c8690bb04f447fc6a8d13/javascript/ql/test/query-tests/Security/CWE-078/CommandInjection/child_process-test.js)
and the adjacent `CommandInjection.expected` file. Source and expected-output
hashes are enforced. CodeQL is MIT licensed; files are fetched to temporary
memory/storage, not vendored or executed. The pinned repository LICENSE applies
to the upstream material.

All 17 explicit `$ Alert` call lines are compared with the upstream diagnostic
rows before scanning. `$ MISSING` is not treated as a known safe example.
Seven literal `"foo"` calls (lines 8–14) are manually adjudicated negative
controls for command injection only. Other unannotated calls, including options
that upstream describes as technically unsafe, are not counted as safe.

The complete unchanged JavaScript file is scanned with TALGED's full local rules.
Command-related rule IDs count only at the labeled call's start line. Duplicate
matches count once; other alerts are listed separately. A warning at the call is
a detection, not proof that TALGED traced the full request-to-command path.
Upstream labels are an external reference, not a guarantee of runtime impact.

## First run: 2026-10-17

Semgrep 1.176.0; rules SHA256:
`01b4c35fc19c4c530fe18ee46c13b29265edb91407060927346229efa53512f2`.

| Outcome | Calls |
| --- | ---: |
| Risky call flagged | 8 |
| Risky call missed | 9 |
| Fixed-command control warned on | 0 |
| Fixed-command control not warned on | 7 |

Misses: source lines 19, 20, 23, 39, 44, 54, 56, 57, 75. These cover
user-controlled executable paths, explicit shell invocations through argument
arrays, and a promisified exec wrapper. Review these with additional safe
controls before implementing detection changes. Do not simply flag every
execFile/spawn call: fixed executables with separate arguments can be valid.

The eight detections were the existing `detect-child-process` warning. This
comparison measures warning coverage at a known risky call, not exploit proof.
There is no whole-product accuracy percentage. SQL, XSS, secrets, dependencies,
and real deployment conditions are outside this pilot.

## Running

From the repository root, put `backend/.venv/Scripts` on PATH and run
`backend/.venv/Scripts/python.exe evaluation/mvp/run_external_validation.py`.
Network access is required only to fetch pinned upstream files. Fixture code is
never executed. Output is written to ignored
`evaluation/results/mvp/external-command-validation.json` with hashes, scanner
version, per-call outcomes and unscored warnings. Exit 0 means all selected labels
matched; 1 means misses/false alarms; 2 means invalid run, not a clean scan.
On failure an older output file may remain: only a newly successful run is valid.

Three bookkeeping tests verify duplicate handling, visible misses/false alarms,
unlabeled-line exclusion, and rejection of inconsistent upstream labels.
This pilot supplements, rather than replaces, the authored regression benchmark.

## Shell-argument refinement: 2026-10-17

Added `request-to-explicit-shell-arguments`: request properties and parsed request
URL query values flowing into `sh`/`bash` with `-c`, through CommonJS `const` or
`var` child_process bindings. Covers inline two-element arrays and a bounded
consecutive empty-array/index-0/index-1/call sequence. The latter deliberately
does not allow intervening statements that could change shell argument meaning.
Named and arrow parameter shadowing is excluded. No blanket warning on separate
argument lists was added. Windows shells, variable-selected shells, arbitrary
wrappers, other imports and cross-function flow are not covered by this rule.

Final rules SHA256:
`e3e2064411534ce415344c8897428faa6d1fd8721e79a1386b0d40df6ff9ded1`.
Same pinned labels: **10 flagged, 7 missed, 0 warned-on fixed controls,
7 unflagged fixed controls**. Newly detected upstream lines: 44 and 54.
Remaining missed lines: 19, 20, 23, 39, 56, 57, 75. A nonzero evaluator exit is
expected because those misses remain; it is not a scanner execution failure.

The new real-engine test checks six unsafe variants and seven negative controls,
including overwritten arguments, fixed command text, normal executable argv,
unrelated modules, script arguments, and shadowed module bindings. Expected labels
were not changed to make results pass. Saved assessments are unchanged; only new
scans use the added rule. Dashboard design and severity ordering are unchanged.
