# Command detection refinement — 2026-11-06

Follow-up: [assigned promise aliases](ASSIGNED_PROMISE_REFINEMENT.md) records the
later five-of-twenty-six development recheck and a new external API checkpoint.
The frozen experiment below remains the historical three-of-twenty-six result.

Three narrow JavaScript/TypeScript rules were added:

- Request input selecting `child_process.execFile`, `execFileSync` or `fork`'s
  executable/module. Fix advice explains that the executable itself must be fixed
  or chosen from an allowed list; separate arguments alone do not solve this.
- Request input passed directly through `util.promisify(child_process.exec)`.
- Request input appended using `concat` to a `cmd.exe` `/C` or `/c` command array.

Visible CommonJS namespace imports are required. Tests include seven unsafe cases
and thirteen controls: fixed programs/modules, ordinary argv, fixed commands,
unrelated modules, overwritten values, and tested parameter/local shadowing.
No fixture application or command is executed. These are bounded local syntax
and flow checks, not general alias, wrapper, binding, or cross-file analysis.

## Existing development examples

The pinned CodeQL `child_process-test.js` expectations were unchanged. Before:
ten labeled calls detected, seven missed. After: sixteen detected, one missed.
All seven fixed-command controls remained unflagged. Newly detected lines:
19, 20, 23, 56, 57, 75. Remaining miss: line 39, where both the shell executable
and its command flag are selected in platform branches. It remains a miss rather
than being relabeled safe. The runner returns exit 1 for this expected incomplete
coverage, and exit 2 for invalid scans or fetch failures.

These examples have been used for development; the improved count is regression
evidence and must not be presented as independent overall accuracy.

## Newly selected example with frozen rules

Rules were frozen before selecting or reading `promisification.js` from the same
CodeQL revision `ff3231c5ac4779befd8c8690bb04f447fc6a8d13` and directory
`javascript/ql/test/query-tests/Security/CWE-078/CommandInjection`.

- Rules SHA256: `3d4cf2f5aea54fa1671f09268c50bb770799ef016bee729252d0c83d7cf30c45`.
- Source SHA256: `65a281cf36d0fc685c55ede1a6f6a36ca025d7e5822568ce87e696c4243ffdd0`.
- Upstream `.expected` SHA256: `a30d141d06e4ea50a35d8ce9fb84b400ecb9497811227d89fd427853b2608569`.
- Scanner: Semgrep 1.176.0. Successful scan with no reported errors.
- Result: three labeled calls warned, twenty-three missed, out of twenty-six.
- Upstream line 102 is marked `SPURIOUS`; it is separately recorded and unscored.
  No unlabeled lines are treated as safe, and there are no labeled negative
  controls in this file. No precision estimate is justified.

The three warnings come from existing generic child-process detection, not the
new rules. Assigned aliases, whole request-body values, bound calls, third-party
promisifiers and indirect helpers remain substantial gaps. No rules were changed
after this checkpoint. Subsequent tuning on this file makes it development
evidence; select another unseen file for a later frozen check.

This is a small externally authored checkpoint, not independent human validation
or proof of deployed exploitability. Do not combine its counting units with
authored benchmark cases to produce an overall accuracy percentage.

## Reproduce

Verification: 260 backend tests passed, with two existing dependency deprecation
warnings. The focused command/guidance run passed 40 tests, including the new
twenty-file positive/control fixture. The controlled benchmark retained all
fourteen expected case outcomes (six positives, eight negatives). These test
counts are not an overall accuracy percentage. Git diff whitespace checks passed.

With the installed backend environment on PATH, run:

```text
python evaluation/mvp/run_external_validation.py
python evaluation/mvp/run_frozen_command_checkpoint.py
```

Both fetch immutable public source, verify hashes, scan temporary copies and
write results under ignored `evaluation/results/mvp`. The frozen runner requires
the exact recorded rule-byte digest; checkout line endings can change that digest.
It deliberately refuses to rerun under a changed ruleset rather than imply a new
run is the original frozen experiment. A failed run may leave older result files;
only a newly completed run is current evidence.
