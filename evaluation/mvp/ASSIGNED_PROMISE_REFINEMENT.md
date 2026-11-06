# Assigned promise aliases — 2026-11-06

`request-to-assigned-promisified-shell-exec` recognizes a visible `const` alias of
`util.promisify(child_process.exec)`, including `exec.bind(child_process)`, when
request-derived data reaches the alias's command argument. The wrapper still
executes a shell command. The existing shell-specific fix advice is retained.

The rule requires visible CommonJS namespace imports. Sources include request
body, query and route-parameter values, including whole-body values. Tests cover
four unsafe examples and fifteen controls: fixed commands, unused input, normal
`execFile` argument lists, options-only input, overwritten input, unrelated
functions/modules and tested alias/module shadowing. Arbitrary alias chains,
mutable wrapper bindings, renamed/third-party promisifiers, other imports and
cross-file flow remain unsupported. This rule does not establish deployed
exploitability or general promise-wrapper coverage.

The previously inspected `promisification.js` is now a development fixture. Its
original three-of-twenty-six frozen result remains documented in
[the previous checkpoint](COMMAND_VARIANTS_REFINEMENT.md). Rechecking it with
changed rules uses `run_frozen_command_checkpoint.py --regression`, writes a
different result file and never overwrites or rebrands the earlier checkpoint.

The development recheck detected five of twenty-six expected calls (previously
three); lines 52 and 55 are newly detected. Twenty-one remain missed. The earlier
`child_process-test.js` result remains sixteen detected, one missed, with seven
fixed-command controls unflagged; these are separate counting units.

## Another frozen external check

After freezing the final rules, `other.js` was selected from the same pinned
CodeQL revision and directory recorded in the previous checkpoint. Its ordinary
`$ Alert` annotations were cross-checked against the pinned `.expected` diagnostic
locations. No rules were changed after inspecting its result.

- Result: zero detected, eighteen missed; scanner completed without errors.
- APIs include cross-spawn, execa, remote-exec, SSH wrappers and opener options.
  They are not covered by the new Node core alias rule.
- No negative controls are labeled, so no false-alarm rate is calculated.
- Source SHA256: `9a88a88dd238a7b8613a3f18cf57842e02ceb9f0133db2c41a6fb414b5d41104`.
- LF-normalized rules SHA256: `eab38ad0a27f58819de75bc6ff0b65cf950e222809716a1385a46afb4eeb6115`.
  This digest normalizes CRLF to LF so checkout line endings do not change it.
- The expected-results hash and source revision are unchanged from the prior
  CodeQL checkpoint. `run_frozen_alias_checkpoint.py` verifies the source,
  expectations and rules before producing its separate result artifact.

This check exposes unsupported APIs; it does not establish general accuracy,
independent human validation or deployed exploitability. The source is now
inspected, so subsequent tuning makes it development evidence. Exit 1 denotes
the preserved misses; exit 2 means invalid execution with no new score.

The focused PR also includes earlier local scanner-completeness reporting and
Angular/sqlite3 detection; authentication, demo account, UI, quota and source
revision changes are excluded. PR #5 remains its review base until merged.

Verification of the isolated staged PR tree: 240 backend tests passed, with two
existing dependency deprecation warnings. The focused alias/command/guidance run
passed 41 tests. These counts describe regression checks, not an accuracy score.
The same isolated tree matched all fourteen controlled benchmark outcomes (six
positives, eight negatives). Its raw-byte rules digest was
`e0e1cd55c780d8d943d3af483b64c892b2c4fdd389662b6b3b2d92e182fe2824`;
the LF-normalized digest above is used for portable frozen-rule verification.

Merge review: after PR #5's additional sanitizer-shadowing repair, the combined
master/PR #6 checkout passed all 240 backend tests. Frozen-checkpoint fingerprints
above identify the historical experiment and are not rewritten after that repair.
