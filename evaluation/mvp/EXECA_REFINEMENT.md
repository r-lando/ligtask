# Focused Execa detection — 2026-11-06

Two rules distinguish request-derived shell-command text from a request-selected
program or Node script. They cover visible CommonJS bindings and inline requires,
legacy default imports, and the tested named `execa` import. Fix advice uses the
existing shell and executable guidance respectively; original evidence remains.

API meaning was checked against upstream documentation:

- [Execa v1](https://github.com/sindresorhus/execa/blob/v1.0.0/readme.md): `shell` and
  `shellSync` use the system shell; `stdout`/`stderr` take an executable path.
- [Execa v5](https://github.com/sindresorhus/execa/blob/v5.1.1/readme.md): direct
  calls and `sync` take a program, while `node` takes a script path. Separate
  argument values do not by themselves select a different executable.
- [Current shell guidance](https://github.com/sindresorhus/execa/blob/main/docs/shell.md)
  explains why shell interpretation should be avoided where possible.

These APIs differ between versions. A syntax match does not establish that the
installed version provides the named method or that deployment is exploitable.
The scanner does not resolve package versions for these SAST rules.

## Scope and controls

The real-engine test covers thirteen unsafe examples and thirteen controls:
literal shell commands, fixed programs/scripts with separate argument data,
fixed tagged-template command arguments, unrelated modules/APIs, overwritten
input, and tested parameter/local shadowing. Recognized calls include legacy
`shell`/`shellSync`, direct executable calls, and legacy `sync`, `node`, `stdout`
and `stderr`. Sources are body/query/params expressions and the bounded parsed
URL query-property pattern already used by command rules.

Other imports, mutable bindings, arbitrary wrappers/aliases, cross-file flow,
shell-enabled argument arrays, modern curried calls/tagged execution, additional
named exports and untested indexed-source combinations are not general coverage
claims. Fixed argv controls assume default/no-shell semantics; application-specific
argument injection and unsafe options are not ruled out by an unflagged control.

## Development evidence

The previously inspected CodeQL `other.js` (revision
`ff3231c5ac4779befd8c8690bb04f447fc6a8d13`, directory
`javascript/ql/test/query-tests/Security/CWE-078/CommandInjection`) is now a
development fixture. It improved from zero to seven warnings among eighteen
labeled calls. The remaining eleven include cross-spawn, SSH, remote-exec and
other wrappers. This is not a fresh holdout. Its source hash remains
`9a88a88dd238a7b8613a3f18cf57842e02ceb9f0133db2c41a6fb414b5d41104`.

`run_frozen_alias_checkpoint.py --regression` writes the updated development
result to `other-command-regression.json`, preserving the original frozen result.

## Newly selected frozen check

After the final rules fingerprint was recorded, previously unused `execa.js`
from the same pinned revision/directory was selected. Its fifteen ordinary
`$ Alert` annotations agree with the upstream `.expected` diagnostic locations.
The unchanged file was scanned statically: zero of fifteen expected locations
warned, with no reported scanner errors. No rules were changed after this result.

The file combines indexed parsed-URL input, modern named APIs and tagged command
forms. This exposes further gaps; it does not demonstrate general Execa support.
Unlabeled lines are unscored, including examples with safe-escaping comments.
No negative-control precision is reported for this checkpoint.

- Rules LF-normalized SHA256: `82450c09ec5c1c89e1288d240b50051c9cdb04622596ff7489e530b54b100a30`.
- `execa.js` SHA256: `64d314bfe378dc96a2c1aebcd45adff8291a45a1c46e5d4b033b49b33a6bda94`.
- `.expected` SHA256: `a30d141d06e4ea50a35d8ce9fb84b400ecb9497811227d89fd427853b2608569`.

Run `python evaluation/mvp/run_frozen_execa_checkpoint.py` with the installed
backend environment on PATH. It checks the exact normalized rules fingerprint,
source and expectation hashes, scans temporary copies and records a separate
ignored result. Exit 1 means the documented misses remain; exit 2 means invalid
execution and no new result. An older output may remain after failure. The
source is now inspected; later tuning turns it into regression evidence.

No fixture JavaScript or dependency installation was executed. These small
checks do not establish deployed exploitability or overall real-world accuracy.

Verification on the clean merged-master branch: 245 backend tests passed, with
two existing dependency deprecation warnings; 44 focused Execa/guidance tests
passed. The real-engine Execa fixture contains thirteen unsafe cases and thirteen
controls. Regression results and frozen external results are recorded separately.
The controlled benchmark also matched all fourteen expected case outcomes (six
positives, eight negatives). Its raw-byte rules SHA256 was
`384ceab0914ac56f737704c0bea75fbff2d9721e7ccd8ccd53551989c4a6997c`;
the normalized fingerprint above is used for the frozen external check.
