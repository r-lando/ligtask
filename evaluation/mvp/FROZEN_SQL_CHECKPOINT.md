# Frozen-rules external SQL checkpoint - 2026-10-19

No production rule changes were made after selecting these previously unused
files or seeing their outcomes. Rules SHA256 remains
`a67180ec4fb5f03431c0be30deefbcee29840437f77a89c90eecfe8aa200bded`.
This is a small checkpoint, not an overall accuracy estimate or release/security
certification. Successful scanner completion is separate from detection coverage.

## Source and labels

GitHub CodeQL revision `ff3231c5ac4779befd8c8690bb04f447fc6a8d13`, directory
`javascript/ql/test/query-tests/Security/CWE-089/untyped`.
Original `$ Alert` annotations were cross-checked with diagnostic rows in the
adjacent `SqlInjection.expected` (SHA256
`e895462221c1c2e2891bdc004a8868d1b24dea2a9b2cb8321e7d6c823c6edfc2`).
These external labels are reference expectations, not proof of runtime impact.

| File | External expected location | Observed full-ruleset result |
| --- | --- | --- |
| `tst3.js` | node-postgres unsafe query call, line 9 | Scanner succeeded; `tainted-sql-string` at construction line 8. This identifies the shared risky construction, not a sink-level trace. |
| `tst4.js` | Angular route input joined into sqlite3 query, line 8 | Scanner succeeded with no findings. External expected issue was missed. |

`tst3.js` also includes an upstream `OK - use parameters` example at lines 13-18;
the separate-values call at line 16 has no warning. It is a SQL-specific reviewed
negative control, not a claim about all code in the file. An exact-line 0/1 score
would misrepresent its construction-site warning, so no aggregate percentage is
reported. The SQLite/Angular example is an uncovered client-side SQL pattern;
do not silently relabel it safe or suggest general SQL coverage is complete.

Source SHA256:

- `tst3.js`: `2715dd8e6eb9af076c61037da7e3bb8c1db17b92ab1d986845213f7ba11895c6`.
- `tst4.js`: `5ad0cfe8aadd297010b4a8bb510a52eff03afefbe8b015bd680d3e44973ffc94`.

Files remain in `tmp/external-sql`. They were scanned statically only; no fixture
JavaScript, SQL or dependency installation ran. The comments identify upstream
MIT/BSD origins; files were not vendored into production or distributed as a new
benchmark package. The local Koa control is authored and scored separately from
these external examples.

## Release interpretation

Live Koa upload/details/PDF verification passed (see KOA_SQL_REFINEMENT.md).
Fresh node-postgres case recognized; fresh SQLite/Angular case missed. Keep this
miss documented and assess whether that client-side pattern belongs in the MVP's
declared support before adding more rules. This checkpoint does not justify
claiming complete coverage, zero misses, or production readiness. Daily assessment
limits remain temporarily disabled by user request until the hosting milestone;
this check does not restore or weaken any security control.
