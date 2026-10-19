# External pg-promise comparison - 2026-10-17

Fresh comparison with unchanged production rules. No fixes or label changes were
made after seeing the result. This is a one-file external reference check, not
a representative accuracy estimate or independently audited evaluation.

## Input and expected observations

GitHub CodeQL revision `ff3231c5ac4779befd8c8690bb04f447fc6a8d13`, file
`javascript/ql/test/query-tests/Security/CWE-089/untyped/pg-promise.js`.
Adjacent `SqlInjection.expected` diagnostic rows agree with all 22 `$ Alert`
annotations: 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 22, 30, 34, 39, 40,
47, 54, 56, 60, 63, 64. These are labeled input locations, not 22 independent
applications or necessarily separate root causes.

Fifteen locations reuse the same SQL string constructed from request input at
lines 6-7. Seven other locations (30, 34, 39, 40, 47, 54, 56) use unsafe raw/open
value formatting. Their grouping matters: do not demand 22 duplicate findings to
claim the shared construction problem is recognized, or count one shared-string
warning as evidence that the seven independent raw-formatting inputs are covered.

The ordinary `$1`/separate-values query at lines 24-27 is manually reviewed as
the negative control for this issue. Mixed queries with both safe and unsafe
values are not counted as clean query controls. Other unannotated source is not
automatically safe. Authoritative formatting documentation:
https://github.com/vitaly-t/pg-promise#query-formatting

## Provenance

- Source SHA256: `f80bbd539d7d62ceee02744daccc1e1ece95b9f8ca5825e9e19ac6a6d21fc343`.
- Expected file SHA256: `e895462221c1c2e2891bdc004a8868d1b24dea2a9b2cb8321e7d6c823c6edfc2`.
- ZIP SHA256: `06d32219a4a9fcfaafc5f577ac7a35315c064e83d22a7385fb346860ab186440`.
- Production rules SHA256: `e3e2064411534ce415344c8897428faa6d1fd8721e79a1386b0d40df6ff9ded1`.

Local ZIP `tmp/external-sql/codeql-postgres-pinned.zip` contains unchanged source
and upstream MIT LICENSE only. It was uploaded through TALGED's signed-in browser.
Neither JavaScript nor SQL was executed. Labels remain outside the uploaded ZIP.

## Observed result

Assessment `d2e6f965-e537-441d-92ff-7d64239e14d7` completed with one HIGH
`semgrep_rules.v1.javascript.express.security.injection.tainted-sql-string`
finding at `pg-promise.js:7`. Browser details confirm the warning describes SQL
string construction, not traced database execution. There were no other findings.
The shared unsafe query construction is recognized; coverage of its 15 downstream
uses is not individually established. All seven separately labeled raw-formatting
input locations lack warnings. The separate-values control has no warning.

No aggregate precision/recall percentage is reported: source-construction warnings
and downstream expected input locations are different scoring units. Reporting
0/22 would ignore the genuine source warning; reporting full coverage would hide
the raw-formatting gap. Dependencies correctly remain Not checked without a lockfile.

Screenshot: `tmp/ui-review/external-postgres-warning.png`.

## Next bounded improvement

Add library-specific detection for request-derived values passed to raw pg-promise
formatting, paired with normal escaped placeholders, quoted-context and unrelated
library controls. Keep this baseline unchanged. If used for development, classify
these examples as regression cases and reserve other external examples for the
next independent check. Do not flag every database method or parameter value.
