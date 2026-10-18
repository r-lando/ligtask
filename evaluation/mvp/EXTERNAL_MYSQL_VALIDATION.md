# External MySQL case comparison - 2026-10-17

No detection rules were changed for this comparison. These SQL examples were
not previously used to adjust TALGED rules during this work. This is a small
externally sourced check, not an independently audited or representative sample.

## Reproducible input

- Upstream repository: GitHub CodeQL.
- Revision: `ff3231c5ac4779befd8c8690bb04f447fc6a8d13`.
- File: `javascript/ql/test/query-tests/Security/CWE-089/untyped/mysql.js`.
- Labels: adjacent `SqlInjection.expected`; explicit `$ Alert` annotations agree
  with upstream diagnostic rows at source lines 15 and 19.
- Source SHA256: `7dc8ee39ceeab816c1f398bd0f882935dfe572c8c832fc0343cb9322e131f1cc`.
- Expected-output SHA256: `e895462221c1c2e2891bdc004a8868d1b24dea2a9b2cb8321e7d6c823c6edfc2`.
- ZIP SHA256: `4e7f2e9a6458378642e11680977a9b6b53e779e36d3902581a345ca57e822e8b`.
- Rules SHA256: `e3e2064411534ce415344c8897428faa6d1fd8721e79a1386b0d40df6ff9ded1`.

The ZIP contains only unchanged `mysql.js` and the upstream MIT LICENSE. Labels
are retained outside the ZIP. Local package: `tmp/external-sql/codeql-mysql-pinned.zip`.
No fixture code or database queries were executed; TALGED only scanned source.

## Expected labels, set before the scan

| Query | Expected | Label origin |
| --- | --- | --- |
| Object query, SQL value joined with request-derived `temp`, line 15 | Flag | Upstream diagnostic and annotation |
| String query joined with request-derived `temp`, line 19 | Flag | Upstream diagnostic and annotation |
| Query at lines 8-11 with `?` placeholder and separate `values: [temp]` | Do not flag for SQL injection | Manually reviewed control, not an upstream universal safe label |

Unannotated source is not automatically safe. The control applies only to SQL
injection in this specific call, not the entire application or database access.

## Live TALGED result

Assessment `fc13808b-216f-47b7-8e78-8bb4fcee1a5b`, ZIP submission through the
signed-in browser. SAST completed in a pipeline lasting 45.6 seconds. Two raw
findings, two consolidated findings, both HIGH `tainted-sql-string`, at exactly
`mysql.js:15` and `mysql.js:19`. No warning on the separate-values control and no
additional findings. Source and license are the two assessed files.

Case counts: 2 risky queries flagged, 0 missed, 0 false alarms on 1 reviewed
negative query. Dependency assessment is correctly Not checked (no lockfile);
secret/configuration checks completed with no findings.

Screenshot: `tmp/ui-review/external-mysql-results.png`.

This verifies the two selected query forms only. It is not a whole-product
accuracy percentage, runtime exploit confirmation, or proof of complete SQL
coverage. No rules were tuned and no findings were suppressed. Keep the baseline
unchanged and expand with additional externally labeled database API cases.
