# Quote-sensitive pg-promise check - 2026-10-18

Added `pg-promise-request-open-value` for request-derived named `:value`
placeholders outside SQL single-quoted value regions. Double-quoted SQL regions
are not treated as string values. SQL placeholder names and values-object keys
must match exactly. A specific recommendation advises normal value formatting
with separately supplied input; it does not claim a deployed attack was tested.

## Bounded support and limitations

This is a deliberately limited lexical check combined with Semgrep structural
and taint constraints, not a full SQL/JavaScript parser or complete pg-promise
analysis. It requires the existing CommonJS/database binding context and supported
query methods, an inline double-quoted JavaScript query string, `text` followed by
flat inline `values`, simple named placeholders and direct call syntax.

It accepts escaped double quotes in the JavaScript source, but not arbitrary
escape sequences. Complete single-quoted SQL regions, including doubled SQL
single quotes, are consumed as tokens. Comments and dollar-quote markers are
excluded conservatively. Spread-built calls and database parameter shadowing
are excluded. Only first/last unquoted open placeholders are guaranteed in a
multi-placeholder query; intermediate ones may be missed. Dynamic strings,
alternate literal forms, SQL files, reversed properties, nested/aliased values,
other quoting modes and arbitrary cross-function flow remain unsupported.

Absence of a finding on unsupported forms never establishes safety. Existing
severity ordering, dashboard structure and saved assessment data are unchanged.

## Development regression result

Unchanged pinned CodeQL `pg-promise.js` now produces exactly eight findings:
7, 30, 34, 39, 40, 47, **54, 56**. No warning at 55 (the single-quoted value),
48 (normal named value), or 24-27 (normal separate-values query). Scanner reports
success. This means the two tracked remaining input locations are now covered;
it does not mean every downstream query or possible library pattern is covered.

Real-engine targeted tests include unquoted/double-quoted positives, a mixed
query with two risky and one safely quoted value, normal placeholders, fixed
values, wrong names, comments, unsupported escapes/spreads and unrelated imports.
Both PostgreSQL rule tests passed after the final multi-placeholder change.
All 14 authored benchmark cases matched. Backend suite: 229 passed with two
existing dependency deprecation warnings. No fixture JavaScript or SQL executed.
Rules fingerprint: `3bf0773505662717e0605f22fe8f0eddaf83550f6d4cd4bddcd312a205cfb822`.

## Fresh external checks (no tuning to their outcomes)

CodeQL revision `ff3231c5ac4779befd8c8690bb04f447fc6a8d13`, directory
`javascript/ql/test/query-tests/Security/CWE-089/untyped`:

- `vercel.ts`, SHA256 `dd621ab0a9d2f7e7840f4be767ae3804b7a133b7cf32b27f3350b244012bbb86`:
  upstream alert line 7 (two expected source paths to the same sink, counted once).
  Real full-ruleset scan succeeded and returned `tainted-sql-string` at line 7.
- `koarouter.js`, SHA256 `2698db29e61b26a1f1ed7c31bfb18e298c27ac65e31f2ccdd64d79c141ee70b8`:
  upstream alert line 17. Full-ruleset scan succeeded with **no findings**:
  an externally expected positive was missed. Do not treat scanner completion or
  zero findings as safety. The destructured Koa query/array-join flow is an open
  coverage item; no fix was made during this fresh comparison.

Upstream annotations were checked against the original adjacent
`SqlInjection.expected` diagnostic rows. These fresh positive-only examples do
not measure false alarms or establish an overall accuracy percentage. External
labels are reference expectations, not proof of deployed exploitability. No
changes were made to fit these examples. Local upstream files remain under tmp;
the existing downloaded MIT LICENSE applies.

Reference: https://github.com/vitaly-t/pg-promise#open-values
