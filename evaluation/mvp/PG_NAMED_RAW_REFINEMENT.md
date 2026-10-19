# Named pg-promise raw placeholder refinement - 2026-10-18

Extended `pg-promise-request-raw-value` with a bounded inline named-value check.
The SQL raw placeholder name must exactly equal the selected values-object key,
and the selected value must be request-derived. This supports `${name}:raw` and
`${name}^`, not just a hardcoded `id` field. Existing numeric placeholder rules,
severity, report structure and guidance attribution are unchanged.

The rule combines a structural query-object match with bounded text capture and
explicit equality comparisons for the object key and actual SQL literal. This
prevents a marker in an unrelated comment or a raw placeholder for a different
field from satisfying the check. Named matching excludes spread-built calls.
Database bindings still require the existing pg-promise/CommonJS context and
exclude parameter shadowing.

## Boundaries

The named branch requires inline literal `text`, directly followed by inline
`values`, simple identifier-style names, and a flat values object. Escaped query
literal representations, arbitrary property order, alternative placeholder
delimiters, nested property paths, object aliases and dynamic SQL are not covered.
Multiple raw placeholders are not guaranteed complete coverage. This is not a
general JavaScript or pg-promise parser. Lack of a warning on unsupported forms
does not mean they are safe. The two `:value` quote-sensitive cases are deliberately
unchanged and still need separate work.

## Verification policy

Real-engine regression test includes named raw/caret positives; fixed raw values,
normal named values, exact-name/prefix mismatch, spread values and misleading
comment negatives. Previous scalar/indexed safe controls remain. Initial unsafe
candidate implementations failed these tests and were not accepted. Scanner
errors invalidate the tests; no expected labels were changed to match output.

The existing external PostgreSQL fixture is now regression/development material,
not a fresh holdout. Its original labels and source remain unchanged. Full-ruleset
comparison should produce exactly lines 7, 30, 34, 39, 40, 47: the added line is
47, not the normal named value at 48 or quoted normal `:value` at 55. Remaining
known misses are 54 and 56. No whole-product accuracy percentage is claimed.

Observed final result: full-ruleset scanner completed successfully and returned
exactly those six locations. All 14 authored benchmark cases matched their labels.
226 backend tests passed, with two existing dependency deprecation warnings.
Rules SHA256: `02300e54eeb35220138ec8b39e902d52dce19d58f05a2fa6d5e2daced0b7ea3b`.
No browser assessment was submitted for this change. The backend loads the YAML
rules on new scans; saved reports remain unchanged. Changes are local/unpushed.

## Live browser verification - 2026-10-18

Uploaded the unchanged `codeql-postgres-pinned.zip` (SHA256
`06d32219a4a9fcfaafc5f577ac7a35315c064e83d22a7385fb346860ab186440`).
Assessment `d5bef4f6-091a-4021-a26a-be363648763b` completed in 27.9 seconds.
The results page lists exactly six findings: lines 7, 30, 34, 39, 40, 47.
Line 48 and the normal separate-values control are not flagged. Known misses
54 and 56 remain. The new line-47 detail shows the expected rule, original
scanner description and specific raw-formatting recommendation/action.
Screenshot: `tmp/ui-review/pg-named-raw-live-verified.png`.
No detection rules or historical reports were changed during this check.

Source documentation: https://docs.semgrep.dev/writing-rules/rule-syntax
and https://github.com/vitaly-t/pg-promise#raw-text
