# Bounded pg-promise raw-value refinement

Added `pg-promise-request-raw-value` to the local production Semgrep rules. It
requires CommonJS initialization of pg-promise and a database binding created
from it, a supported query method, request-derived input, and a matching raw
placeholder. The warning is HIGH and does not claim deployed exploitability.

Rules SHA256 after this change:
`43efe5d75518ce8976cf8d1eb6fce141b7a62e8bafe6a184a03486fa30d06bc4`.

Supported shapes:

- Inline query object with `text` and `values`.
- `$1:raw` / `$1^` with a directly supplied request property.
- `$1:raw` / `$1^` and `$2:raw` / `$2^` mapped to the corresponding first/second
  element of an inline values array.
- Named/arrow function parameter shadowing of the database binding is excluded.

Normal placeholders, fixed raw values, unrelated libraries and a request value
at the wrong array index do not trigger this rule. Unknown scalar aliases are
deliberately not treated as scalar input: an alias may actually hold an array,
and treating the whole array as the first raw parameter would create false alarms.

Not covered: named placeholders, `:value` quote context, higher array indexes,
external SQL files, spread-built options, ESM/alternate initialization, arbitrary
aliases/reassignments, cross-function flow or all possible binding shadowing.
This is not a complete pg-promise analyzer. No blanket warning for every query
method or every occurrence of a raw formatting marker was added.

## Verification

Real Semgrep 1.176.0 test: four supported unsafe shapes flagged; safe controls
include ordinary parameters, fixed raw SQL, wrong index in both directions,
unrelated modules, parameter shadowing, named normal values, index 10, and a
values-array alias. A scalar alias is an explicitly unsupported positive example,
not a claim that the code is safe.

Complete ruleset rerun of unchanged pinned `pg-promise.js` (see
EXTERNAL_POSTGRES_VALIDATION.md for source and pre-change labels): five findings,
at lines **7, 30, 34, 39, 40**, no scanner errors, one source file scanned. The four
new findings cover four of the previously missed seven raw/open-formatting
locations. Lines **47, 54, 56 remain unflagged**. Normal separate-values query
lines 24-27 and the normal third array value at line 41 remain unflagged.
The existing shared SQL-construction warning at line 7 is unchanged.

These examples are now development/regression material, not a fresh holdout.
Historical assessment `d2e6f965-e537-441d-92ff-7d64239e14d7` and the original
comparison document are not rewritten. The verification above used the real
full-ruleset scanner directly, not a newly submitted browser assessment.

The new exact rule ID has specific plain-language remediation explaining how to
replace raw placeholders with normal value formatting. Original scanner evidence,
severity and location remain unchanged. Guidance changes need a backend reload;
the rules file is read on each new scan. Old assessments are not updated.

Source consulted: https://github.com/vitaly-t/pg-promise#raw-text

Final checks: 226 backend tests passed (two existing dependency deprecation
warnings); all 14 authored benchmark cases matched their labels. The restarted
local backend reports healthy/connected. Changes remain local and unpushed.

## Live upload-to-report check - 2026-10-18

Started the stopped local backend; its health check returned healthy/connected.
The existing browser session recovered without entering credentials. Uploaded
the same ZIP (SHA256 `06d32219a4a9fcfaafc5f577ac7a35315c064e83d22a7385fb346860ab186440`).
Assessment `a03f571f-e194-4294-94c9-c30bea29c57f` completed in 33.2 seconds:
five raw/consolidated findings, exactly at lines 7, 30, 34, 39, 40. No finding
on the separate-values query at lines 24-27. The known misses at 47, 54, 56
remain; these results do not establish complete coverage.

Browser finding details show the new specific recommendation/action and TALGED
guidance attribution. Downloaded four-page PDF was text-checked: the same five
locations and four raw-specific recommendations. Page 3 was rendered and visually
checked for readable, unclipped advice. Source scanner descriptions are retained.
Screenshot: `tmp/ui-review/pg-raw-live-verified.png`.
Downloaded report: `C:/Users/a0995/Downloads/talged-assessment-a03f571f-e194-4294-94c9-c30bea29c57f.pdf`.
No rules, severity settings, historical assessments or access controls changed
during this verification.
