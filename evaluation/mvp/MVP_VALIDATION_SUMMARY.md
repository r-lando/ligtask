# MVP validation checkpoint — 2026-10-19

TALGED identifies specific risky source-code patterns. A warning is evidence to
review, not proof that an attacker can exploit a deployed application. No findings
does not mean an application is secure. This checkpoint is not a release approval
or an overall accuracy score.

## Evidence collected

| Check | Observed result | Interpretation |
| --- | --- | --- |
| Authored regression benchmark | All 14 expected case outcomes matched (6 positive, 8 negative). | Development tests, not independent real-world accuracy. |
| Pinned external command examples | 10 of 17 labeled risky calls warned; 7 reviewed controls unflagged. | Seven known misses remain. Warnings are not exploit proofs. |
| External MySQL examples | Two expected risky locations detected; separate-values control unflagged. | Small, specific check only. |
| pg-promise development examples | Eight warnings: one shared construction and seven raw/open-value locations. | Tuned regression evidence; upstream sink labels use a different counting unit. |
| Koa/Sequelize development example | Expected query at line 17 detected; authored safe controls tested. | Narrow CommonJS route pattern, not general Koa coverage. |
| Fresh frozen node-postgres example | Risky construction at line 8 warned; expected query call is line 9. Parameterized control unflagged. | Construction recognized, not a complete sink trace. |
| Fresh frozen Angular/sqlite3 example | Expected issue at line 8 missed despite successful scan. | Known coverage gap, not a safe result. |

External SQL source revision: `github/codeql` at
`ff3231c5ac4779befd8c8690bb04f447fc6a8d13`. Frozen rules SHA256:
`a67180ec4fb5f03431c0be30deefbcee29840437f77a89c90eecfe8aa200bded`.
Recorded scanner version: Semgrep 1.176.0. Sources were scanned statically; fixture
applications and their dependencies were not executed or installed.

The isolated staged-tree benchmark also matched all 14 expectations. Its raw-byte
rules digest is `73579bac244c227fd4a783e67e6c3c5ba52625f5d9ea17dd9740de8d2c367656`.
Git exports LF line endings, whereas the earlier Windows working-tree checkpoint
used mixed checkout line endings; this digest is byte-sensitive. The historical
digest above identifies the original checkpoint, not a portable semantic hash.

The Koa upload, finding details and downloaded PDF were also checked locally:
assessment `98de863e-f570-481a-a356-e0a963be87da` retained one finding at line 17
and its specific fix advice. This is workflow evidence, not independent accuracy
measurement. The latest eight-warning pg-promise result is a direct scanner check,
not a claim that all eight were reverified through the live PDF workflow.

## Improvements covered by this checkpoint

- More specific SQL and shell-input patterns, with positive and safe controls.
- Fewer warnings for valid cookie defaults and fixed/local path values.
- Narrow recognition of direct DOMPurify use; not blanket trust of sanitizers.
- Grouping only matching known SQL/eval evidence with strict location checks.
- Plain, rule-specific fix advice while preserving original scanner evidence.

These changes do not establish complete cross-file data flow, deployed
reachability, business-logic or authorization coverage. Parser errors and skipped
files must not be interpreted as checked-safe code.

## Open issues and scope decisions

1. Keep the seven external command misses visible; see [external validation](EXTERNAL_VALIDATION.md).
2. Keep Angular/sqlite3 in the miss ledger. Decide its MVP support scope explicitly
   before adding rules; do not silently exclude it or label it safe.
3. Dependency checks found all 45 previously expected advisory IDs in ten cases,
   but four additional IDs still need review. Live advisory data changes, and
   package presence does not establish exploitability. See [benchmark details](ACCURACY_BENCHMARK.md).
4. Do not infer dependency coverage when no supported lockfile was checked.
5. Preserve the dashboard and high-to-low severity order. Explain evidence and
   limitations without turning the finding total into a security score.

## Reproduce and release boundary

Run backend tests and `evaluation/mvp/run_accuracy_benchmark.py` using the backend
environment. The external runner fetches pinned public fixtures and deliberately
reports remaining misses; network or scan failure is not a passing result.
See [frozen SQL evidence](FROZEN_SQL_CHECKPOINT.md),
[Koa evidence](KOA_SQL_REFINEMENT.md), and
[targeted guidance](TARGETED_FIX_GUIDANCE.md) for exact methods and limits.

Authentication recovery, UI changes and Git-commit provenance are separate local
work and are not bundled into this scanner checkpoint. Before hosting, complete
the [release checklist](RELEASE_CHECKLIST.md), including restoring and testing a
positive daily assessment limit. The owner requested that the local limit remain
disabled until the hosting milestone; this checkpoint does not change it.
