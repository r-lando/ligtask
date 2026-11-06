# Koa-to-Sequelize SQL flow refinement - 2026-10-19

## Cause and change

The pinned CodeQL Koa example reads a destructured value from `ctx.query`, pushes
an interpolated condition into an array, joins that array into SQL and passes it
to `new Sequelize().query` at line 17. Existing Express-style source patterns do
not establish this Koa callback source; following mutation of the condition array
also requires an explicit taint propagator in the targeted rule.

Added `koa-request-sequelize-query`, scoped to visible CommonJS `koa-router`
initialization and an inline `new Router(...).get/post/put/patch/delete/all`
arrow callback. Sources are that context's query or request body. A `push`
propagator carries the input into the list, after which normal propagation can
follow the join/template. Sinks are query text passed to a visible, imported
Sequelize constructor or a directly assigned instance. The values/options
argument is not a sink, so ordinary bind/replacements do not trigger this rule.

The finding uses the existing SQL-specific fix guidance and preserves evidence,
location and severity handling. It describes a potential unsafe flow, not a
successful attack. The example's alphanumeric check is not treated as proof that
unquoted SQL interpolation is safe. No exploit or fixture application was run.

## Safe controls and limits

Real engine controls cover fixed conditions, untouched fixed queries, separate
bind/replacement values, cleared arrays, unrelated router/database modules,
constructor shadowing and named/assigned-arrow context shadowing. Positive cases
cover direct input, instance queries, destructured pushed input, and input checked
by an alphanumeric expression before string construction. Labels were not changed
to make a failed implementation pass.

This is not general Koa or cross-function analysis. ESM imports, saved router
instances, arbitrary middleware registration, async/other callback shapes,
arbitrary aliases/reassignments and all shadowing forms are not guaranteed.
The `push` propagator is a conservative syntactic model within this rule, not
proof that every method named push mutates a real array. Input validation and
deployment applicability still require review; no zero-error claim is made.

## External reference

CodeQL revision `ff3231c5ac4779befd8c8690bb04f447fc6a8d13`, file
`javascript/ql/test/query-tests/Security/CWE-089/untyped/koarouter.js`.
Source SHA256 `2698db29e61b26a1f1ed7c31bfb18e298c27ac65e31f2ccdd64d79c141ee70b8`.
Original annotation and adjacent `SqlInjection.expected` diagnostic agree on
line 17. The previous no-findings observation remains in
PG_OPEN_VALUE_REFINEMENT.md; no historical assessment or label is rewritten.
Because this case was now used for development, it is a regression example,
not a fresh holdout or overall accuracy estimate.

Final direct full-ruleset rerun succeeded and returned exactly one finding at
line 17: `koa-request-sequelize-query`. The authored 14-case benchmark still
matched every expected label. Rules SHA256:
`a67180ec4fb5f03431c0be30deefbcee29840437f77a89c90eecfe8aa200bded`.
The stopped local backend was started with the new guidance; health returned
healthy/connected. No browser assessment was submitted during this change.
Existing reports are unchanged; a fresh scan is needed to see the Koa warning.
All 232 backend tests passed (two existing dependency deprecation warnings).
Changes remain local and unpushed.

## Live upload-to-report check - 2026-10-19

ZIP `tmp/external-sql/koa-live-verification.zip` contains unchanged `koarouter.js`,
upstream MIT LICENSE and a separate authored `koa-safe-control.js` using bind
values. ZIP SHA256:
`cd6c24dc50e4dbd60e126599b87005388083794e16fdff603a5d8060c3aef391`.
Assessment `98de863e-f570-481a-a356-e0a963be87da` completed in 33.1 seconds:
one raw/consolidated HIGH finding at `koarouter.js:17`, no warning in the
safe-control file. Dependencies correctly Not checked without a lockfile.

Browser detail verified the SQL-specific recommendation, action and TALGED
guidance attribution. The downloaded three-page PDF contains the same location
and advice; page 3 was rendered and visually checked for legible, unclipped text.
Screenshot: `tmp/ui-review/koa-live-verified.png`.
Downloaded PDF:
`C:/Users/a0995/Downloads/talged-assessment-98de863e-f570-481a-a356-e0a963be87da.pdf`.
The initial browser connection failure required starting the stopped frontend
and the user reopening TALGED; no access controls or credentials changed.
No detection rules changed during this live check.

References consulted:

- https://koajs.com/#request-query
- https://sequelize.org/docs/v6/core-concepts/raw-queries/
- https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/advanced
