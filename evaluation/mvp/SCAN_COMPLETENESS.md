# Scan completeness and SQL refinement — 2026-10-28

The code scanner previously treated an exit code of zero as a completed check,
even when its JSON output contained parsing problems. New assessments now retain
available findings and record execution evidence separately:

- `completed`: files were reported scanned, with no reported errors, skipped files
  or skipped rules. This applies to the selected files and configured rules only.
- `partial`: scanning returned findings or results, but reported errors, skips,
  skipped rules, or missing file-coverage metadata. Zero findings is inconclusive.
- `not_run`: the scanner reported zero scanned files. This also makes the overall
  assessment partial; it is not a clean result.
- Existing execution failures and timeouts remain failures and timeouts.

Verbose JSON supplies skip information. Counts are stored on the SAST mechanism
as `coverage`, with a plain-language `note`. Existing dashboard, HTML and PDF
mechanism sections already display this note and execution status. Raw error
messages, source excerpts and temporary absolute paths are not copied into notes.
Skipped files include intentional exclusions and unsupported files; they are not
automatically vulnerabilities. A reported scanned file may still have parsing
errors. These counts do not certify that every line was analyzed.

The controlled accuracy benchmark now refuses a score for partial, empty or
unknown-coverage code checks. Existing saved assessments are not rewritten.

## Known SQL miss

The original CodeQL `tst4.js` documented in [the frozen checkpoint](FROZEN_SQL_CHECKPOINT.md)
is now detected at query line 8 by `angular-route-sqlite-query`. It is now a
development regression example, not a new independent holdout. The historical
miss remains valid evidence of the earlier ruleset.

The rule covers visible CommonJS sqlite3 imports, a `var` Database instance, and
literal `$routeParams` properties in inline function controller callbacks flowing
into SQL text. Separate SQL parameters, fixed SQL, unrelated modules, unrelated
controller inputs, and the tested shadowed bindings remain unflagged. SQL fix
guidance uses the existing parameterized-query advice.

This is bounded syntax and local flow coverage. Renamed injection parameters,
other instance declarations, imports, callback forms, local binding mutations,
cross-file flows and untested shadowing remain limitations. Controllers containing
the excluded nested shadowing patterns are conservatively excluded as a whole.
Do not claim general Angular or SQLite coverage.

## Verification

- Backend suite: 247 tests passed, with two existing dependency deprecation warnings.
- Additional focused execution: real parsing failure retained other findings and
  produced partial status; the SQL rule's eight unsafe/control examples passed.
- Original external SQL fixture: one finding at line 8, with completed execution.
- Controlled benchmark: all 14 case outcomes matched (six positives, eight negatives).
  Rules SHA256: `be01dd8d20622a27fc62b3a7b4354c8236267676974f9a9c829333c4ca7b7e8f`.
- Pinned external command recheck with Semgrep 1.176.0: ten labeled calls detected,
  seven missed, seven fixed controls unflagged. Exit 1 denotes those known misses,
  rather than scanner failure. Command coverage has not improved in this change.
- Git diff whitespace check passed. Extra dependency advisories still require review.

No fixture application or SQL was executed. These checks do not measure deployed
exploitability or overall real-world accuracy. Daily assessment limits retain the
owner's current local-testing setting until the hosting milestone.
