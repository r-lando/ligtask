# MVP precision update

This update changes the production ruleset after the original MVP validation.
Historical assessment counts and formal evaluation results are not rewritten.

- File-context labels are deterministic path hints, not deployment or exploitability judgments.
  Findings in tests, fixtures, evaluation scripts, and scanner rules remain visible and
  included in severity totals. Separate context totals are provided in detail/API and reports.
- Generic secret matching ignores Python annotation-only declarations while retaining
  literal defaults (`str` / `SecretStr`) and quoted mapping values.
- The XML import audit excludes `from xml.sax.saxutils import escape`, not parser imports.
- The broad subprocess audit remains enabled but is informational and explicitly requires
  manual review. It does not establish command injection or advise shell escaping for argv lists.
- Frontend source-map-js lockfile version updated from 1.2.1 to 1.2.2.

Verification: 151 backend tests (including a real Semgrep XML regression), 10 frontend
tests, frontend lint/typecheck/production build passed. Evaluation fixtures unchanged.
The 15-case secret evaluation was rerun separately: TP 5, FP 0, FN 0, TN 10;
privacy checks 5/5. This small synthetic dataset does not establish general accuracy.
Frozen formal results were preserved. Other formal datasets were not rerun.

Follow-up: generic secret matching now requires complete quoted literals in source
code. Bare values are supported only in recognized config/text files, not runtime
identifiers or calls. Regression coverage includes the two runtime-expression false
positives from assessment 57fa9697-24dc-4cfc-beeb-f74ca2d74b15. A direct secret scan
of backend/app completed with zero matches. Detection remains heuristic; unsupported
literal formats and multiline values can still be missed.
