# Cookie defaults and coverage labels — 2026-10-16

Verified against the official [express-session](https://expressjs.com/en/resources/middleware/session/) and [cookie-session](https://expressjs.com/en/resources/middleware/cookie-session/) documentation.

- Removed rules that treated absent cookie domain, path, or expiry as standalone vulnerabilities. These omissions can represent valid host-only/default-path/nonpersistent behavior.
- Replaced the absent-httpOnly warning with explicit-disabled checks. express-session cookie properties are nested under `cookie`; cookie-session properties are top-level.
- Explicit `httpOnly: false` and `secure: false` remain warnings. Literal options and directly assigned options objects are covered. Dynamic configuration, later mutation, spreads, and cross-file settings are not fully resolved; findings still require review.
- Default-name and missing explicit express-session secure configuration are INFO observations, not vulnerability claims. No missing-secure observation is inferred for cookie-session, whose defaults differ. These changes are bounded to CommonJS imports recognized by the rules, not a general JavaScript configuration evaluator.
- HTML and PDF use the same coverage-label helper: a completed dependency mechanism with the persisted “No software libraries were checked.” note displays “Not checked.” Zero findings alone is not treated as absent coverage; failures/partial statuses remain visible.

Verification: 179 backend tests passed, including real-engine positive/negative cookie cases and HTML/PDF table-label assertions. Historical finding records and existing downloaded PDFs are unchanged. New scans use corrected cookie rules; newly generated exports use corrected coverage labels.

The separate path-traversal audit warning discussed in the DVNA review is not changed by this pass.
