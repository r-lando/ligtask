# MVP validation baseline

Validation date: 16 October 2026 (Asia/Manila).

Result: automated MVP acceptance checks passed. A real-scanner clean baseline
also passed. This is a controlled local pilot baseline, not a public-deployment
security certification or a new formal accuracy benchmark.

## Expected versus actual

| Scenario | Expected | Actual | Evidence / boundary |
| --- | --- | --- | --- |
| Two user identities | Each sees only their own history, jobs, results and reports | Passed; foreign IDs return 404, history/counts exclude other users | `test_auth_and_ownership.py`; provider responses are simulated |
| End-to-end ownership | Submitted ZIP result belongs to submitter; second user cannot read job/result/reports | Passed through actual queue, persistence and report generation | `test_timeout_preserves_results_reports_and_user_isolation`; only Semgrep timeout and provider responses simulated |
| Clean static web fixture | Completed; zero findings | Completed; zero findings; 28.320 seconds | Real production pipeline, bundled local Semgrep rules, no saved assessment |
| Invalid ZIP bytes with .zip extension | Accepted job becomes failed; archive removed; no assessment saved | Passed | `test_invalid_zip_fails_as_job_and_cleans_up` |
| Upload of 50 MB + 1 byte | HTTP 413; staged file and reservation removed | Passed using actual configured upload limit | `test_real_50mb_upload_boundary_returns_413_and_releases_job` |
| Scanner timeout | SAST timed out; other findings survive; assessment is partial | Passed; three Docker configuration findings persisted; owner can export HTML/PDF | `test_timeout_preserves_results_reports_and_user_isolation`; timeout deliberately simulated, not a 120-second wait |
| One active scan per user | Atomic admission; second scan rejected, another user unaffected | Passed | Concurrent service-level quota test |
| Five submissions per rolling day | Both ZIP and GitHub endpoints return 429 after quota | Passed; no extra job created | `test_daily_quota_is_enforced_on_both_submission_endpoints` |
| Daily quota expiry | Failed/completed jobs count; slots become available after 24 hours | Passed with controlled timestamps | Service-level quota test |
| Interrupted worker | Expired running jobs fail; queued and live jobs remain | Passed | Controlled lease timestamps; not a forced live-server crash |
| Session handling | Cookie credentials, refresh/retry, logout abort, account separation | Passed | Frontend service tests; browser/provider sessions are not exercised live |
| Severity mapping | ERROR becomes HIGH; WARNING becomes MEDIUM; INFO remains INFO | Passed; CVSS remains unset when not provided | Finding-normalizer tests |
| Report limits note | Exploitability limitation present in reports | HTML regression passed; prior PDF extraction/render check passed | Report tests plus preceding PDF QA |

## Recorded checks

- Backend: **132 passed**, two upstream deprecation warnings, 9.69 seconds.
- Frontend service tests: **10 passed**.
- Frontend type check and production build: **passed**.
- Frontend lint: **passed**.
- Real clean scan: **passed**, four mechanisms returned completed and zero findings.

Machine-readable local evidence is in the ignored `evaluation/results/mvp/`:
`backend-tests.xml` and `clean-scan.json`. Test data uses temporary databases;
validation does not alter pilot accounts, quotas, or live assessment history.

The clean fixture has no third-party packages and no supported configuration
files. OSV and configuration mechanisms therefore have nothing to evaluate;
their zero counts are not evidence of advisory accuracy or configuration
coverage. A zero-finding static fixture cannot establish a false-positive rate.
Keep the existing controlled evaluations under `evaluation/` separate.

## Previous live sample observation

The user-provided `test-web-app - Copy.zip` assessment
`829abf48-a70a-46aa-bf47-83733b664495` completed with 21 findings:
1 critical, 6 high, 5 medium, 7 low, 1 informational, 1 unknown.
The previous review checked the archive and all 15 reported dependency matches
against OSV. SQL severity and the report note were verified in the exported PDF.
That observation is not a newly rerun scan in this validation batch and does
not prove all findings are reachable or exploitable.

## Reproduce

From the project root in PowerShell:

```powershell
$env:PATH = "$PWD\backend\.venv\Scripts;" + $env:PATH
.\backend\.venv\Scripts\python.exe evaluation/mvp/run_clean_scan.py
```

From `backend/`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests --junitxml=../evaluation/results/mvp/backend-tests.xml
```

From `frontend/`, run `npm test`, `npm run lint`, and `npm run build`.
These commands regenerate their local evidence and may report different timings.

## Remaining live check

Two real Supabase/browser accounts have not been tested against each other.
The isolation checks above verify the application using controlled provider
responses. Complete the two-account sequence in `DEMO.md` before calling live
multi-user acceptance complete. Do not share passwords in chat or create test
users automatically in the production provider.
