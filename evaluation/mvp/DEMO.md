# Frozen MVP scope and demo

## MVP boundary

The MVP is an invite-only repository security assessment platform on one server.
Its accepted features are email/password sign-in, private user-owned assessments,
public GitHub or ZIP input, a bounded background queue, rule-based source checks,
npm dependency advisory matches, potential-secret and Docker configuration
checks, findings/history, and HTML/PDF exports with a limitations note.

Validation and defect fixes remain in scope. New feature work is deferred until
the acceptance baseline is complete. This boundary does not change the existing
formal benchmark methodology or claim that findings are proven exploits.

Deferred features: teams, roles, billing, public signup, automated secret
verification, exploitability/reachability analysis, private repositories,
additional package managers, cancellation, live per-scanner progress, public
hosting, and a PostgreSQL/storage migration.

## Short demo

1. Start the backend and frontend using the root README. Open
   `http://127.0.0.1:5173`; sign in with an approved, verified account.
2. Start an assessment and upload a small ZIP. Explain queued/running status.
3. On completion, check mechanism statuses before interpreting the findings.
4. Open one finding: show file/line, severity, explanation and recommended action.
5. Explain that dependency matches identify affected locked versions and that
   informational observations do not establish exploitable vulnerabilities.
6. Download HTML and PDF reports. Point out the limitation note.
7. Open History and reopen the result to demonstrate persistence.
8. Run the clean fixture to show that the scanner can return zero findings.

The checked-in clean fixture is `fixtures/clean-web`. To package it from the
repository root:

```powershell
Compress-Archive -Path evaluation/mvp/fixtures/clean-web -DestinationPath clean-web-demo.zip
```

Use a new output name if that ZIP already exists. No install or execution of the
fixture is needed: TALGED analyzes its source files.

## Live two-account acceptance

The 16 October 2026 local pilot check is complete and recorded in
`VALIDATION.md`. With both caller identities confirmed, foreign assessment,
HTML/PDF report and job-status requests returned 404 in both directions.
After sign-out, protected assessment and job requests returned 401. History
separation was also reported by the user. Repeat this sequence when changing
authentication or ownership behavior.

An administrator must create a second verified Supabase account and add its
email to `AUTH_ALLOWED_EMAILS`, then restart the backend when scans are idle.
Use two separate browser profiles/private sessions to prevent session cookies
from being shared. Do not use merely two tabs in the same browser session.
Before each cross-user request, open `/auth/me` on port 8000 in that same session
and confirm it identifies the intended caller rather than the assessment owner.

1. User A scans a repository and notes its assessment ID and job ID.
2. User B signs in separately. User A's result must not appear in B's history.
3. In B's session, test the API GET URLs for A's assessment, job, HTML report,
   and PDF report. Every request must return 404. The app uses cookies, so the
   browser session making the request matters.
4. User B creates a scan and verifies that A cannot access it, in the same way.
5. Sign out of B. Protected API requests must now return 401.

API URLs are `/assessments/{id}`, `/assessments/jobs/{job_id}`,
`/assessments/{id}/report`, and `/assessments/{id}/report.pdf` on port 8000.
Do not paste or forward authenticated cookies, refresh tokens, or passwords.

## Pilot limitations

- Scanner processes still run on the application host without container isolation.
  Keep the pilot restricted to trusted participants; public hosting is deferred.
- App data and queue use SQLite and local disk, not a horizontally deployed backend.
- Individual scanner timeouts do not provide an overall job deadline. OSV detail
  requests are sequential and can make large vulnerable repositories slow.
- Zero findings is limited to supported rules/files and successfully completed
  mechanisms. Parser errors/skipped targets require separate scrutiny.
- Provider availability affects authentication. Local HTTP cookies are only for
  development; deployment requires HTTPS and the documented same-site setup.
- Account creation, invitation acceptance and password recovery are administrator
  managed. No public registration flow is included in this MVP.
- Source cleanup is attempted; retention, stale temporary-file cleanup, backups
  and deployment-wide resource limits still need operational policies.
- Rolling daily quotas also count accepted failed scans. Use a small demo set to
  avoid exhausting the pilot user's allowance.
