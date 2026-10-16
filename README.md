# TALGED

Repository security assessment app using FastAPI, SQLite, React, TypeScript,
and a bundled Semgrep ruleset. Accepts public GitHub URLs and ZIP archives.

## Local setup

From the repository root in PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
# Before starting: copy .env.example to .env and configure authentication below.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open the Vite URL. API documentation: `http://127.0.0.1:8000/docs`.
Semgrep must be on the server's PATH; start the server in the activated virtual
environment. Frontend configuration and checks are in
[frontend/README.md](frontend/README.md).

## Authentication setup

1. Create a Supabase project. In Authentication settings, disable **Allow new
   users to sign up** for an invite-only pilot. Keep the email provider enabled.
   See [Supabase configuration](https://supabase.com/docs/guides/auth/general-configuration).
2. Create the pilot users through the Supabase Authentication Users dashboard,
   with verified emails and passwords. Public signup and email invitation-link
   acceptance are not implemented in this UI. Administrators manage account
   creation and password resets for this pilot.
3. Copy `backend/.env.example` to `backend/.env` and set `SUPABASE_URL` plus a
   publishable key. A service-role or Supabase secret key is not needed. Add the
   approved emails to `AUTH_ALLOWED_EMAILS` (comma separated). Only verified
   emails on this list can enter the app; an empty list denies access.
4. For local HTTP use `AUTH_COOKIE_SECURE=false`, open
   `http://127.0.0.1:5173`, and keep the API at `http://127.0.0.1:8000`. Do not
   mix `localhost` and `127.0.0.1`: the session cookies require the same site.
5. For deployment use HTTPS, `AUTH_COOKIE_SECURE=true`, an explicit
   `AUTH_ALLOWED_ORIGINS`, and serve the UI and API on the same site (for example,
   `app.example.com` and `api.example.com`). Unrelated frontend/API domains are
   not supported by the cookie policy. Restart the API after configuration changes.

The backend verifies sessions against Supabase Auth. Access and rotating refresh
tokens are kept in HttpOnly, SameSite cookies, not browser storage. The frontend
refreshes an expired session before retrying a request. Logout clears local
cookies even when the provider is unavailable. Browser cookies cannot be used
to submit mutations from an unapproved Origin.

All jobs, assessment history, findings, and report downloads require a signed-in
user. A separate ownership table links assessments to the user who submitted
the job. Records from before authentication was added have no assigned owner
and are hidden from all users; they are preserved in the local database. Do
not automatically assign old results to the first person who signs in.

Sessions, invites, and password recovery are managed by Supabase; the application
database remains SQLite. Switching to another Supabase project also changes the
user identity namespace: plan an explicit ownership migration before doing so.

## Backend verification

From `backend/`, run `.\.venv\Scripts\python.exe -m pytest -q tests`.

The [MVP validation baseline](evaluation/mvp/VALIDATION.md) records expected
versus actual checks and their limits. The [scope and demo guide](evaluation/mvp/DEMO.md)
defines the frozen pilot scope and the remaining live two-account check.

## Operating limits

- ZIP uploads/downloads: 50 MB; extracted archives: 200 MB and 5,000 entries.
  Traversal paths, symlinks, encrypted entries, and special files are rejected.
- Submissions return HTTP 202 with a `job_id`. Poll
  `GET /assessments/jobs/{job_id}` for `queued`, `running`, `completed`, or
  `failed`; completed jobs include the resulting `assessment_id`.
- Two assessments run concurrently per API process. The SQLite queue accepts at
  most ten pending jobs across processes sharing the database. Excess requests
  return HTTP 503 with `Retry-After: 10`.
- Each user may have one pending assessment and five submissions in a rolling
  24-hour window. `ASSESSMENTS_PER_DAY` changes the daily limit. Quotas are
  checked atomically in SQLite and include completed and failed accepted jobs.
  User-limit responses use HTTP 429.
- Job metadata and queued work survive restarts. Uploaded archives are staged in
  `backend/assessment_jobs/` until execution finishes. Queued jobs resume after
  startup; interrupted running jobs become failed after their 60-second lease
  expires and must be submitted again. Graceful shutdown waits for active jobs.
- The frontend polls status and remembers the pending job in session storage.
  Reloading the same tab reconnects; polling errors can be retried without
  submitting a duplicate scan. Closing the tab does not cancel backend work.
  Cancellation and individual scanner progress are not implemented.
- Semgrep has a 120-second timeout. Check mechanism statuses: partial results
  do not imply that every scanner completed successfully.
- Dependency checks cover npm lockfiles with a `packages` section and query OSV.
  Older npm lockfiles and other package managers are not covered yet.
- GitHub and OSV need network access. OSV receives package names and versions.
  Temporary source cleanup is attempted after processing. Processed findings
  and assessment metadata remain in `backend/talged.db`.

## Deployment boundary

The app now supports an invite-only multi-user pilot on one server. Before
public hosting, isolate scanner workers with resource limits, enforce ingress
request-body limits, configure provider login rate limits, and define retention
and backup policies. SQLite is still used for app data and queue coordination;
horizontal deployment requires a shared database and worker/storage design.

Back up the SQLite database before schema changes. Removing temporary source
does not remove persisted findings or metadata.
