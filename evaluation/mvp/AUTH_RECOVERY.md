# Authentication outage recovery — 2026-10-16

Observed: the local API/database were healthy, while Supabase health and user requests intermittently timed out after 10 seconds. The management API reported the project `ACTIVE_HEALTHY`; this does not establish the cause of individual request failures. A completed DVNA job remained saved while the UI incorrectly displayed assessment failure.

Changes:

- Authentication GET requests retry at most once on transport errors or upstream 5xx. No stale authorization cache, token verification bypass, or ownership change was introduced. POST login/refresh operations are never automatically replayed by this change; 401 and 429 are not retried.
- Logs include only transport exception class, not request headers, tokens, payloads, or exception messages.
- An error with a retained pending job shows “Connection interrupted” and “Reconnect to assessment,” not a claim that the scan failed. The retry reuses the existing job.
- Initial session-check outages offer “Check connection again” without requiring another password submission.

Verification: 26 authentication/ownership tests and 21 frontend tests passed; frontend build/lint passed. Tests cover bounded retry, no POST replay, no retry on authentication rejection/rate limiting, preservation of a pending job on 503, and resuming that job without submission. Restarted only the verified local API after confirming zero active jobs. Live provider health and browser session checks subsequently succeeded. This improves recovery, but does not guarantee availability or establish/fix the underlying external network/provider cause.
