# Scanned Git commit provenance

GitHub assessments now resolve the default branch to a full validated 40-character commit SHA before downloading. The archive URL uses that SHA, not a moving branch ref. Failure to resolve a valid SHA stops retrieval; no fallback to an unpinned branch archive is allowed.

Stored metadata contains the commit SHA, branch name at resolution, canonical repository URL, and SHA-256 of the downloaded archive bytes. No repository source contents are retained by this feature. The archive hash identifies those bytes; it is not Git's tree hash or a guarantee that ZIP serialization will remain identical forever.

The worker passes this metadata through finalization into the assessment transaction. An additive SQLite column (`source_revision_json`) preserves older rows. Results/history APIs return it; the results UI and HTML/PDF exports display the full commit and branch. Legacy GitHub assessments display “Not recorded (older assessment).” ZIP uploads do not receive an inferred Git commit. Saved legacy records are not backfilled from today's branch state.

Tests cover branch-name encoding, immutable archive URLs, invalid/non-200 commit-resolution responses, no unpinned fallback, idempotent legacy migration, metadata persistence, PDF metadata cells, HTML escaping, and the results UI's legacy label.

Live read-only retrieval on 2026-10-17 resolved public `appsecco/dvna` master to `9ba473add536f66ac9007966acb2a775dd31277a`, downloaded 3,161,179 bytes by that commit, and computed archive SHA-256 `f2bcbf24b2fbbbf6c854734b8bd280feaaaee68059edbcd322b409d0157384e6`. No assessment or user record was created by this check.

This pins source input, not the entire analysis environment. Advisory databases, rule revisions, and scanner versions can still change between runs. It does not pin submodule or external runtime content.

Verification: 196 backend tests and 22 frontend tests passed; frontend build and lint passed. Local API startup applied the additive migration and the API/database health check succeeded. The existing browser session reconnected successfully. No new assessment was submitted as part of verification.

Visual-verification limitation: the browser initially retained an older cached frontend. Its subsequent reload/navigation failed at the browser error-page URL policy. The frontend dev server was started, but the new commit line was not visually verified in this pass; automated UI source checks and report metadata tests passed. Do not treat the earlier cached screen as proof of the new display.
