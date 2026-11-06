# Targeted fix advice

Added plain-language recommendations and short actions for exact known SQL,
request-to-shell, and dynamic JavaScript execution rule IDs, including the known
SQL/eval grouped findings. Both root and backend scanner ID prefixes are handled.
Other findings retain their existing guidance; no keyword guessing or automatic
code edits are performed. A raw-query warning is still a review item, not proof
that the query is injectable.

The scanner message/description, severity, location, rule IDs and evidence counts
are preserved. TALGED-authored advice is labeled `TALGED Rule Guidance`, not
attributed to the scanner. Recommendations explain what to inspect, a specific
replacement and how to check the intended behavior, without claiming an attack
was verified. Dashboard structure, severity order and detection rules are unchanged.

New assessments persist this advice in the existing recommendation/action fields,
used by the finding details and recommendation exports. Historical records are
not rewritten. Run a new assessment to receive the updated advice.

Sources checked 2026-10-17:

- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://nodejs.org/api/child_process.html
- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval

Verification: 32 focused enrichment/report tests passed. Exact-ID mapping,
backend prefixes, unmodified input/evidence, guidance attribution and unrelated
rule/category fallback are covered. No live exploitation or browser visual
verification was performed for this backend-only change.
