# UNiPick-driven refinements

- Combine only the two explicitly equivalent HTML-write rules at the same file and line;
  retain original raw counts and supporting rule IDs. Different locations stay separate.
- Explain HTML matches as code-review evidence rather than confirmed exploitation.
- Exclude fixed literal HTML alternatives. Unknown-source values, including button HTML
  restored from a variable, remain flagged: the scanner cannot prove they are safe.
- A complete flat `firebaseConfig` object containing apiKey, authDomain, projectId and
  appId is recognized as browser configuration. Its apiKey match stays visible as INFO.
  This is a syntax-based classification, not verification of the key or Firebase rules.
  Other secrets in or outside the object retain their normal rules and severity.
- Dependency mechanism notes distinguish zero libraries checked from supported lockfile
  coverage. Notes appear in the dashboard and HTML/PDF reports for new assessments.

Existing stored assessments are not rewritten. No fixture or frozen evaluation results
were altered. Tests cover Firebase classification, retained private-secret candidates,
overlap boundaries, and real Semgrep fixed-versus-dynamic HTML matching. The prior
UNiPick findings replay grouped 86 raw matches into 61 review items; this is not a claim
that the remaining items are confirmed vulnerabilities or that fewer matches prove safety.
