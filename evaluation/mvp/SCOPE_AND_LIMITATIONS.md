# Frozen MVP scope

TALGED scans submitted web-application repository source, not live websites.
The dashboard and Critical-to-Info order remain unchanged. Findings are review
items supported by rule matches or dependency advisories, not a security score.

## Supported checks

- Frozen local Semgrep rules for source-code patterns.
- OSV advisory matching for installed npm versions in package-lock.json.
- Pattern-based secret detection; detected values are omitted from findings.
- Selected Dockerfile configuration checks.
- Explicit grouping with supporting rule IDs and occurrence counts retained.

## Limits

- No proof of exploitability, runtime testing, or guarantee of complete coverage.
- Python and other non-npm dependency formats are not checked by OSV integration.
- Framework evidence and file-context labels are heuristics, not deployment facts.
- Firebase browser configuration remains visible as an informational access-setting
  check; remote restrictions are not verified. Ambiguous multi-secret lines retain
  normal secret severity rather than risk downgrading another credential.
- Unknown-source HTML remains flagged; safe code may still produce warnings.
- External services can fail. Incomplete mechanisms must not be read as a clean scan.
- Existing reports are historical snapshots; new rules require a new assessment.

## Release review

PR #3 review found and corrected same-line Firebase/private-password downgrading.
Grouping boundaries and unsafe HTML examples are covered by regression tests.
Independent NodeGoat/UNiPick scans demonstrate selected behaviors, not an overall
accuracy percentage. Larger calibrated evaluation is future work, not a release claim.
