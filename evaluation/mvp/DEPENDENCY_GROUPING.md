# Dependency occurrence grouping

Dependency findings are combined only when advisory ID, package name, version,
ecosystem, and lockfile path match exactly. Incomplete identities are not combined.
Case-distinct paths remain separate. The original advisory ID, package metadata,
scanner provenance and selected original severity/CVSS are retained. Evidence count
records occurrences; repeated copies do not establish greater exploitability.

Read-only replay of NodeGoat assessment 9759a079-899d-4084-961f-1ef082c6da4c:
465 raw findings -> 339 review items; 446 dependency occurrences -> 320 dependency
items. 126 repeated matches combined across 51 groups. Stored assessment unchanged.
163 backend regression tests passed. No advisory or affected version was suppressed.
