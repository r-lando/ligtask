# Formal Dependency Assessment Results

## Evaluation Scope

This controlled evaluation examined TALGED's dependency assessment mechanism for npm dependencies represented by exact package and version information in `package-lock.json`.

The frozen dataset consisted of 10 dependency cases. Ground truth was collected independently from the OSV `/v1/query` endpoint before the formal TALGED execution. The frozen ground truth classified 7 cases as vulnerable and 3 cases as non-vulnerable.

TALGED's production dependency assessment implementation was then executed against each frozen fixture using its normal dependency collection, OSV batch-query, vulnerability-detail retrieval, and finding-generation workflow.

## Formal Execution

- Execution timestamp: 2026-09-04T11:34:16.289664+00:00
- Total cases: 10
- Vulnerable ground-truth cases: 7
- Non-vulnerable ground-truth cases: 3
- Completed scans: 10
- Scans with request errors: 0
- Total dependency-assessment processing time: 21.522835 seconds

## Case-Level Results

| Measure | Result |
| --- | ---: |
| True Positives (TP) | 7 |
| False Negatives (FN) | 0 |
| True Negatives (TN) | 3 |
| Cases Requiring Adjudication | 0 |
| Case-Level Recall | 1.0000 |
| OSV-ID Recall | 1.0000 |
| Unexpected Unique OSV IDs | 0 |

All seven dependency cases classified as vulnerable in the frozen ground truth produced at least one expected OSV vulnerability identifier. All three non-vulnerable control cases produced no vulnerability findings.

The formal execution also reproduced all expected OSV vulnerability identifiers from the frozen ground truth. No expected identifiers were missed and no unexpected identifiers were observed during the formal run.

## Per-Case Execution

| Case | Package | Version | Findings | Classification | Processing Time (s) |
| --- | --- | ---: | ---: | --- | ---: |
| DEP-001 | lodash | 4.17.15 | 6 | TP | 2.019140 |
| DEP-002 | minimist | 0.0.8 | 2 | TP | 0.970131 |
| DEP-003 | axios | 0.21.1 | 24 | TP | 6.562847 |
| DEP-004 | express | 4.17.1 | 2 | TP | 0.889092 |
| DEP-005 | jsonwebtoken | 8.5.1 | 3 | TP | 1.102077 |
| DEP-006 | lodash | 4.17.21 | 3 | TP | 1.153903 |
| DEP-007 | minimist | 1.2.8 | 0 | TN | 0.416708 |
| DEP-008 | axios | 1.12.2 | 28 | TP | 7.646122 |
| DEP-009 | express | 5.1.0 | 0 | TN | 0.365705 |
| DEP-010 | jsonwebtoken | 9.0.2 | 0 | TN | 0.397110 |

Each fixture contained one dependency for evaluation. The number of findings therefore represents OSV vulnerability records associated with the tested package/version and must not be interpreted as the number of vulnerable packages.

## Formal Result Artifact

The raw formal result is stored locally at:

`evaluation/dependency/results/formal-results.json`

SHA-256:

`FF8975CA4E8DBAA40AC91C446207DCA60FD878103A976A0BE06F0BF728C4FF24`

The raw result directory is excluded from Git. This document preserves the principal formal measurements and the cryptographic hash of the original result artifact.

## Interpretation and Limitation

The formal result demonstrates complete detection of the expected vulnerabilities within this frozen 10-case controlled npm/OSV dataset. It must not be interpreted as evidence that TALGED achieves 100% vulnerability-detection accuracy across arbitrary repositories, dependency ecosystems, or vulnerability classes.

The evaluated implementation scope is limited to npm dependencies extracted from `package-lock.json` and assessed through exact package/version matching against OSV. Because OSV is a continuously updated vulnerability database, results obtained at another time may differ as vulnerability records are added, modified, or withdrawn.
