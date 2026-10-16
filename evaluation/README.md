# TALGED Technical Evaluation

## Controlled SAST Benchmark

Benchmark: OWASP Benchmark for Java
Benchmark Version: 1.2
Benchmark Commit: 51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661
Ground Truth: expectedresults-1.2.csv
Total Cases: 2740
Vulnerable Cases: 1415
Non-Vulnerable Cases: 1325

## Semgrep Environment

\## Semgrep Environment

Semgrep Version: 1.176.0

Engine: OSS

Formal SAST Configuration: Pinned Semgrep Community Rules

Rules Repository: semgrep/semgrep-rules

Rules Commit: 40b8c63f75dc7c22c8a77482d73bfb864b146f7e

Rules Path: java/lang/security/

Validated Rules: 86

Configuration Validation Errors: 0



The formal controlled SAST evaluation uses the complete Java

security rule tree from the pinned Semgrep Community Rules

snapshot identified above. The complete security rule tree is

used rather than selecting individual rules based on benchmark

results.



Before the formal evaluation configuration was frozen, TALGED

used Semgrep with the `auto` configuration. An applicability

dry run was performed only to determine whether the OWASP

Benchmark vulnerability categories were represented by the

SAST rules available to the platform. The dry-run findings are

not used as formal benchmark results.



The `auto` configuration resolved to 1074 rules using Semgrep

1.176.0 and the OSS engine at the time of the applicability

check. Because `auto` obtains rules dynamically from the

Semgrep Registry, it is not used as the fixed configuration for

formal benchmark scoring.



Resolved Auto-Configuration Dump SHA-256:

E8F32FEEF7B28B543E1EBD74D2E2DB75BDFF8E00BF0A0A34E9C2A6F64E604B5C



Applicability Dry-Run Output SHA-256:

1E7D69452D752AAF413A607046527BBB3DF476D3653ED0411FCAFD2DCFB93FB6In-Scope Benchmark Categories

* CWE-22: Path Traversal
* CWE-78: Command Injection
* CWE-79: Cross-Site Scripting
* CWE-89: SQL Injection
* CWE-90: LDAP Injection
* CWE-327: Broken or Risky Cryptographic Algorithm
* CWE-328: Reversible One-Way Hash
* CWE-330: Insufficiently Random Values
* CWE-501: Trust Boundary Violation
* CWE-614: Sensitive Cookie Without Secure Attribute
* CWE-643: XPath Injection

All 2740 benchmark cases are included in the controlled SAST
evaluation scope.

## Ground-Truth Classification

The OWASP Benchmark expected-results file is treated as the
ground truth for the controlled SAST evaluation.

True Positive (TP):
A benchmark case classified as vulnerable for which the SAST
component reports a corresponding finding for the benchmark
vulnerability category.

False Negative (FN):
A benchmark case classified as vulnerable for which the SAST
component does not report a corresponding finding for the
benchmark vulnerability category.

False Positive (FP):
A benchmark case classified as non-vulnerable for which the
SAST component reports a corresponding finding for the
benchmark vulnerability category.

True Negative (TN):
A benchmark case classified as non-vulnerable for which the
SAST component does not report a corresponding finding for
the benchmark vulnerability category.

Findings unrelated to the benchmark vulnerability category
assigned to a test case are not treated as successful
detections of that benchmark case.

## SAST Finding-to-Benchmark Mapping

Formal scoring is performed at the benchmark test-case level.
A Semgrep finding counts as detection of a benchmark case only
when the finding occurs in that benchmark test file and its
security category corresponds to the vulnerability category
assigned to that case by the OWASP Benchmark ground truth.

The following benchmark-category mapping is used:

- CWE-22 findings -> pathtraver
- CWE-78 findings -> cmdi
- CWE-79 findings -> xss
- CWE-89 findings -> sqli
- CWE-90 findings -> ldapi
- CWE-326 DES/3DES findings -> crypto
- CWE-327 findings -> crypto
- CWE-328 findings -> hash
- CWE-330 findings -> weakrand
- CWE-501 findings -> trustbound
- CWE-614 findings -> securecookie
- CWE-643 findings -> xpathi

The OWASP Benchmark classifies its crypto test cases as
CWE-327. The pinned Semgrep rules classify detected DES and
3DES usage as CWE-326. Because these rules identify the
insecure cryptographic behavior exercised by the benchmark's
crypto test cases, their findings are mapped to the benchmark
crypto category for test-case scoring. This is a
benchmark-category mapping and does not treat CWE-326 and
CWE-327 as generally interchangeable.

Multiple corresponding Semgrep findings within the same
benchmark test case count as one detected case. Findings in a
benchmark test file that do not correspond to that file's
assigned benchmark category do not count as detection of the
case.

## Evaluation Integrity

The benchmark source code and expected-results file must not
be modified to improve detection performance.

The benchmark scope and classification criteria were defined
before the formal benchmark results were examined.

Raw assessment output must be preserved separately from
processed evaluation summaries.

Scanner warnings, skipped files, timeouts, and other execution
limitations must be recorded with the evaluation results.

The OWASP Benchmark evaluates the SAST component of TALGED.
Dependency assessment, secret detection, and configuration
assessment require separate controlled evaluation datasets.
## Formal OWASP Benchmark SAST Results

The formal controlled SAST evaluation was performed using the
previously frozen methodology, finding-to-benchmark mapping,
and deterministic scoring procedure.

### Execution Summary

- Benchmark cases: 2,740
- Vulnerable cases: 1,415
- Non-vulnerable cases: 1,325
- Semgrep version: 1.176.0
- Semgrep engine: OSS
- Validated security rules: 86
- Java rules executed: 82
- Target files scanned: 2,740
- Raw Semgrep findings: 2,404
- Semgrep errors: 0
- Skipped targets: 0
- Formal scan wall-clock time: 44.5041788 seconds

### Overall Case-Level Results

- True positives (TP): 1,248
- False positives (FP): 552
- False negatives (FN): 167
- True negatives (TN): 773
- Precision: 0.6933
- Recall: 0.8820
- False-positive rate: 0.4166
- Accuracy: 0.7376
- F1 score: 0.7764

The 2,404 raw Semgrep findings must not be interpreted as
2,404 detected vulnerabilities. After category-aware
benchmark matching, 2,258 raw findings corresponded to the
assigned vulnerability categories of benchmark cases. These
findings covered 1,800 distinct benchmark cases, consisting
of 1,248 true-positive cases and 552 false-positive cases.
An additional 146 raw findings were unrelated to the
benchmark category assigned to the files in which they
occurred.

### Per-Category Results

| Category | Cases | TP | FP | FN | TN | Precision | Recall | FPR | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| pathtraver | 268 | 120 | 106 | 13 | 29 | 0.5310 | 0.9023 | 0.7852 | 0.6685 |
| cmdi | 251 | 117 | 109 | 9 | 16 | 0.5177 | 0.9286 | 0.8720 | 0.6648 |
| xss | 455 | 202 | 108 | 44 | 101 | 0.6516 | 0.8211 | 0.5167 | 0.7266 |
| sqli | 504 | 253 | 170 | 19 | 62 | 0.5981 | 0.9301 | 0.7328 | 0.7281 |
| ldapi | 59 | 26 | 28 | 1 | 4 | 0.4815 | 0.9630 | 0.8750 | 0.6420 |
| crypto | 246 | 130 | 0 | 0 | 116 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| hash | 236 | 89 | 0 | 40 | 107 | 1.0000 | 0.6899 | 0.0000 | 0.8165 |
| weakrand | 493 | 218 | 0 | 0 | 275 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| trustbound | 126 | 43 | 18 | 40 | 25 | 0.7049 | 0.5181 | 0.4186 | 0.5972 |
| securecookie | 67 | 36 | 0 | 0 | 31 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| xpathi | 35 | 14 | 13 | 1 | 7 | 0.5185 | 0.9333 | 0.6500 | 0.6667 |

### Artifact Integrity

Formal raw Semgrep output:

`evaluation/results/owasp-semgrep-formal.json`

SHA-256:

`146851B230C84B05267E5391BE509170C6A7E0EBB8E133A99EB6795CB623774F`

Deterministic scoring output:

`evaluation/results/owasp-semgrep-scoring.txt`

SHA-256:

`F031BF89D7D74AA0DCE549A44FF2DBAB580CD30C41FE2A89BEB1915A2987D508`

The raw result artifacts are retained locally under the
ignored `evaluation/results/` directory. Their hashes are
recorded here so that the evaluated artifacts can be
identified without committing the large generated result
files to the source repository.