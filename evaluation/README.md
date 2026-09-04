# Ligtask Technical Evaluation

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



Before the formal evaluation configuration was frozen, Ligtask

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

The OWASP Benchmark evaluates the SAST component of Ligtask.
Dependency assessment, secret detection, and configuration
assessment require separate controlled evaluation datasets.
