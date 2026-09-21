\# Controlled Secret-Detection Evaluation



\## Purpose



This evaluation measures the behavior of TALGED's secret-detection mechanism against a frozen set of synthetic repository fixtures with predefined expected outcomes.



The evaluation is limited to the secret-detection rules implemented by TALGED at the time the benchmark is frozen. It does not measure detection of every possible credential or secret format.



\## Production Scope



The evaluated implementation contains five secret-detection rule families:



1\. AWS access-key identifier detection

2\. GitHub token detection

3\. Private-key header detection

4\. Database connection-string detection

5\. Generic secret-assignment detection



The generic secret-assignment rule also applies placeholder suppression to reduce findings for obvious example or dummy credential values.



\## Dataset Design



The controlled dataset will contain 15 synthetic cases divided into three groups:



\- 5 positive cases containing synthetic strings designed to satisfy one supported secret rule each.

\- 5 negative-control cases containing structurally related but non-matching content.

\- 5 placeholder-control cases designed to exercise TALGED's placeholder-suppression behavior.



All test values must be synthetic and must not be active, usable, or copied from real credentials.



Each case will be stored in an isolated fixture directory so that its expected result can be evaluated independently.



\## Ground Truth



Ground truth will be defined before the fixtures are processed by TALGED.



Each case will specify:



\- case identifier

\- case group

\- targeted rule

\- expected finding state

\- expected rule identifier when applicable

\- expected number of findings when applicable



Positive cases are expected to produce the predefined rule finding.



Negative controls are expected to produce no secret finding.



Placeholder controls are expected to produce no finding when the candidate value is intentionally suppressed by the production placeholder logic.



\## Measurements



The formal evaluation will record:



\- total cases

\- true positives

\- false negatives

\- true negatives

\- false positives

\- precision

\- recall

\- specificity

\- accuracy

\- F1 score

\- per-rule detection result

\- findings produced per case

\- scanner execution status

\- processing errors

\- processing time



A true positive occurs when a positive case produces its expected rule finding.



A false negative occurs when a positive case does not produce its expected rule finding.



A true negative occurs when a negative or placeholder control produces no secret finding.



A false positive occurs when a negative or placeholder control produces one or more secret findings.



\## Privacy Verification



The formal evaluation will also verify that returned findings do not contain the seeded synthetic secret value.



Synthetic values may exist inside the local controlled fixture used for matching, but the detected value must not appear in the finding message or other returned finding fields.



This check evaluates TALGED's intended behavior of reporting the location and type of a potential secret without returning the detected credential value.



\## Execution Protocol



The methodology, case definitions, fixture generator, fixtures, and formal evaluation runner must be frozen in Git before the first formal execution.



The formal evaluation must use the production `scan\_secrets()` implementation without modifying its rules after observing benchmark results.



The formal result must be preserved after the first valid execution. The benchmark must not be tuned or selectively modified in response to observed results.



If an execution is invalidated by an infrastructure or execution failure, the reason for invalidation must be documented before another formal execution is performed.



\## Interpretation



Results from this dataset describe performance only for the frozen controlled cases and the secret patterns implemented by TALGED.



They must not be generalized as the detection accuracy of TALGED for all possible secrets, credentials, repository types, or secret-detection techniques.
