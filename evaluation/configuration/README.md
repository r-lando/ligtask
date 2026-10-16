\# Controlled Configuration-Assessment Evaluation



\## Purpose



This evaluation measures the behavior of TALGED's production configuration

assessment mechanism against a frozen set of controlled synthetic Dockerfile

fixtures with predefined ground truth.



The evaluation is intended to verify the implemented configuration rules under

known conditions. It is not intended to establish general configuration

security-detection accuracy across all container technologies, configuration

formats, or real-world repositories.



\## Production Mechanism Under Evaluation



The evaluation uses the production function:



`app.services.config\_service.scan\_configurations`



The current configuration assessment supports Dockerfiles and implements three

predefined rules:



1\. `docker-root-user`

2\. `docker-latest-tag`

3\. `docker-add-instead-of-copy`



No separate evaluation-only detection logic will be used.



\## Ground-Truth Design



Ground truth will be defined before the formal scanner execution.



The controlled benchmark will contain 12 synthetic cases:



\- 6 positive cases expected to produce a predefined configuration finding; and

\- 6 negative/control cases expected to produce no configuration finding.



The positive cases will exercise:



\- a Dockerfile without a `USER` instruction;

\- an explicit root `USER`;

\- an image using the `latest` tag;

\- case-insensitive handling of the `latest` tag;

\- an `ADD` instruction; and

\- case-insensitive handling of an `ADD` instruction.



The negative/control cases will exercise:



\- an explicit non-root `USER`;

\- a final non-root `USER` following an earlier root `USER`;

\- a version-pinned image;

\- a digest-pinned image;

\- a `COPY` instruction; and

\- commented-out configuration instructions that must not be treated as active

&#x20; instructions.



Each case will have a predefined expected finding state and expected rule ID

before formal execution.



\## Fixture Isolation



Each benchmark case will be stored in a separate repository-like fixture

directory containing one Dockerfile.



Fixtures will be synthetic and minimal so that the expected behavior of each

case can be determined independently.



Each positive fixture will be designed to trigger one intended rule. Control

fixtures will be designed to trigger no rule.



\## Classification



For positive cases:



\- \*\*True Positive (TP):\*\* the expected rule is detected.

\- \*\*False Negative (FN):\*\* the expected rule is not detected.



For negative/control cases:



\- \*\*True Negative (TN):\*\* no configuration finding is returned.

\- \*\*False Positive (FP):\*\* one or more configuration findings are returned.



Unexpected additional rule findings will be recorded separately rather than

silently discarded.



\## Metrics



The formal evaluation will report:



\- True Positives (TP)

\- False Positives (FP)

\- False Negatives (FN)

\- True Negatives (TN)

\- Precision

\- Recall

\- Specificity

\- Accuracy

\- F1-score



The evaluation will additionally record:



\- per-rule results;

\- findings returned per case;

\- unexpected rule findings;

\- files scanned;

\- scan status;

\- processing errors; and

\- processing time.



\## Reliability Verification



Each case is expected to complete with `scan\_status` equal to `completed`.



Any non-completed scan or processing error will be preserved in the formal

result and will not be silently treated as a successful zero-finding scan.



\## Reproducibility Controls



The evaluation methodology, case definitions, fixture generator, generated

fixtures, and formal evaluation runner will be frozen in version control before

the first formal scanner execution.



The formal result will be generated once and preserved as observed.



The production configuration rules and frozen benchmark fixtures will not be

modified in response to the observed formal result for the purpose of improving

reported evaluation metrics.



The raw formal result artifact will be preserved locally and identified in the

tracked evaluation summary using its SHA-256 hash.



\## Interpretation Limitation



The controlled benchmark is intentionally small and constructed around the

configuration rules currently implemented by TALGED.



Therefore, results from this evaluation describe only the behavior of the

implemented configuration assessment mechanism within the frozen controlled

Dockerfile dataset. They must not be interpreted as evidence of universal

configuration-security detection accuracy.
