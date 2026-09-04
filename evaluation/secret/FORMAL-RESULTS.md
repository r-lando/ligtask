\# Formal Secret-Detection Evaluation Results



\## Evaluation Scope



The formal secret-detection evaluation assessed Ligtask's production

secret-detection mechanism using the frozen controlled synthetic benchmark

defined under `evaluation/secret/`.



The benchmark contained 15 cases:



\- 5 positive cases representing the five implemented secret-detection rule

&#x20; families;

\- 5 negative cases containing secret-like but intentionally non-matching

&#x20; content; and

\- 5 placeholder cases expected to be suppressed or otherwise produce no

&#x20; finding.



The production function

`app.services.secret\_service.scan\_secrets` was executed against each frozen

fixture exactly once during the formal evaluation.



The results reported here apply only to this controlled 15-case synthetic

benchmark and must not be interpreted as general real-world secret-detection

accuracy.



\## Execution Record



\- Execution timestamp (UTC): `2026-09-04T11:56:30.408799+00:00`

\- Number of cases: 15

\- Total measured processing time: 0.008732 seconds

\- Raw result artifact: `evaluation/secret/results/formal-results.json`

\- Raw result SHA-256:

&#x20; `E68E271894D857FDD9BABEE11C0CF57CDADA92E8A3824CBA655C1A18E0160D96`



\## Classification Results



| Metric | Result |

| --- | ---: |

| True Positives (TP) | 5 |

| False Positives (FP) | 0 |

| False Negatives (FN) | 0 |

| True Negatives (TN) | 10 |

| Precision | 1.0000 |

| Recall | 1.0000 |

| Specificity | 1.0000 |

| Accuracy | 1.0000 |

| F1-score | 1.0000 |



These values describe performance only within the frozen controlled

secret-detection benchmark.



\## Per-Rule Results



| Rule | Expected | Result |

| --- | --- | --- |

| `aws-access-key-id` | Detection | PASS |

| `github-token` | Detection | PASS |

| `private-key` | Detection | PASS |

| `database-connection-string` | Detection | PASS |

| `generic-secret-assignment` | Detection | PASS |



All five positive cases were detected by their expected rule. No positive case

produced an unexpected additional rule finding.



\## Negative and Placeholder Controls



All 10 non-positive cases were classified as true negatives:



\- 5 negative cases produced no findings.

\- 5 placeholder cases produced no findings.



No false-positive case was observed within the frozen control set.



\## Privacy Verification



Five privacy checks were performed, one for each positive case. Each check

verified that the seeded synthetic secret value, token, connection string, or

private-key marker used as the privacy probe was absent from the serialized

finding output returned by the production scanner.



Results:



\- Privacy checks performed: 5

\- Privacy checks passed: 5

\- Privacy checks failed: 0



The controlled evaluation therefore observed no disclosure of the seeded

positive-case secret values through the returned finding objects.



This verification applies to the tested scanner output and synthetic fixtures;

it should not be interpreted as proof against every possible information

disclosure scenario.



\## Reliability Observations



All 15 cases completed with `scan\_status` equal to `completed`.



\- Non-completed cases: 0

\- Cases with processing errors: 0

\- Cases with unexpected rule findings: 0



\## Interpretation



Within the frozen 15-case controlled synthetic dataset, Ligtask achieved

precision, recall, specificity, accuracy, and F1-score values of 1.0000.



These results demonstrate that the implemented secret-detection rules behaved

as expected for the predefined positive, negative, and placeholder cases used

in this evaluation. Because the dataset is intentionally small, synthetic, and

constructed around the implemented rule families, these results do not

establish 100% secret-detection performance on arbitrary or real-world

repositories.



The evaluation should therefore be reported as controlled functional and

technical validation of the implemented secret-detection mechanism rather than

as evidence of universal detection accuracy.
