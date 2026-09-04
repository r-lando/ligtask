# Formal Configuration Assessment Results

## Evaluation Scope

The formal configuration assessment evaluated Ligtask's production configuration scanner using the frozen 12-case controlled Dockerfile benchmark.

The evaluation used the production function:

`app.services.config_service.scan_configurations`

The benchmark consisted of:

- 6 positive cases
- 6 negative/control cases
- 3 supported configuration rule families

The tested rule families were:

- `docker-root-user`
- `docker-latest-tag`
- `docker-add-instead-of-copy`

## Formal Execution

Execution timestamp:

`2026-09-04T12:23:36.697461+00:00`

The formal evaluation was executed once using the frozen benchmark methodology, cases, fixture generator, fixtures, and evaluation runner.

## Results

| Metric | Result |
|---|---:|
| Cases | 12 |
| True Positives | 6 |
| False Positives | 0 |
| False Negatives | 0 |
| True Negatives | 6 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| Specificity | 1.0000 |
| Accuracy | 1.0000 |
| F1-score | 1.0000 |
| Unexpected Finding Cases | 0 |
| Non-completed Cases | 0 |
| Cases with Processing Errors | 0 |
| Total Processing Time | 0.005334400339052081 seconds |

## Per-Rule Results

| Rule | Expected Positive Cases | Detected | Missed |
|---|---:|---:|---:|
| `docker-root-user` | 2 | 2 | 0 |
| `docker-latest-tag` | 2 | 2 | 0 |
| `docker-add-instead-of-copy` | 2 | 2 | 0 |

## Raw Result Integrity

Raw result artifact:

`evaluation/configuration/results/formal-results.json`

SHA-256:

`3E72870B4D0ED5F01AFBB46BA1F2A6FFB324CD9E649DD24542AF62D01BBF8DF8`

The raw formal result is excluded from version control and preserved separately as the formal evaluation artifact.

## Interpretation

Ligtask achieved 100% precision, recall, specificity, accuracy, and F1-score within the frozen 12-case controlled configuration-assessment dataset.

These results demonstrate that the implemented configuration scanner correctly detected the expected findings and produced no unexpected findings within the defined benchmark scope.

## Limitation

The configuration benchmark is intentionally small, synthetic, and aligned with the configuration rules currently supported by Ligtask. The results therefore characterize performance within the frozen controlled dataset and should not be interpreted as evidence that the platform can detect all possible configuration vulnerabilities or misconfigurations.
