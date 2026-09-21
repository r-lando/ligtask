# TALGED Semgrep Ruleset v1

## Purpose

This directory contains the frozen Semgrep rule configuration used by
TALGED for production Static Application Security Testing (SAST).

TALGED uses a local, versioned ruleset instead of Semgrep's `--config auto`
configuration so that repository assessments use a reproducible rule
configuration.

## Supported SAST Languages

The production ruleset contains security-focused rules for:

- JavaScript
- TypeScript
- Python
- PHP

HTML and CSS may be identified during repository profiling but are not
included as primary SAST languages in TALGED v1.

## Rule Selection

Rules were selected from directories named `security` under the four
supported language directories in the pinned Semgrep Community Rules
snapshot.

The frozen ruleset contains:

- 492 YAML configuration files
- 504 Semgrep rules

The ruleset was validated successfully using Semgrep 1.176.0 with zero
configuration errors.

## Provenance

Source: Semgrep Community Rules

Pinned upstream commit:

40b8c63f75dc7c22c8a77482d73bfb864b146f7e

Semgrep version used during validation:

1.176.0

The upstream license notice is preserved in the LICENSE file in this
directory.

## Evaluation Distinction

This production ruleset is separate from the frozen configuration used
for the formal OWASP Benchmark evaluation.

The formal OWASP Benchmark evaluation used the pinned Java security rule
subset from the same upstream Community Rules snapshot. Its previously
recorded results remain unchanged and are not interpreted as performance
measurements for every rule or language contained in this production
ruleset.

No benchmark rules or formal evaluation results were modified when this
production ruleset was created.

