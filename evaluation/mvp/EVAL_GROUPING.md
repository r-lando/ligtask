# Eval warning grouping

The explicit `code-string-concat` / `eval-detected` rule pair can form one `overlapping-eval-warnings` finding only with the same case-sensitive normalized file and exact positive start/end line-column range. There must be exactly one match from each known rule. Missing/invalid locations, ambiguous repeated candidates, and unrelated rules remain separate. Distinct calls on the same line have different ranges and are not collapsed together.

Consolidation retains the highest existing severity, both rule IDs, and evidence count. Raw records are not modified. A generic eval warning without a matching request-input warning stays visible. No detection rule, private-key severity, dependency matching, or saved assessment record is changed.

Real-engine integration exercised three request-body eval calls on separate lines, two request-query eval calls on the same line, a generic dynamic eval, and a fixed-string eval. The two known rules produced 11 raw matches, consolidated into five paired High warnings plus one standalone generic warning. Synthetic tests also cover differing paths/case, neighboring lines, mismatched/missing ranges, duplicate candidates, unrelated rules, and raw-input immutability.

Grouping improves presentation, not proof of exploitability or general scanner recall. New scans use the change; saved reports are not recalculated. Scanned Git commit provenance remains a separate next improvement and is not implemented by this pass.

Full backend regression verification: 188 passed, with two existing dependency deprecation warnings.
