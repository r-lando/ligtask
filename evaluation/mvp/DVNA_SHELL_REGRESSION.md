# DVNA direct exec alias regression

Review of appsecco/dvna showed request data passed into a shell command through
`const exec = require('child_process').exec`. The existing detect-child-process
rule handles module-object calls but not this direct alias.

Added request-to-shell-exec: taint matching from body/query/params field access
into the command-string argument of an explicitly imported child_process.exec.
Real Semgrep tests cover property import, destructuring alias and ES import alias,
plus negative controls for a fixed command, execFile argv use, and an unrelated
function named exec. The DVNA-style handler is reproduced without executing it.

This is a narrow extension, not complete shell-injection coverage. It does not
establish live reachability or prove exploitation. Safe argv use may still need
application-specific argument validation. Other broad path/session rules are
unchanged pending independent review. The production ruleset has changed;
historical reports and frozen evaluation results are not rewritten.
