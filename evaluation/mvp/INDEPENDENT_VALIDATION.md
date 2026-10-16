# Independent repository validation checkpoint

Scope frozen: static repository scanning only. No live exploitation, new rule
families, dashboard redesign, or general accuracy percentage is claimed here.

## Saved live assessments

| Repository | Assessment ID | Raw / grouped | Observations |
| --- | --- | --- | --- |
| r-lando/UNiPick | a2dc4fe7-6e4d-4bbe-a2fc-79f7a0a3ea40 | 86 / 61 | Known overlapping HTML rules grouped; 14 Firebase browser configuration items visible as INFO; dependencies not checked without lockfile. |
| OWASP/NodeGoat | c76a25f9-c698-42c3-9fbe-1a457a404866 | 465 / 339 | OSV completed with 446 dependency occurrences; 126 repeated matches grouped. Eval, redirect and private-key matches retained. Three Django form matches excluded with an explanation. |
| appsecco/dvna | 24cb5b83-4f8f-4539-aefc-2429e8dba9bc | 24 / 24 | New direct exec alias rule detects previously missed request-to-shell case. SQL, XML and redirect warnings remain. Dependencies not checked without lockfile. |

These are historical snapshots read from local assessment storage, not fresh
rescans at a common revision. Source commit hashes were not preserved by these
assessments, so this is observational evidence, not a reproducible benchmark.

## Safe / unsafe controls

- Real Semgrep shell test: three unsafe direct-import/alias forms detected;
  fixed command, execFile argument-list form, and unrelated exec function not
  detected by the new rule. This does not establish argument validation safety.
- Real Semgrep HTML test: dynamic value retained; fixed literal alternatives
  excluded. Unknown-origin button restoration remains a review warning.
- XML import test: parser import detected; escaping-only import excluded.
- Secret tests: literal credentials retained; runtime references excluded;
  Firebase classification stays visible and does not downgrade a private password
  sharing its line; credential-bearing database URLs remain detectable.
- Grouping tests retain different advisory IDs, versions, packages, ecosystems,
  files, and locations, and leave raw input unchanged.

## Failures and open review items

- NodeGoat OSV request originally failed: 1,479 queries exceeded the request size.
  Batching fixed the reproduced error and the saved later scan completed.
- Transient Auth read timeout and GitHub metadata lookup failure were observed.
  Auth health recovered. GitHub's original failure cause was not established;
  a later DVNA scan succeeded. Recovery is not proof of an implemented retry fix.
- Broad path-traversal, session-cookie and some HTML warnings still need manual
  applicability review. SQL and eval warnings may overlap beyond current explicit
  grouping. Findings absent from the selected review are not proven safe.
- No complete independently labeled ground-truth dataset was scored. These runs
  cannot establish overall precision, recall, or zero false negatives.

## Verification

165 backend tests and 12 frontend tests passed; frontend typecheck/build and lint
passed. Existing fixtures, frozen results, historical assessments, and unrelated
local UI/gitignore edits were preserved. Future work should measure documented
misses and false alarms before proposing additional narrowly tested changes.
