\# Controlled Dependency Vulnerability Evaluation



\## Purpose



This evaluation measures the dependency vulnerability

assessment mechanism implemented in TALGED. It is separate

from the controlled SAST evaluation performed using the

OWASP Benchmark.



The evaluation is limited to dependency functionality that

is currently implemented in TALGED.



\## Evaluation Scope



The dependency assessment pipeline evaluated here is:



package-lock.json

\-> npm package and exact-version extraction

\-> OSV package/version query

\-> vulnerability matching

\-> TALGED dependency finding



Only the npm ecosystem is included in this evaluation.



Python, Maven, Gradle, Composer, and other dependency

ecosystems are outside the current evaluation scope because

TALGED does not currently implement dependency extraction

for those ecosystems.



\## Evaluation Unit



The primary evaluation unit is a controlled npm

package/version case.



Each case contains:



\- a package name;

\- an exact package version;

\- an expected vulnerability state;

\- the OSV vulnerability identifiers applicable to that

&#x20; package/version at the time the ground truth is frozen; and

\- a package-lock.json fixture processed by TALGED.



A vulnerable case is considered detected when TALGED

reports at least one OSV vulnerability identifier that

belongs to the frozen expected OSV identifier set for that

package/version.



A vulnerable case is considered missed when none of its

expected OSV vulnerability identifiers is reported.



A non-vulnerable control passes when TALGED reports no OSV

vulnerability for the package/version according to the

frozen ground truth.



Any vulnerability identifier returned by TALGED that is

not contained in the frozen expected set will be recorded

separately and reviewed against the preserved ground-truth

snapshot. It will not automatically be classified as a

false positive without verification.



\## Ground-Truth Procedure



Ground truth will be established before the formal TALGED

execution.



For every selected package/version case, the evaluation

will record the OSV response obtained directly for that

exact npm package/version.



The frozen ground truth will record:



\- package name;

\- exact version;

\- ecosystem;

\- expected vulnerability state;

\- expected OSV vulnerability identifiers;

\- ground-truth collection date and time;

\- source endpoint;

\- and the preserved response artifact or its cryptographic

&#x20; hash.



The ground-truth records will not be changed in response to

the subsequent TALGED evaluation results.



Because OSV is a continuously maintained vulnerability

database, the recorded ground truth represents the state of

OSV at the documented evaluation time.



\## Case Selection



Cases will be selected before the formal TALGED evaluation

results are observed.



The controlled dataset will include both known vulnerable

package/version cases and non-vulnerable controls.



Package/version cases will not be added, removed, or changed

because of their observed TALGED results.



\## Measurements



The evaluation will record:



\- total controlled cases;

\- vulnerable cases;

\- non-vulnerable controls;

\- correctly detected vulnerable cases;

\- missed vulnerable cases;

\- correctly handled non-vulnerable controls;

\- unexpected vulnerability identifiers requiring

&#x20; adjudication;

\- package/version extraction success;

\- OSV request status;

\- normalized dependency findings;

\- and processing time where applicable.



Where the frozen ground truth supports binary

classification, the following case-level classifications

may be reported:



\- TP: vulnerable case with at least one expected OSV

&#x20; vulnerability detected;

\- FN: vulnerable case with no expected OSV vulnerability

&#x20; detected;

\- FP: non-vulnerable case with a vulnerability finding

&#x20; verified as incorrect against the frozen ground truth;

\- TN: non-vulnerable case with no vulnerability finding.



Precision, recall, false-positive rate, accuracy, and F1

will only be calculated when the ground-truth dataset

supports those classifications.



\## Reproducibility and Integrity



Ground-truth artifacts and formal result artifacts will be

preserved separately from the source code where appropriate.



Cryptographic hashes will be recorded for preserved

evaluation artifacts.



The evaluation date must be reported with dependency

results because OSV data may change after the formal

evaluation.



The dependency evaluation assesses TALGED's use of OSV for

known dependency vulnerabilities. It does not demonstrate

detection of vulnerabilities that are absent from OSV and

does not evaluate unknown or zero-day dependency

vulnerabilities.

## Controlled Case-Selection Procedure

The formal controlled dataset will contain 10 npm
package/version cases:

- 5 vulnerable cases; and
- 5 non-vulnerable control cases.

Distinct npm packages will be used where practical so that
the evaluation is not dominated by multiple versions of a
single package.

Candidate cases will be evaluated using direct OSV
package/version queries before any formal TALGED execution.

A candidate is eligible as a vulnerable case when the
direct OSV query for its exact npm package/version returns
at least one vulnerability identifier.

A candidate is eligible as a non-vulnerable control when
the direct OSV query for its exact npm package/version
returns no vulnerability identifiers at the time the
ground truth is collected.

Selection eligibility is determined only from the direct
OSV ground-truth query. TALGED output must not be inspected
or used when deciding whether a candidate is included.

Once 5 vulnerable and 5 non-vulnerable eligible cases have
been selected and their ground truth has been frozen, the
formal case list will not be changed because of subsequent
TALGED results.

For each selected case, the exact package name, version,
expected OSV identifiers, collection timestamp, and
ground-truth artifact hash will be recorded before the
formal TALGED evaluation is executed.

The purpose of the controlled dataset is to verify the
implemented dependency-assessment pipeline under known
package/version conditions. The dataset is not intended to
estimate the prevalence of vulnerable npm packages in the
general software ecosystem.
