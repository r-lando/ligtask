# NodeGoat reliability refinements

- Reproduced OSV HTTP 400 "too many queries" for 1,479 NodeGoat lockfile entries.
  Batching in groups of 100 returned 1,479 results successfully against the live API.
  Each batch response count is validated; failures are not presented as a clean scan.
- Database connection string secret detection requires a nonempty URL password.
  Host/database addresses without passwords are not private-credential findings.
  This does not assess database network exposure or detect every alternative auth format.
- Django's generic HTML CSRF rule is retained only with a Python Django import in
  submitted files. Excluded match counts and rationale are exposed in mechanism notes.
  This narrow evidence heuristic can miss frameworks configured outside submitted files;
  it is not a guarantee of framework identification or CSRF safety.
- Existing reports and frozen fixtures remain unchanged. Eval warnings remain enabled.

Verification: 161 backend tests passed including the final mechanism-note addition;
live OSV batch retest passed. No application was executed or attacked.
