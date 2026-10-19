# Request-path precision and overlapping SQL evidence

## Path construction

The previous taint source treated arbitrary function parameters as attacker input, including a callback parameter from a local `readdirSync(__dirname)` listing. The rule now uses request query/body/params/cookies/headers/files as explicit sources. Local listing and fixed-name examples do not match; query/body-derived join/resolve examples do. Arbitrary `replace`, `indexOf`, or functions named sanitize are no longer assumed to guarantee safe containment.

This remains a static review warning, not proof that a later file operation can escape an allowed directory. Non-request sources, cross-function/cross-file propagation, destructured handler input, and alternate path APIs are not comprehensively covered. The change intentionally trades broad arbitrary-parameter audit coverage for explicit request-source evidence. It does not establish that every local-directory operation is safe.

## SQL correlation

Only the known `tainted-sql-string` / `sequelize-raw-query` pair can form `overlapping-sql-warnings`. Requirements: same case-sensitive normalized file path, same start line, exactly one finding per rule, valid scanner line/column ranges, and nonempty range overlap. Missing locations, adjacent lines, nonoverlapping columns, repeated candidates, and unrelated rules remain separate. No distance-based or fuzzy matching is used.

Semgrep ranges pass through normalization for correlation; no source text or secret content is added. Raw findings are not mutated. The consolidated warning retains highest existing severity, both rule IDs, and evidence count. This is a grouping of overlapping warnings, not a claim that all database findings share one root cause. The next-line `express-sequelize-injection` finding stays separate because available evidence is insufficient to merge it confidently. Existing saved results are not reprocessed.

## Verification

Real-engine tests cover local directory callbacks, fixed paths, request-controlled query/body paths, and ineffective replace/indexOf checks. Grouping tests cover missing/ambiguous locations, distinct files, case differences, adjacent/nonoverlapping ranges, raw-input immutability, and severity/evidence preservation. An end-to-end production scan supplies actual ranges: three SQL rule matches become two consolidated warnings, preserving the next-line injection finding separately.

The original 14-case accuracy benchmark still passes (6 positive / 8 negative examples); this is not a real-world accuracy percentage. No public repository scan was submitted by this change.

Full backend regression run: 185 passed (two existing dependency deprecation warnings).
