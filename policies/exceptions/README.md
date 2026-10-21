# Break-glass exceptions (ADR-020)

A `PolicyException` (Kyverno CEL type, `policies.kyverno.io`) lets one named workload bypass one named policy
for a limited time. It is the only sanctioned way around admission.

Requirements for every exception file in this folder:

1. One exception per file, named `<yyyy-mm-dd>-<service>-<policy>.yaml`.
2. Annotations:
   - `warden.dev/expires-at: "<RFC 3339 timestamp>"` — at most 72 hours after creation
   - `warden.dev/reason: "<one sentence>"`
   - `warden.dev/approved-by: "<two GitHub handles>"`
3. Scope as narrow as possible: one namespace, one workload, one policy.
4. Merged by PR with two approvals; the expiry job opens an issue when `expires-at` passes, and the follow-up PR
   deletes the file.

Exceptions are listed on the admission dashboard; any exception active during an evaluation run must be
reported with the results.
