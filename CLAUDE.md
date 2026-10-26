# CLAUDE.md — warden-policy

Admission policies + tests + attack suite. Workspace-wide rules: `../CLAUDE.md` (hub). Read hub `DESIGN.md` §7
and `THREAT_MODEL.md` before changing a policy.

- Write only `policies.kyverno.io/v1` CEL types (`ImageValidatingPolicy`, `ValidatingPolicy`, `PolicyException`)
  and native `admissionregistration.k8s.io/v1` `ValidatingAdmissionPolicy`. Never `kind: ClusterPolicy`.
  Most examples online still use ClusterPolicy `verifyImages` — do not copy them.
- Cheap invariants (registry, digest) belong in VAP; anything needing registry or Sigstore access belongs in Kyverno.
- Every policy: `warden.dev/threat-ids` annotation; every validation message starts with the threat ID.
- Staged M3 (hub ADR-032, owner-approved 2026-10-26): the VAP bindings and `warden-pod-hygiene` are `[Deny, Audit]`.
  The image-verification policies stay `Audit` + `failurePolicy: Ignore` until Kyverno retries transient errors;
  do not flip them early. Run every legitimate pod class (CNPG pods, Jobs) under a policy before enforcing it:
  Audit mode hides denials (hub ADR-033).
- Exempt-namespace lists must match the hub's `workspace.yaml` `platformNamespaces`.
- A policy change ships with a `kyverno test` case for the allow path **and** the deny path.
- An attack passes only if refused for the expected reason (match the message prefix).
- Files headed `DRAFT` have not been run on a cluster; spike S1 validates the supply-chain ones.

Verify: `../.venv/Scripts/python.exe ../scripts/verify.py` (from this folder) plus `kyverno test tests/cli`.
