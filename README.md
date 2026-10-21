# warden-policy

Admission policies for Warden, their tests, and the attack suite that proves they work.
Design: hub `DESIGN.md` §7; decisions ADR-006, 007, 020, 022; threats: hub `THREAT_MODEL.md`.

```
policies/
  admission/      Layer 1 — native ValidatingAdmissionPolicy: registry allowlist, digest pinning (T01, T06)
  supply-chain/   Layer 2 — Kyverno ImageValidatingPolicy: signature, identity, provenance, SBOM, vulns
  hygiene/        Layer 3 — Kyverno ValidatingPolicy: non-root, read-only rootfs, limits, probes (planned)
  exceptions/     Break-glass PolicyExceptions (expiring; see exceptions/README.md)
tests/
  cli/            `kyverno test` unit tests (resources + expected results), run in CI on every PR
  chainsaw/       end-to-end tests against kind
attacks/          A01–A12 attack scripts (evaluation E2)
```

Argo CD syncs `policies/` into every cluster (Application defined in `warden-gitops/platform/kyverno/`).

## Rules

- CEL policy types only (`policies.kyverno.io/v1`). `ClusterPolicy` is removed in Kyverno 1.20.
- Every policy carries `warden.dev/threat-ids` naming the threats it mitigates; the hub's `scripts/verify.py`
  checks the IDs exist.
- Every validation message starts with its threat ID, so denials are self-explaining in attack results.
- Changes need **two** approvals (CODEOWNERS). Policies stay `Audit` until milestone M3.
- The exempt-namespace list must equal `platformNamespaces` in the hub's `workspace.yaml`.

## Local commands (once tools are installed)

```bash
kyverno test tests/cli
chainsaw test tests/chainsaw
sh attacks/run-all.sh        # against the current kube context
```
