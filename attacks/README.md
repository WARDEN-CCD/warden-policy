# Attack suite

Each attack is a script that tries to get something past admission (or past CI) and asserts the **reason** it was
refused. The suite is evaluation E2 and, from milestone M3, a required CI job against a kind cluster.
Threat IDs refer to the hub's `THREAT_MODEL.md`.

| ID | Script (planned) | Threat | Attempt | Expected refusal |
|----|------------------|--------|---------|------------------|
| A01 | `a01-tag-reference.sh` | T01 | Pod uses `ghcr.io/<org>/svc-books:v1` | VAP: `T01: image must be pinned by digest` |
| A02 | `a02-unsigned-image.sh` | T02 | Push an unsigned image with a PAT, deploy by digest | IVP: `T02/T03/T07: image is not signed…` |
| A03 | `a03-foreign-signer.sh` | T03 | Sign with a workflow in another repo (valid Fulcio cert) | IVP: identity mismatch |
| A04 | `a04-confused-deputy.sh` | T04 | Call `build-sign-attest.yml` from a repo outside the org | IVP: `T04: provenance names a source repository outside…` |
| A05 | `a05-non-main-ref.sh` | T05 | Image built from a feature branch via `workflow_dispatch` | IVP: `T05: … not built from refs/heads/main` |
| A06 | `a06-foreign-registry.sh` | T06 | Pod uses `docker.io/library/nginx@sha256:…` | VAP: `T06: image not from ghcr.io/<org>/` |
| A07 | `a07-modified-image.sh` | T07 | Append a layer to a signed image (new digest) | IVP: no signature for digest |
| A08 | `a08-stripped-sbom.sh` | T08 | Copy a signed image + signature without the SBOM attestation | IVP: `T08: CycloneDX SBOM attestation missing…` |
| A09 | `a09-no-cluster-creds.sh` | T09 | Grep all workflows/secrets lists for kubeconfig/token use | Nothing found |
| A10 | `a10-oidc-from-build.sh` | T11 | PR adds a Maven plugin that requests an OIDC token in the build job | Token request fails |
| A11 | `a11-bot-overreach.sh` | T12 | Bot-authored PR in gitops that also edits a policy Application | `digest-only` check fails |
| A12 | `a12-policy-drift.sh` | T13 | `kubectl edit` an IVP to remove a validation | Argo CD reverts within one reconcile |

Conventions:

- Scripts are POSIX sh, idempotent, clean up after themselves, and print one JSON line:
  `{"attack":"A02","expected":"deny","observed":"deny","message":"…","ts":"…"}`.
- `run-all.sh` runs every script and writes `../evidence/attacks/<date>-results.json` in the hub.
- An attack "passes" only if it is refused **for the expected reason** — a refusal for a different reason is a
  failure (it means a different control fired and the intended one is untested).
