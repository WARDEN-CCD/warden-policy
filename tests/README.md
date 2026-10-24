# Policy tests

| Where | What | Runs |
|-------|------|------|
| `cli/vap-image-references/` | T01/T06 image VAP for Pods: digest, registry, look-alike prefix, init and ephemeral containers, CNPG image from an ordinary user | `kyverno test tests/cli`, CI on every PR |
| `cli/vap-image-references-cnpg/` | The CNPG carve-out, requested as `cnpg-system:cloudnative-pg`: pinned image allowed; unpinned, other digest, ephemeral use refused | same |
| `cli/pod-hygiene/` | `warden-pod-hygiene`: one case per HYG rule, init and ephemeral containers, exempt namespace | same |
| `vap-smoke.sh` | What the CLI cannot evaluate: exempt namespaces (the CLI ignores a VAP `namespaceSelector`) and the Rollouts VAP (the CLI cannot map the Rollout CRD offline) | live, `sh tests/vap-smoke.sh [namespace]` |
| `hygiene-smoke.sh` | `warden-ephemeral-container-hygiene` on the `pods/ephemeralcontainers` subresource (`kubectl debug`), via server-side dry-run patches | live, `sh tests/hygiene-smoke.sh [namespace]` |
| `../attacks/` | A01–A12 end to end, including the ImageValidatingPolicies, which need real signatures from GHCR | live, `python attacks/run_attacks.py` |

The ImageValidatingPolicies are not in `cli/`: verifying them needs the registry and Sigstore, so they are
covered by the attack suite on kind (GOOD, A02–A05, A07, A08). `chainsaw/` is reserved for running the attack
suite in CI against a kind cluster created inside the runner (M3).

`cli/` is generated once and then edited by hand: each case is a Pod named after what it tests, and
`kyverno-test.yaml` lists the expected result per Pod.
