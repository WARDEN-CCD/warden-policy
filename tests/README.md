# Policy tests

- `cli/` — `kyverno test` suites. One folder per policy: `kyverno-test.yaml`, `resources.yaml`, expected
  pass/fail per resource. ImageValidatingPolicy cases that need real signatures use the fixture images
  produced in spike S1 (pushed under `ghcr.io/<org>/warden-fixtures`).
- `chainsaw/` — Chainsaw end-to-end tests on kind: apply policy, create Pods/Rollouts, assert admission result
  and PolicyReport contents.

Both run in this repo's CI on every PR (workflow added in weeks 6–8).
