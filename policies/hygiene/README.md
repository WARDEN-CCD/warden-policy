# Hygiene policies (Layer 3)

`pod-hygiene.yaml`: Kyverno `ValidatingPolicy` (CEL) enforcing the golden-path defaults the service template
already sets: non-root, no privilege escalation, read-only root filesystem, drop ALL capabilities, CPU/memory
requests plus a memory limit, readiness and liveness probes. Same namespace scope as the other layers. Messages
are prefixed `HYG:` (these are not threat-model controls). Audit until M3.
