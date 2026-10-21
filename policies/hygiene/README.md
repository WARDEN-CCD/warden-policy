# Hygiene policies (Layer 3, planned for weeks 6–8)

Kyverno `ValidatingPolicy` (CEL) enforcing the golden-path defaults the service template already sets:

| Policy | Rule |
|--------|------|
| `warden-run-as-non-root` | `securityContext.runAsNonRoot: true`, no privilege escalation, drop ALL capabilities |
| `warden-readonly-rootfs` | `readOnlyRootFilesystem: true` |
| `warden-resources` | CPU/memory requests and memory limit set on every container |
| `warden-probes` | readiness and liveness probes present |

Same namespace scope as the other layers. Messages prefixed `HYG:` (these are not threat-model controls).
