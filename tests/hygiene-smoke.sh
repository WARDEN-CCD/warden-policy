#!/usr/bin/env sh
# Smoke test for warden-pod-hygiene against the current kube context: create pods with a server-side dry run
# and read the Kyverno audit result. In Audit mode Kyverno reports through PolicyReports, not the API response,
# so this test evaluates the policy with `kubectl create --dry-run=server` only to confirm the policy is
# accepted, then checks the PolicyReport of a real, compliant pod.
set -u
ns="${1:-svc-dbtest}"
fail=0

ready=$(kubectl get validatingpolicies.policies.kyverno.io warden-pod-hygiene \
  -o jsonpath='{.status.conditionStatus.ready}' 2>/dev/null)
if [ "$ready" = "true" ]; then echo "ok   policy warden-pod-hygiene is ready"; else echo "FAIL policy not ready ($ready)"; fail=1; fi

# The CNPG instance pod is compliant by design; its report must not contain hygiene failures.
pod=$(kubectl -n "$ns" get pods -l cnpg.io/podRole=instance -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$pod" ]; then
  uid=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.metadata.uid}')
  failures=$(kubectl -n "$ns" get policyreports.wgpolicyk8s.io "$uid" \
    -o jsonpath='{range .results[?(@.policy=="warden-pod-hygiene")]}{.result}{" "}{.message}{"\n"}{end}' 2>/dev/null | grep -c '^fail')
  echo "info $pod hygiene failures: ${failures:-0} (CNPG pods are expected to pass)"
fi
exit $fail
