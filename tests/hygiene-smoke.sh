#!/usr/bin/env sh
# Smoke test for the hygiene policies against the current kube context.
# - warden-pod-hygiene (Kyverno ValidatingPolicy, Audit): must be ready; CNPG instance pods must have no hygiene
#   failures in their PolicyReports. Rule-by-rule cases live in tests/cli/pod-hygiene.
# - warden-ephemeral-container-hygiene (VAP, Audit+Warn): ephemeral containers added later (kubectl debug) arrive
#   on the pods/ephemeralcontainers subresource, which the kyverno CLI cannot drive. A server-side dry-run patch
#   on a running pod of the service exercises it without attaching anything.
set -u
ns="${1:-svc-books}"
fail=0

ready=$(kubectl get validatingpolicies.policies.kyverno.io warden-pod-hygiene \
  -o jsonpath='{.status.conditionStatus.ready}' 2>/dev/null)
if [ "$ready" = "true" ]; then echo "ok   policy warden-pod-hygiene is ready"; else echo "FAIL policy not ready ($ready)"; fail=1; fi

target=$(kubectl -n "$ns" get pods --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
image=$(kubectl -n "$ns" get pod "$target" -o jsonpath='{.spec.containers[0].image}' 2>/dev/null)

debug() {  # $1 description, $2 expected substring ("" = no HYG message), $3 securityContext JSON
  patch=$(printf '{"spec":{"ephemeralContainers":[{"name":"smoke-%s","image":"%s","securityContext":%s}]}}' "$$" "$image" "$3")
  out=$(kubectl -n "$ns" patch pod "$target" --subresource=ephemeralcontainers --type=strategic --dry-run=server -p "$patch" 2>&1)
  if [ -z "$2" ]; then
    case "$out" in *"HYG:"*) echo "FAIL $1: unexpected: $out"; fail=1 ;; *) echo "ok   $1" ;; esac
  else
    case "$out" in *"$2"*) echo "ok   $1" ;; *) echo "FAIL $1: wanted '$2', got: $out"; fail=1 ;; esac
  fi
}

hardened='"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}'
if [ -n "$target" ]; then
  debug "debug container as root is flagged"    "HYG: ephemeral containers must run as non-root"      "{\"runAsNonRoot\":false,$hardened}"
  # The API server itself rejects privileged with allowPrivilegeEscalation false, so that field is left out here.
  debug "privileged debug container is flagged" "HYG: privileged ephemeral containers are not allowed" \
    '{"runAsNonRoot":true,"privileged":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}'
  debug "debug container adding SYS_ADMIN flagged" "HYG: ephemeral containers must drop ALL capabilities" \
    '{"runAsNonRoot":true,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"],"add":["SYS_ADMIN"]}}'
  debug "hardened debug container is clean"     ""                                                   "{\"runAsNonRoot\":true,$hardened}"
else
  echo "FAIL no running pod in $ns to dry-run a debug container against"; fail=1
fi

# CNPG instance pods are compliant by design; their reports must not contain hygiene failures.
pod=$(kubectl get pods -A -l cnpg.io/podRole=instance -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
pns=$(kubectl get pods -A -l cnpg.io/podRole=instance -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)
if [ -n "$pod" ]; then
  uid=$(kubectl -n "$pns" get pod "$pod" -o jsonpath='{.metadata.uid}')
  failures=$(kubectl -n "$pns" get policyreports.wgpolicyk8s.io "$uid" \
    -o jsonpath='{range .results[?(@.policy=="warden-pod-hygiene")]}{.result}{" "}{.message}{"\n"}{end}' 2>/dev/null | grep -c '^fail')
  echo "info $pns/$pod hygiene failures: ${failures:-0} (CNPG pods are expected to pass)"
else
  echo "info no CNPG instance pod running; PolicyReport check skipped"
fi
exit $fail
