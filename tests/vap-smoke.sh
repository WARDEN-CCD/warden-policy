#!/usr/bin/env sh
# Smoke test for the image-reference ValidatingAdmissionPolicies against the current kube context.
# In Audit+Warn mode, a violating object is admitted with a warning; in Deny mode it is refused. Either way the
# expected T01/T06 message must appear. Uses server-side dry runs, so nothing is created.
# Covers what tests/cli cannot: exempt namespaces (the kyverno CLI ignores a VAP namespaceSelector) and the
# Rollouts VAP (the CLI cannot map the Rollout CRD offline).
set -u
ns="${1:-svc-books}"
fail=0

check() {  # $1 description, $2 expected substring ("" = no warning expected), rest = kubectl run args
  desc="$1"; expect="$2"; shift 2
  out=$(kubectl -n "$ns" run "vap-smoke-$$" --restart=Never --dry-run=server "$@" 2>&1)
  verdict "$desc" "$expect" "$out"
}

verdict() {  # $1 description, $2 expected substring ("" = none), $3 output
  if [ -z "$2" ]; then
    case "$3" in *"T01:"*|*"T06:"*) echo "FAIL $1: unexpected policy message: $3"; fail=1 ;; *) echo "ok   $1" ;; esac
  else
    case "$3" in *"$2"*) echo "ok   $1" ;; *) echo "FAIL $1: wanted '$2', got: $3"; fail=1 ;; esac
  fi
}

check_rollout() {  # $1 description, $2 expected substring ("" = none), $3 image
  manifest="apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: vap-smoke-$$
spec:
  selector: {matchLabels: {app: vap-smoke}}
  template:
    metadata: {labels: {app: vap-smoke}}
    spec: {containers: [{name: app, image: \"$3\"}]}
  strategy: {canary: {steps: [{setWeight: 5}]}}"
  out=$(printf '%s\n' "$manifest" | kubectl -n "$ns" create --dry-run=server -f - 2>&1)
  verdict "$1" "$2" "$out"
}

check "A06 foreign registry is flagged"  "T06: image not from ghcr.io/warden-ccd/" --image=docker.io/library/nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
check "A01 tag reference is flagged"     "T01: image must be pinned by digest"     --image=ghcr.io/warden-ccd/svc-books:v1
check "Warden image by digest is clean"  ""                                        --image=ghcr.io/warden-ccd/svc-books@sha256:0000000000000000000000000000000000000000000000000000000000000000
check "CNPG label alone is not trusted" "T06: image not from ghcr.io/warden-ccd/" --image=ghcr.io/cloudnative-pg/postgresql:18.6-system-trixie@sha256:f7e00138159bb45d70b624ba25e446924cb3ed1bf366d13e936c3f81b914064e --labels=cnpg.io/cluster=smoke
check "CNPG image on other pod flagged"  "T06: image not from ghcr.io/warden-ccd/" --image=ghcr.io/cloudnative-pg/postgresql:18.6-system-trixie@sha256:f7e00138159bb45d70b624ba25e446924cb3ed1bf366d13e936c3f81b914064e

out=$(kubectl -n k6-operator-system run "vap-smoke-$$" --restart=Never --dry-run=server --image=docker.io/library/nginx:latest 2>&1)
verdict "exempt platform namespace is skipped" "" "$out"

check_rollout "Rollout by tag is flagged"             "T01: Rollout template image must be pinned by digest" ghcr.io/warden-ccd/svc-books:v1
check_rollout "Rollout from foreign registry flagged" "T06: Rollout template uses an image outside" quay.io/evil/app@sha256:3333333333333333333333333333333333333333333333333333333333333333
check_rollout "Rollout by Warden digest is clean"     "" ghcr.io/warden-ccd/svc-books@sha256:0000000000000000000000000000000000000000000000000000000000000000

# The carve-out itself: CNPG instance pods are admitted without a T06 failure when the operator creates them.
if kubectl get events -A --field-selector reason=FailedCreate 2>/dev/null | grep -q "T06"; then
  echo "FAIL CNPG operator pod creation hit T06"; fail=1
else
  echo "ok   CNPG operator-created pods pass (no T06 FailedCreate events)"
fi
exit $fail
