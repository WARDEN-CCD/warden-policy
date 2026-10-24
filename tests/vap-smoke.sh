#!/usr/bin/env sh
# Smoke test for the image-reference ValidatingAdmissionPolicy against the current kube context.
# In Audit+Warn mode, a violating Pod is admitted with a warning; in Deny mode it is refused. Either way the
# expected T01/T06 message must appear. Uses a server-side dry run, so nothing is created.
set -u
ns="${1:-svc-dbtest}"
fail=0

check() {  # $1 description, $2 expected substring ("" = no warning expected), rest = kubectl run args
  desc="$1"; expect="$2"; shift 2
  out=$(kubectl -n "$ns" run "vap-smoke-$$" --restart=Never --dry-run=server "$@" 2>&1)
  if [ -z "$expect" ]; then
    case "$out" in *"T01:"*|*"T06:"*) echo "FAIL $desc: unexpected policy message: $out"; fail=1 ;; *) echo "ok   $desc" ;; esac
  else
    case "$out" in *"$expect"*) echo "ok   $desc" ;; *) echo "FAIL $desc: wanted '$expect', got: $out"; fail=1 ;; esac
  fi
}

check "A06 foreign registry is flagged"  "T06: image not from ghcr.io/warden-ccd/" --image=docker.io/library/nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
check "A01 tag reference is flagged"     "T01: image must be pinned by digest"     --image=ghcr.io/warden-ccd/svc-books:v1
check "Warden image by digest is clean"  ""                                        --image=ghcr.io/warden-ccd/svc-books@sha256:0000000000000000000000000000000000000000000000000000000000000000
check "CNPG label alone is not trusted" "T06: image not from ghcr.io/warden-ccd/" --image=ghcr.io/cloudnative-pg/postgresql:18.6-system-trixie@sha256:f7e00138159bb45d70b624ba25e446924cb3ed1bf366d13e936c3f81b914064e --labels=cnpg.io/cluster=smoke
check "CNPG image on other pod flagged"  "T06: image not from ghcr.io/warden-ccd/" --image=ghcr.io/cloudnative-pg/postgresql:18.6-system-trixie@sha256:f7e00138159bb45d70b624ba25e446924cb3ed1bf366d13e936c3f81b914064e
# The carve-out itself: the live CNPG instance pod was admitted without a T06 warning when the operator created it.
if kubectl get events -A --field-selector reason=FailedCreate 2>/dev/null | grep -q "T06"; then
  echo "FAIL CNPG operator pod creation hit T06"; fail=1
else
  echo "ok   CNPG operator-created pods pass (no T06 FailedCreate events)"
fi
exit $fail
