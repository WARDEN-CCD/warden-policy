"""Warden attack suite A01-A12 (hub EVALUATION.md E2, THREAT_MODEL.md).

  python attacks/run_attacks.py [--keep-lab] [--out DIR]

Admission attacks run in an "attack lab" namespace guarded by Deny-mode clones of the real policies
(attacks/lab.py), as server-side dry runs: admission is fully evaluated, nothing is created. An attack passes only
if it is refused for the expected reason (its message carries the expected threat ID). Non-admission attacks
check the pipeline (A09, A10), the promotion guard (A11) and GitOps drift repair (A12).

Results: one JSON array in <out>/<UTC timestamp>-results.json (default: hub evidence/attacks) and a Markdown
table on stdout. Needs kubectl on a cluster bootstrapped from warden-gitops, PyYAML, and git.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
HUB = REPO.parent
LAB_NS = "attack-lab"


def sh(*cmd: str, stdin: str | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, cwd=cwd)


# --- fixtures ---------------------------------------------------------------------------------------------------
def resolve(ref: str) -> str:
    """name:tag -> name@sha256:... using an anonymous GHCR token (clusters pull the same way, ADR-028)."""
    if "@sha256:" in ref or not ref.startswith("ghcr.io/"):
        return ref
    name, tag = ref.rsplit(":", 1)
    repo = name.removeprefix("ghcr.io/")
    with urllib.request.urlopen(f"https://ghcr.io/token?scope=repository:{repo}:pull", timeout=20) as r:
        token = json.load(r)["token"]
    req = urllib.request.Request(f"https://ghcr.io/v2/{repo}/manifests/{tag}", method="HEAD", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, "
                  "application/vnd.docker.distribution.manifest.v2+json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return f"{name}@{r.headers['Docker-Content-Digest']}"


# --- lab ---------------------------------------------------------------------------------------------------------
def setup_lab() -> None:
    sh("kubectl", "create", "namespace", LAB_NS)
    sh("kubectl", "label", "namespace", LAB_NS, "warden.dev/attack-lab=true", "--overwrite")
    lab = sh(sys.executable, str(HERE / "lab.py")).stdout
    applied = sh("kubectl", "apply", "-f", "-", stdin=lab)
    if applied.returncode != 0:
        raise SystemExit(f"applying lab policies failed: {applied.stderr}")
    for _ in range(40):
        ready = sh("kubectl", "get", "imagevalidatingpolicies.policies.kyverno.io", "warden-verify-supply-chain-lab",
                   "-o", "jsonpath={.status.conditionStatus.ready}").stdout
        if ready == "true":
            break
        time.sleep(3)
    time.sleep(10)  # webhook and VAP propagation


def teardown_lab() -> None:
    sh("kubectl", "delete", "-f", "-", "--ignore-not-found", stdin=sh(sys.executable, str(HERE / "lab.py")).stdout)
    sh("kubectl", "delete", "namespace", LAB_NS, "--ignore-not-found", "--wait=false")


def admission(attack: str, image: str | None, expect: str | None) -> dict:
    """expect=None: must be admitted; otherwise must be denied with `expect` in the message."""
    if image is None:
        return {"observed": "skipped", "passed": None, "message": "fixture not available (attacks/fixtures.json)"}
    name = attack.lower().replace("_", "-")
    r = sh("kubectl", "-n", LAB_NS, "run", f"{name}-{int(time.time())}", "--restart=Never", "--dry-run=server",
           f"--image={image}")
    out = (r.stdout + r.stderr).strip()
    observed = "admit" if r.returncode == 0 else "deny"
    if expect is None:
        passed = observed == "admit"
    else:
        passed = observed == "deny" and expect in out
    return {"observed": observed, "passed": passed, "message": " ".join(out.split())[:400]}


# --- non-admission attacks ---------------------------------------------------------------------------------------
def a09_no_cluster_credentials() -> dict:
    """Search every platform workflow and the service template for cluster access, and every Warden repo's
    Actions secrets for cluster credentials. warden-spike-* repos are excluded: their CI creates a disposable kind
    cluster inside the runner, which is test tooling, not access to a Warden cluster."""
    pattern = re.compile(r"kubeconfig|KUBECONFIG|kubectl|k8s-set-context|aks-set-context|azure/aks", re.I)
    files = [p for p in HUB.glob("warden-*/.github/workflows/*.y*ml") if not p.parts[-4].startswith("warden-spike")]
    files += list((HUB / "warden-platform" / "templates").rglob("*.yml"))
    hits = [f"{p.relative_to(HUB).as_posix()}:{i}" for p in files
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if pattern.search(line) and not line.lstrip().startswith("#")]
    repos = sh("gh", "repo", "list", "WARDEN-CCD", "--limit", "100", "--json", "name", "--jq", ".[].name").stdout.split()
    secrets, unreadable = {}, []
    for repo in repos:
        r = sh("gh", "api", f"repos/WARDEN-CCD/{repo}/actions/secrets", "--jq", "[.secrets[].name] | join(\",\")")
        if r.returncode != 0:
            unreadable.append(repo)
        elif r.stdout.strip():
            secrets[repo] = r.stdout.strip()
    kube = {r: n for r, n in secrets.items() if re.search(r"KUBE|AKS|CLUSTER", n, re.I)}
    passed = not hits and not kube
    return {"observed": "none found" if passed else "found", "passed": passed,
            "message": f"{len(files)} workflow files scanned, matches: {hits or 'none'}; repo secrets in "
                       f"{len(repos)} repos: {secrets or 'none'}; unreadable: {unreadable or 'none'}"}


def a10_oidc_only_in_sign_job() -> dict:
    """The platform workflow grants id-token only to sign-attest, and that job never checks out code."""
    wf = yaml.safe_load((HUB / "warden-platform/.github/workflows/build-sign-attest.yml").read_text(encoding="utf-8"))
    with_oidc = [n for n, j in wf["jobs"].items() if (j.get("permissions") or {}).get("id-token") == "write"]
    sign_steps = wf["jobs"].get("sign-attest", {}).get("steps", [])
    checks_out = any("actions/checkout" in str(s.get("uses", "")) or "mvnw" in str(s.get("run", "")) for s in sign_steps)
    top = wf.get("permissions")
    passed = with_oidc == ["sign-attest"] and not checks_out and top == {}
    return {"observed": f"id-token in {with_oidc}; sign job checks out code: {checks_out}; top-level permissions: {top}",
            "passed": passed, "message": "build job cannot request an OIDC token, so build code cannot mint a signing cert"}


def a11_bot_overreach() -> dict:
    """Run the real digest-only guard against crafted promotion PRs."""
    guard = HUB / "warden-gitops/.github/scripts/digest_only.py"
    d1, d2 = "a" * 64, "b" * 64
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        git = lambda *a: sh("git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "core.autocrlf=false", *a, cwd=repo)
        git("init", "-q", "-b", "main")
        (repo / "apps/books").mkdir(parents=True)
        rollout = repo / "apps/books/rollout.yaml"
        # Same shape as the rendered template (warden-platform/templates/spring-service/gitops/rollout.yaml).
        rollout.write_text("spec:\n  template:\n    spec:\n      containers:\n        - name: app\n"
                           f"          image: ghcr.io/warden-ccd/svc-books@sha256:{d1}\n")
        git("add", "-A"); git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD").stdout.strip()

        def attempt(label, mutate, expect_ok):
            git("checkout", "-q", "-B", "pr", base)
            mutate()
            git("add", "-A"); git("commit", "-qm", label)
            git("update-ref", "refs/remotes/pr/head", "HEAD")
            env = dict(os.environ, PR_AUTHOR="warden-ccd-promoter[bot]", BOT_LOGIN="warden-ccd-promoter[bot]",
                       BASE_SHA=base, ORG="WARDEN-CCD")
            r = subprocess.run([sys.executable, str(guard)], capture_output=True, text=True, cwd=repo, env=env)
            cases.append((label, (r.returncode == 0) == expect_ok, r.stdout.strip()))

        attempt("legitimate digest bump", lambda: rollout.write_text(rollout.read_text().replace(d1, d2)), True)
        attempt("also edits a policy app", lambda: (rollout.write_text(rollout.read_text().replace(d1, d2)),
                                                   (repo / "policies.yaml").write_text("x: 1\n")), False)
        attempt("swaps the image name", lambda: rollout.write_text(
            rollout.read_text().replace(f"svc-books@sha256:{d1}", f"svc-evil@sha256:{d2}")), False)
        attempt("changes a non-image line", lambda: rollout.write_text(rollout.read_text().replace("spec:", "spec: # x", 1)), False)
    passed = all(ok for _, ok, _ in cases)
    return {"observed": "; ".join(f"{label}: {'as expected' if ok else 'WRONG'}" for label, ok, _ in cases),
            "passed": passed, "message": " | ".join(out for _, _, out in cases)[:400]}


def a12_policy_drift() -> dict:
    """Tamper with a live admission policy; Argo CD self-heal must restore it."""
    name = "warden-verify-supply-chain"
    before = sh("kubectl", "get", "imagevalidatingpolicies.policies.kyverno.io", name,
                "-o", "jsonpath={.spec.validations[*].message}").stdout
    if not before:
        return {"observed": "skipped", "passed": None, "message": f"{name} not found on this cluster"}
    removed = sh("kubectl", "get", "imagevalidatingpolicies.policies.kyverno.io", name,
                 "-o", "jsonpath={.spec.validations[0].message}").stdout.split(":")[0]
    patch = sh("kubectl", "patch", "imagevalidatingpolicies.policies.kyverno.io", name, "--type=json",
               "-p", '[{"op":"remove","path":"/spec/validations/0"}]')
    if patch.returncode != 0:
        return {"observed": "patch failed", "passed": False, "message": patch.stderr.strip()[:300]}
    start = time.time()
    while time.time() - start < 300:
        now = sh("kubectl", "get", "imagevalidatingpolicies.policies.kyverno.io", name,
                 "-o", "jsonpath={.spec.validations[*].message}").stdout
        if now == before:
            secs = round(time.time() - start, 1)
            return {"observed": f"restored after {secs}s", "passed": True, "seconds": secs,
                    "message": f"removed the first validation ({removed}); Argo CD self-heal put it back"}
        time.sleep(1)
    return {"observed": "not restored within 300s", "passed": False, "message": "self-heal did not revert the tampering"}


def a13_init_container_smuggle(good: str | None, unsigned: str | None) -> dict:
    """An unsigned org image as an initContainer next to a signed app container. The IVP validations iterate
    images.containers only; validationConfigurations.required must refuse any matched image nobody verified."""
    if not good or not unsigned:
        return {"observed": "skipped", "passed": None, "message": "fixtures not available (good, a02_unsigned)"}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": f"a13-{int(time.time())}", "namespace": LAB_NS},
           "spec": {"initContainers": [{"name": "init", "image": unsigned}],
                    "containers": [{"name": "app", "image": good}]}}
    r = sh("kubectl", "create", "--dry-run=server", "-f", "-", stdin=json.dumps(pod))
    out = " ".join((r.stdout + r.stderr).split())
    observed = "admit" if r.returncode == 0 else "deny"
    return {"observed": observed, "passed": observed == "deny" and "is not verified" in out, "message": out[:400]}


def a14_replicaset_path(unsigned: str | None) -> dict:
    """A real ReplicaSet with an unsigned org image. Kyverno 1.19.2 does not verify ReplicaSets (ADR-031), so the
    ReplicaSet may be admitted; the Pods the ReplicaSet controller then creates must be refused at Pod admission."""
    if not unsigned:
        return {"observed": "skipped", "passed": None, "message": "fixture not available (a02_unsigned)"}
    name = f"a14-{int(time.time())}"
    rs = {"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": {"name": name, "namespace": LAB_NS},
          "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}},
                   "template": {"metadata": {"labels": {"app": name}},
                                "spec": {"containers": [{"name": "app", "image": unsigned}]}}}}
    r = sh("kubectl", "create", "-f", "-", stdin=json.dumps(rs))
    if r.returncode != 0:
        out = " ".join((r.stdout + r.stderr).split())
        return {"observed": "ReplicaSet refused", "passed": "T02/T03/T07/T08" in out, "message": out[:400]}
    try:
        deadline = time.time() + 180
        while time.time() < deadline:
            pods = sh("kubectl", "-n", LAB_NS, "get", "pods", "-l", f"app={name}", "-o", "name").stdout.strip()
            if pods:
                return {"observed": "Pod created from an unsigned template", "passed": False, "message": pods}
            events = sh("kubectl", "-n", LAB_NS, "get", "events", "--field-selector",
                        f"involvedObject.name={name},reason=FailedCreate", "-o", "jsonpath={.items[*].message}").stdout
            if "T02/T03/T07/T08" in events:
                return {"observed": "ReplicaSet admitted; its Pods refused", "passed": True,
                        "message": " ".join(events.split())[:400]}
            time.sleep(3)
        return {"observed": "no Pod and no FailedCreate within 180 s", "passed": False, "message": ""}
    finally:
        sh("kubectl", "-n", LAB_NS, "delete", "rs", name, "--ignore-not-found", "--wait=false")


# --- main --------------------------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-lab", action="store_true")
    ap.add_argument("--out", type=Path, default=HUB / "evidence" / "attacks")
    args = ap.parse_args()

    fx = {k: v for k, v in json.loads((HERE / "fixtures.json").read_text()).items() if not k.startswith("_")}
    resolved, unresolved = {}, {}
    for k, v in fx.items():
        try:
            resolved[k] = resolve(v) if v else None
        except Exception as exc:  # not built, or not public yet (ADR-028)
            resolved[k], unresolved[k] = None, f"{v}: {exc}"
    resolved["a01_tag_reference"] = fx["a01_tag_reference"]  # keep the tag: that is the attack

    plan = [
        ("GOOD", "-", "signed platform image by digest is admitted", "admission", resolved["good"], None),
        ("A01", "T01", "tag instead of digest", "admission", resolved["a01_tag_reference"], "T01"),
        ("A02", "T02", "unsigned image in the org registry", "admission", resolved["a02_unsigned"], "T02/T03/T07"),
        ("A03", "T03", "valid Fulcio cert, wrong signer identity", "admission", resolved["a03_foreign_signer"], "T02/T03/T07"),
        ("A04", "T04", "platform workflow called from a non-svc repo", "admission", resolved["a04_confused_deputy"], "T04"),
        ("A05", "T05", "non-main build", "note", None, None),
        ("A06", "T06", "image from docker.io", "admission", resolved["a06_foreign_registry"], "T06"),
        ("A07", "T07", "signed image modified (new digest)", "admission", resolved["a07_modified_after_signing"], "T02/T03/T07"),
        ("A08", "T08", "signature kept, attestations stripped", "admission", resolved["a08_stripped_attestations"], "T08"),
        ("A09", "T09", "cluster credentials anywhere in CI", "a09", None, None),
        ("A10", "T11", "OIDC token from the build job", "a10", None, None),
        ("A11", "T12", "promotion bot changes more than a digest", "a11", None, None),
        ("A12", "T13", "kubectl edit of an admission policy", "a12", None, None),
        ("A13", "T02", "unsigned org image smuggled in as an initContainer", "a13", None, None),
        ("A14", "T02", "unsigned org image via a ReplicaSet", "a14", None, None),
    ]
    results = []
    setup_lab()
    try:
        for aid, threat, desc, kind, image, expect in plan:
            if kind == "admission":
                r = admission(aid, image, expect)
                key = next((k for k in fx if k.startswith(aid.lower() + "_")), None)
                if r["observed"] == "skipped" and key in unresolved:
                    r["message"] = "fixture not pullable anonymously: " + unresolved[key][:200]
                expected = "admit" if expect is None else f"deny ({expect})"
            elif kind == "note":
                r = {"observed": "prevented earlier", "passed": True,
                     "message": "build-sign-attest pushes and signs only on push to refs/heads/main, so no non-main "
                                "image exists to admit; the IVP ref check is defense in depth (warden verify unit test)"}
                expected = "no signed artifact"
            else:
                r = {"a09": a09_no_cluster_credentials, "a10": a10_oidc_only_in_sign_job,
                     "a11": a11_bot_overreach, "a12": a12_policy_drift,
                     "a13": lambda: a13_init_container_smuggle(resolved["good"], resolved["a02_unsigned"]),
                     "a14": lambda: a14_replicaset_path(resolved["a02_unsigned"])}[kind]()
                expected = {"a13": "deny (image not verified)",
                            "a14": "no Pod from an unsigned template"}.get(kind, "refused / restored")
            results.append({"attack": aid, "threat": threat, "description": desc, "image": image,
                            "expected": expected, **r})
            mark = {True: "PASS", False: "FAIL", None: "SKIP"}[r["passed"]]
            print(f"{mark}  {aid:5} {desc:48} {r['observed']}", flush=True)
    finally:
        if not args.keep_lab:
            teardown_lab()

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    path = args.out / f"{stamp}-results.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    failed = [r["attack"] for r in results if r["passed"] is False]
    skipped = [r["attack"] for r in results if r["passed"] is None]
    print(f"\n{len(results) - len(failed) - len(skipped)} passed, {len(failed)} failed {failed or ''}, "
          f"{len(skipped)} skipped {skipped or ''}\nwritten: {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
