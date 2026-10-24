"""Generate Deny-mode clones of the real admission policies for the attack lab (evaluation E2).

  python attacks/lab.py > lab.yaml        # then: kubectl apply -f lab.yaml

The cluster's policies stay in Audit until milestone M3 (ADR-020). To test their logic in Enforce mode without
touching other namespaces, every ValidatingAdmissionPolicy (+ binding) and Kyverno ImageValidatingPolicy under
policies/ is cloned with a `-lab` suffix, `Deny`, and a namespace selector that matches only namespaces labelled
warden.dev/attack-lab=true. The validation logic is copied unchanged. Needs PyYAML (hub requirements-dev.txt).
"""

import copy
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LAB_SELECTOR = {"matchLabels": {"warden.dev/attack-lab": "true"}}


def clone(doc: dict) -> dict | None:
    kind = doc.get("kind")
    d = copy.deepcopy(doc)
    d["metadata"] = {"name": doc["metadata"]["name"] + "-lab", "labels": {"warden.dev/attack-lab": "true"}}
    if kind == "ValidatingAdmissionPolicy":
        d["spec"]["matchConstraints"]["namespaceSelector"] = LAB_SELECTOR
        return d
    if kind == "ValidatingAdmissionPolicyBinding":
        d["spec"]["policyName"] = doc["spec"]["policyName"] + "-lab"
        d["spec"]["validationActions"] = ["Deny"]
        return d
    if kind == "ImageValidatingPolicy":
        d["spec"]["matchConstraints"]["namespaceSelector"] = LAB_SELECTOR
        d["spec"]["validationActions"] = ["Deny"]
        d["spec"]["failurePolicy"] = "Fail"  # enforcement semantics, whatever the cluster's audit-phase setting
        return d
    return None


def main() -> int:
    out = []
    for path in sorted((ROOT / "policies").rglob("*.yaml")):
        if "supply-chain/ivp-vuln-attestation" in path.as_posix():
            continue  # stays Audit by design (ADR-022), not an admission gate
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(doc, dict) and (c := clone(doc)):
                out.append(c)
    yaml.safe_dump_all(out, sys.stdout, sort_keys=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
