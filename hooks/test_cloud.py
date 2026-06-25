#!/usr/bin/env python3
"""Smoke test for cloud/infra blast-radius guard (module 7)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from failsafe import check_cloud_infra

ASK   = "ask"
ALLOW = None

cases = [
    # --- terraform ---
    ("terraform destroy",           "terraform destroy",                                    ASK),
    ("terraform destroy -auto",     "terraform destroy -auto-approve",                      ASK),
    # --- kubectl ---
    ("kubectl delete namespace",    "kubectl delete namespace default",                     ASK),
    ("kubectl delete ns",           "kubectl delete ns kube-system",                        ASK),
    ("kubectl delete --all pods",   "kubectl delete pods --all",                            ASK),
    ("kubectl delete -A",           "kubectl delete pods -A",                               ASK),
    # --- docker ---
    ("docker system prune -a",      "docker system prune -a",                              ASK),
    ("docker system prune --all",   "docker system prune --all",                           ASK),
    ("docker volume rm",            "docker volume rm mydata",                             ASK),
    ("docker volume remove",        "docker volume remove pgdata",                         ASK),
    # --- aws ---
    ("aws s3 rm recursive",         "aws s3 rm s3://my-bucket --recursive",                ASK),
    ("aws s3 sync delete",          "aws s3 sync . s3://bucket --delete",                  ASK),
    # --- gcloud ---
    ("gcloud projects delete",      "gcloud projects delete my-project",                   ASK),
    # --- az ---
    ("az group delete",             "az group delete --name mygroup --yes",                ASK),
    # --- bash nested ---
    ("bash nested terraform",       'bash -c "terraform destroy"',                         ASK),
    # --- ALLOW ---
    ("terraform plan",              "terraform plan",                                      ALLOW),
    ("terraform apply",             "terraform apply",                                     ALLOW),
    ("kubectl get pods",            "kubectl get pods",                                    ALLOW),
    ("kubectl apply",               "kubectl apply -f deployment.yaml",                    ALLOW),
    ("kubectl delete pod single",   "kubectl delete pod my-pod",                           ALLOW),
    ("docker ps",                   "docker ps",                                           ALLOW),
    ("docker system prune no -a",   "docker system prune",                                 ALLOW),
    ("aws s3 ls",                   "aws s3 ls",                                           ALLOW),
    ("aws s3 cp",                   "aws s3 cp file.txt s3://bucket/",                     ALLOW),
]

passed = failed = 0
for label, cmd, expected in cases:
    result = check_cloud_infra(cmd)
    got = result[0] if result else None
    ok = (got == expected)
    if ok:
        passed += 1; print(f"PASS  {label}")
    else:
        failed += 1; print(f"FAIL  {label!r:<35}  expected={expected}  got={got}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
