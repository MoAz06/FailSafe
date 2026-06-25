#!/usr/bin/env python3
"""Tests for failsafe.toml config (protected_branches, allowed_packages, strict)."""
import importlib
import json
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(__file__))

passed = failed = 0


def check(label, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label!r:<50}  expected={expected!r}  got={got!r}")


def _reload_with_config(toml_text, cwd):
    """Reload failsafe with a specific failsafe.toml in cwd."""
    orig_cwd = os.getcwd()
    try:
        os.chdir(cwd)
        import failsafe
        importlib.reload(failsafe)
        return failsafe
    finally:
        os.chdir(orig_cwd)


# --- protected_branches ---

with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, "failsafe.toml"), "w") as f:
        f.write('[failsafe]\nprotected_branches = ["deploy", "live"]\n')
    fs = _reload_with_config("", tmp)

    r = fs.check_git_disaster("git push origin deploy --force")
    check("custom branch 'deploy' -> deny",   r[0] if r else None, "deny")

    r = fs.check_git_disaster("git push origin live --force")
    check("custom branch 'live' -> deny",     r[0] if r else None, "deny")

    r = fs.check_git_disaster("git push origin main --force")
    check("'main' not in custom list -> ask", r[0] if r else None, "ask")

# --- allowed_packages ---

with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, "failsafe.toml"), "w") as f:
        f.write('[failsafe]\nallowed_packages = ["internal-tool", "my-private-pkg"]\n')
    fs = _reload_with_config("", tmp)

    r = fs.evaluate(("npm", "internal-tool"))
    check("allowed_packages npm skip -> allow", r[0], "allow")

    r = fs.evaluate(("pypi", "my-private-pkg"))
    check("allowed_packages pypi skip -> allow", r[0], "allow")

# --- strict mode ---

with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, "failsafe.toml"), "w") as f:
        f.write('[failsafe]\nstrict = true\n')
    fs = _reload_with_config("", tmp)

    r = fs._strict(("ask", "some reason"))
    check("strict=true: ask -> deny",    r[0], "deny")

    r = fs._strict(("deny", "some reason"))
    check("strict=true: deny stays deny", r[0], "deny")

    r = fs._strict(None)
    check("strict=true: None stays None", r, None)

with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, "failsafe.toml"), "w") as f:
        f.write('[failsafe]\nstrict = false\n')
    fs = _reload_with_config("", tmp)

    r = fs._strict(("ask", "some reason"))
    check("strict=false: ask stays ask", r[0], "ask")

# --- no config -> defaults intact ---

with tempfile.TemporaryDirectory() as tmp:
    fs = _reload_with_config("", tmp)

    r = fs.check_git_disaster("git push origin main --force")
    check("no config: main still protected -> deny", r[0] if r else None, "deny")

    r = fs._strict(("ask", "msg"))
    check("no config: strict off -> ask stays ask", r[0], "ask")

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
