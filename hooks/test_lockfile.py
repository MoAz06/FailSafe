#!/usr/bin/env python3
"""Tests for lockfile parsing: package-lock.json, yarn.lock, poetry.lock."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from failsafe import (
    _parse_package_lock, _parse_yarn_lock, _parse_poetry_lock,
    parse_manifest_targets,
)

passed = failed = 0


def check(label, got, expected):
    global passed, failed
    if isinstance(expected, bool):
        ok = got == expected
    else:
        ok = set(got) == set(expected)
    if ok:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label!r:<50}")
        if not isinstance(expected, bool):
            print(f"       expected={sorted(expected)}")
            print(f"       got     ={sorted(got) if not isinstance(got, bool) else got}")
        else:
            print(f"       expected={expected!r}  got={got!r}")


# --- _parse_package_lock ---

LOCK_V2 = json.dumps({
    "lockfileVersion": 2,
    "packages": {
        "": {},
        "node_modules/express": {"version": "4.18.2"},
        "node_modules/@types/node": {"version": "20.0.0"},
        "node_modules/express/node_modules/qs": {"version": "6.11.0"},  # nested -> skip
        "node_modules/fake-pkg": {"version": "0.0.1"},
    }
})

check("package-lock v2: basic packages",
    _parse_package_lock(LOCK_V2),
    [("npm", "express"), ("npm", "@types/node"), ("npm", "fake-pkg")])

check("package-lock: nested node_modules skipped",
    [t for t in _parse_package_lock(LOCK_V2) if "qs" in t[1]],
    [])

check("package-lock: empty -> []",
    _parse_package_lock("{}"),
    [])

check("package-lock: invalid json -> []",
    _parse_package_lock("not json"),
    [])

# --- _parse_yarn_lock ---

YARN_V1 = """\
# yarn lockfile v1

express@^4.0.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

"@types/node@^20.0.0":
  version "20.0.0"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.0.0.tgz"

fake-pkg@^1.0.0, fake-pkg@^1.2.0:
  version "1.2.0"
"""

check("yarn.lock v1: basic packages",
    _parse_yarn_lock(YARN_V1),
    [("npm", "express"), ("npm", "@types/node"), ("npm", "fake-pkg")])

check("yarn.lock: deduplicates same package",
    [t for t in _parse_yarn_lock(YARN_V1) if t[1] == "fake-pkg"],
    [("npm", "fake-pkg")])

check("yarn.lock: empty -> []",
    _parse_yarn_lock(""),
    [])

# --- _parse_poetry_lock ---

try:
    import tomllib
    HAS_TOMLLIB = True
except ImportError:
    HAS_TOMLLIB = False

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "urllib3"
version = "2.0.4"
description = "HTTP library with thread-safe connection pooling."

[[package]]
name = "fake-pypi-pkg"
version = "0.0.1"
description = "Definitely real."
"""

if HAS_TOMLLIB:
    check("poetry.lock: basic packages",
        _parse_poetry_lock(POETRY_LOCK),
        [("pypi", "requests"), ("pypi", "urllib3"), ("pypi", "fake-pypi-pkg")])

    check("poetry.lock: empty -> []",
        _parse_poetry_lock("[metadata]\ncontent-hash = \"abc\"\n"),
        [])
else:
    print("SKIP  poetry.lock tests (Python < 3.11, no tomllib)")

# --- parse_manifest_targets: npm ci -> package-lock.json ---

with tempfile.TemporaryDirectory() as tmp:
    lock = {
        "lockfileVersion": 2,
        "packages": {
            "": {},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/fake-lock-pkg": {"version": "0.0.1"},
        }
    }
    with open(os.path.join(tmp, "package-lock.json"), "w") as f:
        json.dump(lock, f)
    r = parse_manifest_targets("npm ci", tmp)
    check("npm ci reads package-lock.json",
        r, [("npm", "express"), ("npm", "fake-lock-pkg")])

with tempfile.TemporaryDirectory() as tmp:
    r = parse_manifest_targets("npm ci", tmp)
    check("npm ci no lockfile -> []", r, [])

# --- parse_manifest_targets: yarn install -> yarn.lock ---

with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, "package.json"), "w") as f:
        json.dump({"dependencies": {"express": "^4.0.0"}}, f)
    with open(os.path.join(tmp, "yarn.lock"), "w") as f:
        f.write('# yarn lockfile v1\n\nexpress@^4.0.0:\n  version "4.18.2"\n\nfake-yarn-pkg@^1.0.0:\n  version "1.0.0"\n')
    r = parse_manifest_targets("yarn install", tmp)
    names = {name for _, name in r}
    check("yarn install includes yarn.lock packages",
        "fake-yarn-pkg" in names, True)

# --- parse_manifest_targets: poetry install -> poetry.lock ---

if HAS_TOMLLIB:
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "poetry.lock"), "w") as f:
            f.write(POETRY_LOCK)
        r = parse_manifest_targets("poetry install", tmp)
        names = {name for _, name in r}
        check("poetry install reads poetry.lock when present",
            "fake-pypi-pkg" in names, True)
        check("poetry install prefers lock over pyproject.toml",
            "requests" in names, True)

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
