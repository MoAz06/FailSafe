#!/usr/bin/env python3
"""Smoke test for manifest install parsing (module 4)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from failsafe import parse_manifest_targets

try:
    import tomllib  # noqa: F401
    HAVE_TOML = True
except ImportError:
    HAVE_TOML = False


PACKAGE_JSON = """{
  "name": "demo",
  "dependencies": {
    "express": "^4.18.0",
    "reqeusts-fake": "1.0.0",
    "@scope/thing": "^2.0.0",
    "local-dep": "file:../local",
    "git-dep": "git+https://example.com/x.git",
    "ws-dep": "workspace:*",
    "lodash": "npm:loadsh@1.0.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
"""

REQUIREMENTS = """# a comment
requests==2.31.0
reqeusts-fake>=1.0   # inline comment
flask
-r other.txt
-e .
./local/pkg
https://example.com/pkg.tar.gz
some-pkg @ https://example.com/x.whl
django ; python_version < "3.12"
pillow[extra]==10.0
"""

PYPROJECT_PEP621 = """
[project]
name = "demo"
dependencies = [
    "requests>=2.0",
    "reqeusts-fake==1.0",
    "httpx",
]

[project.optional-dependencies]
dev = ["pytest>=7", "black"]
"""

PYPROJECT_POETRY = """
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
loadsh-fake = "^1.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
"""


def write(d, name, content):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


passed = failed = 0


def check(label, got, expected):
    global passed, failed
    got_s = sorted(got)
    exp_s = sorted(expected)
    ok = got_s == exp_s
    if ok:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label!r}\n      expected={exp_s!r}\n      got={got_s!r}")


with tempfile.TemporaryDirectory() as d:
    write(d, "package.json", PACKAGE_JSON)
    write(d, "requirements.txt", REQUIREMENTS)

    # loadsh is the real pkg in npm alias "lodash": "npm:loadsh@1.0.0"
    expect_pkg = [("npm", "express"), ("npm", "reqeusts-fake"),
                  ("npm", "@scope/thing"), ("npm", "jest"), ("npm", "loadsh")]
    check("npm install -> package.json",
          parse_manifest_targets("npm install", d), expect_pkg)
    check("npm i (alias)",
          parse_manifest_targets("npm i", d), expect_pkg)
    check("npm ci -> nothing (uses lockfile, not package.json)",
          parse_manifest_targets("npm ci", d), [])
    check("pnpm install",
          parse_manifest_targets("pnpm install", d), expect_pkg)
    check("yarn (bare)",
          parse_manifest_targets("yarn", d), expect_pkg)
    check("bun install",
          parse_manifest_targets("bun install", d), expect_pkg)

    # direct install is NOT a manifest install (handled elsewhere)
    check("npm install express -> no manifest",
          parse_manifest_targets("npm install express", d), [])

    expect_req = [("pypi", "requests"), ("pypi", "reqeusts-fake"),
                  ("pypi", "flask"), ("pypi", "django"), ("pypi", "pillow")]
    check("pip install -r requirements.txt",
          parse_manifest_targets("pip install -r requirements.txt", d), expect_req)
    check("python -m pip install -r",
          parse_manifest_targets("python -m pip install -r requirements.txt", d), expect_req)
    check("uv pip install -r",
          parse_manifest_targets("uv pip install -r requirements.txt", d), expect_req)
    check("pip install (no -r) -> nothing",
          parse_manifest_targets("pip install", d), [])
    check("pip install -c constraints.txt -> nothing (constraints not install targets)",
          parse_manifest_targets("pip install -c requirements.txt", d), [])

    # bash-nested + chained
    check("bash -c nested npm install",
          parse_manifest_targets('bash -c "npm install"', d), expect_pkg)
    check("chained: echo && npm install",
          parse_manifest_targets("echo hi && npm install", d), expect_pkg)


# pyproject (needs tomllib)
with tempfile.TemporaryDirectory() as d:
    write(d, "pyproject.toml", PYPROJECT_PEP621)
    if HAVE_TOML:
        check("uv sync -> pep621 deps",
              parse_manifest_targets("uv sync", d),
              [("pypi", "requests"), ("pypi", "reqeusts-fake"),
               ("pypi", "httpx"), ("pypi", "pytest"), ("pypi", "black")])
    else:
        check("uv sync -> fail open (no tomllib)",
              parse_manifest_targets("uv sync", d), [])

with tempfile.TemporaryDirectory() as d:
    write(d, "pyproject.toml", PYPROJECT_POETRY)
    if HAVE_TOML:
        check("poetry install -> deps (python excluded)",
              parse_manifest_targets("poetry install", d),
              [("pypi", "requests"), ("pypi", "loadsh-fake"), ("pypi", "pytest")])
    else:
        check("poetry install -> fail open (no tomllib)",
              parse_manifest_targets("poetry install", d), [])


# missing manifest -> fail open, no crash
with tempfile.TemporaryDirectory() as d:
    check("npm install, no package.json -> []",
          parse_manifest_targets("npm install", d), [])

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
