#!/usr/bin/env python3
"""Quick smoke test for package target parsing."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from failsafe import parse_install_targets


cases = [
    # (label, command, expected targets)
    # --- existing install paths ---
    ("npm install one", "npm install expres", [("npm", "expres")]),
    ("pip install one", "pip install reqeusts", [("pypi", "reqeusts")]),
    ("python -m pip", "python -m pip install urllib3", [("pypi", "urllib3")]),
    ("bash nested install", 'bash -c "npm install loadsh"', [("npm", "loadsh")]),
    ("semicolon no spaces", "npm install express;rm -rf /", [("npm", "express")]),
    ("and no spaces", "npm install express&&rm -rf /", [("npm", "express")]),
    ("pip semicolon no spaces", "pip install requests;rm -rf /", [("pypi", "requests")]),
    # --- module 3: one-off runners ---
    ("npx first arg only", "npx cowsay hello", [("npm", "cowsay")]),
    ("npx yes version", "npx -y prettier@latest --write .", [("npm", "prettier")]),
    ("npx package flag", "npx -p typescript tsc --version", [("npm", "typescript")]),
    ("npx package equals", "npx --package=tsx tsx script.ts", [("npm", "tsx")]),
    ("npx multiple packages", "npx -p typescript -p ts-node ts-node script.ts",
     [("npm", "typescript"), ("npm", "ts-node")]),
    ("npm exec implicit", "npm exec -- eslint --fix .", [("npm", "eslint")]),
    ("npm exec package flag", "npm exec --package typescript -- tsc --version",
     [("npm", "typescript")]),
    ("npm x alias", "npm x cowsay hello", [("npm", "cowsay")]),
    ("pnpm dlx", "pnpm dlx create-vite my-app", [("npm", "create-vite")]),
    ("bunx scoped", "bunx @angular/cli new app", [("npm", "@angular/cli")]),
    ("bun x alias", "bun x cowsay hello", [("npm", "cowsay")]),
    ("yarn dlx", "yarn dlx create-react-app my-app", [("npm", "create-react-app")]),
    ("bash nested runner", 'bash -c "npx cowsay hi"', [("npm", "cowsay")]),
    ("npx and no spaces", "npx cowsay&&rm -rf /", [("npm", "cowsay")]),
    # --- should ignore local paths / runner args ---
    ("npx local path", "npx ./scripts/tool.js arg", []),
    ("pnpm dlx local path", "pnpm dlx ../tool arg", []),
]

passed = failed = 0
for label, cmd, expected in cases:
    got = parse_install_targets(cmd)
    ok = (got == expected)
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
        print(f"{status}  {label}")
    else:
        failed += 1
        print(f"{status}  {label!r:<25}  expected={expected!r}  got={got!r}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
