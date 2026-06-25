#!/usr/bin/env python3
"""
SlopGuard - Claude Code PreToolUse hook
-----------------------------------------------------------------------
Blocks the agent from installing packages that do not exist on the
official registry (the #1 sign of an AI "hallucinated" package), and
warns on suspicious look-alikes. This defends against "slopsquatting":
attackers pre-register package names that LLMs commonly invent, then
ship malware to whoever installs them on the AI's suggestion.

Scope: inspects packages passed as direct arguments to an install
command (npm/pnpm/yarn/bun add|install, pip/uv/poetry install|add).
It does NOT yet inspect manifest installs (bare `npm install`,
`pip install -r`, `poetry install`, `uv sync`) or one-off runners
(npx/dlx/bunx).

Design rules:
  - FAIL OPEN. Any network/parse/unexpected error -> allow the install.
    A security tool that breaks your workflow gets uninstalled.
  - FAST PATH. Non-install Bash commands return instantly, no network.
  - CONSERVATIVE. Only "does not exist" hard-blocks (deny). Everything
    fuzzy (new + low downloads, look-alike) only escalates (ask).

Stdlib only -> zero install. Works wherever Python 3.8+ is present.
"""

import json
import re
import shlex
import sys
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

REQUEST_TIMEOUT = 3.5
NEW_PACKAGE_DAYS = 90
LOW_DOWNLOADS = 100
MAX_PACKAGES = 25  # beyond this, fail open rather than stall the agent

POPULAR_NPM = {
    "react", "react-dom", "react-router-dom", "lodash", "express", "axios",
    "chalk", "commander", "next", "vue", "typescript", "webpack", "eslint",
    "prettier", "jest", "vitest", "dotenv", "moment", "dayjs", "uuid",
    "classnames", "zod", "redux", "tailwindcss", "vite", "rollup", "node-fetch",
    "cross-env", "nodemon", "ts-node", "mongoose", "pg", "mysql2", "cors",
    "body-parser", "bcrypt", "jsonwebtoken", "socket.io",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pytest",
    "pydantic", "sqlalchemy", "boto3", "scipy", "matplotlib", "pillow",
    "urllib3", "certifi", "click", "rich", "tqdm", "beautifulsoup4",
    "scikit-learn", "tensorflow", "torch", "transformers", "openai",
    "anthropic", "aiohttp", "httpx", "uvicorn", "gunicorn", "celery", "redis",
    "psycopg2", "pymongo", "python-dotenv", "setuptools", "wheel", "black",
    "flake8", "mypy", "isort",
}

JS_MANAGERS = {
    "npm": {"install", "i", "add"},
    "pnpm": {"add", "install", "i"},
    "yarn": {"add"},
    "bun": {"add", "install", "i"},
}

# Options whose NEXT token is a value, not a package (prevents false positives
# like `pip install --platform win_amd64 requests` denying "win_amd64").
PIP_VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "--platform", "--python-version", "--implementation", "--abi",
    "-t", "--target", "--prefix", "--root", "--no-binary", "--only-binary",
    "--progress-bar", "--report", "--hash", "--cache-dir", "--log", "--python",
}
UV_VALUE_FLAGS = PIP_VALUE_FLAGS | {"--index", "--default-index", "--index-strategy", "-p"}
POETRY_VALUE_FLAGS = {"--group", "-G", "--source", "--extras", "-E", "--python", "--platform"}
NPM_VALUE_FLAGS = {
    "--registry", "--prefix", "-C", "--workspace", "-w", "--save-prefix",
    "--omit", "--include", "--tag", "--access", "--otp", "--loglevel", "--cache",
}

SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"env", "sudo", "doas", "command", "time", "nice", "exec", "xargs"}
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
OPERATORS = {"&&", "||", ";", "|", "&", "|&"}

NPM_NAME_RE = re.compile(r"^(@[a-z0-9\-~][a-z0-9\-._~]*/)?[a-z0-9\-~][a-z0-9\-._~]*$", re.I)
PY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


# --------------------------------------------------------------- HTTP
def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "slopguard/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            status = getattr(r, "status", 200)
            if 200 <= status < 300:
                return status, json.loads(r.read().decode("utf-8", "replace"))
            return status, None
    except urllib.error.HTTPError as e:
        return e.code, None  # 404 lands here
    except Exception:
        return 0, None  # network/timeout -> unknown -> fail open


# ----------------------------------------------------- command parsing
def strip_npm_version(arg):
    if arg.startswith("@"):
        i = arg.find("@", 1)
        return arg if i == -1 else arg[:i]
    i = arg.find("@")
    return arg if i == -1 else arg[:i]


def strip_py_version(arg):
    return re.split(r"[=<>!~ ;\[]", arg)[0]


def is_js_local_or_url(a):
    if a.startswith("@"):
        return False  # scoped package, not a path
    return ("/" in a or "\\" in a or "://" in a or a.startswith("git+")
            or a.startswith(".") or a.endswith(".tgz") or a.endswith(".tar.gz"))


def strip_prefix(tokens):
    """Drop leading env assignments and wrappers: env FOO=bar sudo npm ..."""
    i = 0
    while i < len(tokens) and (tokens[i] in WRAPPERS or ENV_ASSIGN_RE.match(tokens[i])):
        i += 1
    return tokens[i:]


def collect_js(args, targets, value_flags):
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in value_flags:
            skip_next = True
            continue
        if a.startswith("-") or a in (".", ".."):
            continue
        if is_js_local_or_url(a):
            continue
        name = strip_npm_version(a)
        if name and not name.startswith("-") and NPM_NAME_RE.match(name):
            targets.append(("npm", name))


def collect_py(args, targets, value_flags):
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in value_flags:
            skip_next = True  # next token is a value, not a package
            continue
        if a.startswith("-") or a in (".", ".."):
            continue
        if "/" in a or "\\" in a or "://" in a:
            continue
        if re.search(r"\.(txt|cfg|toml|ini|whl|zip)$", a, re.I) or a.endswith(".tar.gz"):
            continue
        name = strip_py_version(a)
        if name and not name.startswith("-") and PY_NAME_RE.match(name):
            targets.append(("pypi", name))


def parse_install_targets(command, _depth=0):
    try:
        toks = shlex.split(command, posix=True)  # quote-aware
    except ValueError:
        toks = command.split()

    # Split the token stream into segments on shell control operators.
    segments, cur = [], []
    for t in toks:
        if t in OPERATORS:
            if cur:
                segments.append(cur)
                cur = []
        else:
            cur.append(t)
    if cur:
        segments.append(cur)

    targets = []
    for tokens in segments:
        tokens = strip_prefix(tokens)
        if len(tokens) < 2:
            continue
        mgr, rest = tokens[0], tokens[1:]

        # Recurse into shell wrappers: bash -c "npm install x"
        if mgr in SHELLS and _depth < 2:
            for t in rest:
                if " " in t:  # a quoted inner command
                    targets.extend(parse_install_targets(t, _depth + 1))
            continue

        if mgr in ("python", "python3") and len(rest) >= 2 and rest[0] == "-m" and rest[1] == "pip":
            mgr, rest = "pip", rest[2:]

        if mgr == "uv":
            if len(rest) >= 2 and rest[0] == "pip" and rest[1] == "install":
                collect_py(rest[2:], targets, UV_VALUE_FLAGS)
            elif rest and rest[0] == "add":
                collect_py(rest[1:], targets, UV_VALUE_FLAGS)
            continue
        if mgr == "poetry":
            if rest and rest[0] == "add":
                collect_py(rest[1:], targets, POETRY_VALUE_FLAGS)
            continue
        if mgr in ("pip", "pip3"):
            if rest and rest[0] == "install":
                collect_py(rest[1:], targets, PIP_VALUE_FLAGS)
            continue
        if mgr in JS_MANAGERS:
            if rest and rest[0] in JS_MANAGERS[mgr]:
                collect_js(rest[1:], targets, NPM_VALUE_FLAGS)
            continue
    return targets


# ----------------------------------------------------- registry lookups
def parse_dt(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def age_days(dt):
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0


def npm_encode(name):
    return name.replace("/", "%2F") if name.startswith("@") else urllib.parse.quote(name)


def check_npm(name):
    status, data = http_get_json("https://registry.npmjs.org/" + npm_encode(name))
    if status == 404:
        return {"exists": False}
    if not data:
        return {"exists": None}
    created = parse_dt((data.get("time") or {}).get("created"))
    downloads = None
    _, dd = http_get_json("https://api.npmjs.org/downloads/point/last-month/" + npm_encode(name))
    if dd and isinstance(dd.get("downloads"), int):
        downloads = dd["downloads"]
    return {"exists": True, "age_days": age_days(created), "downloads": downloads}


def check_pypi(name):
    status, data = http_get_json("https://pypi.org/pypi/" + urllib.parse.quote(name) + "/json")
    if status == 404:
        return {"exists": False}
    if not data:
        return {"exists": None}
    earliest = None
    for files in (data.get("releases") or {}).values():
        for f in files or []:
            dt = parse_dt(f.get("upload_time_iso_8601") or f.get("upload_time"))
            if dt and (earliest is None or dt < earliest):
                earliest = dt
    return {"exists": True, "age_days": age_days(earliest), "downloads": None}


# --------------------------------------------------- look-alike check
def damerau_levenshtein(a, b):
    """Optimal string alignment: counts an adjacent transposition as 1."""
    m, n = len(a), len(b)
    if abs(m - n) > 1:
        return 2  # we only care about distance <= 1
    d = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        d[i][0] = i
    for j in range(n + 1):
        d[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[m][n]


def nearest_popular(name, popular):
    if name in popular:
        return None
    for p in popular:
        if damerau_levenshtein(name, p) == 1:
            return p
    return None


# ------------------------------------------------------------- evaluate
def evaluate(target):
    ecosystem, name = target
    info = check_npm(name) if ecosystem == "npm" else check_pypi(name)
    registry = "the npm registry" if ecosystem == "npm" else "PyPI"

    if info["exists"] is False:
        return ("deny", name, "not found on " + registry)
    if info["exists"] is not True:
        return ("allow", name, "")

    reasons = []
    popular = POPULAR_NPM if ecosystem == "npm" else POPULAR_PYPI
    look = nearest_popular(name.lower(), popular)
    if look:
        reasons.append('one character away from the popular package "%s" (possible look-alike)' % look)
    if (info.get("age_days") is not None and info["age_days"] < NEW_PACKAGE_DAYS
            and info.get("downloads") is not None and info["downloads"] < LOW_DOWNLOADS):
        reasons.append("first published %d days ago with only ~%d downloads/month"
                       % (round(info["age_days"]), info["downloads"]))
    if reasons:
        return ("ask", name, "; ".join(reasons))
    return ("allow", name, "")


def emit(decision, reason):
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def main():
    try:
        raw = sys.stdin.read()
        if not raw:
            return
        data = json.loads(raw)
        if data.get("tool_name") != "Bash":
            return
        command = (data.get("tool_input") or {}).get("command")
        if not command or not isinstance(command, str):
            return

        targets = parse_install_targets(command)
        seen, uniq = set(), []
        for t in targets:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        if not uniq or len(uniq) > MAX_PACKAGES:
            return  # fast path / too many to check quickly -> fail open

        with ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(evaluate, uniq))

        denies = [(n, r) for (lvl, n, r) in results if lvl == "deny"]
        asks = [(n, r) for (lvl, n, r) in results if lvl == "ask"]

        if denies:
            listing = "\n".join("  - %s: %s" % (n, r) for n, r in denies)
            emit("deny",
                 "SlopGuard blocked this install:\n%s\n\n"
                 "AI assistants sometimes invent package names that don't exist; attackers "
                 "pre-register those names with malware (\"slopsquatting\"). Verify the correct "
                 "name on the official registry before installing. If you're certain it's "
                 "legitimate, install it yourself outside the agent." % listing)
        if asks:
            listing = "\n".join("  - %s: %s" % (n, r) for n, r in asks)
            emit("ask",
                 "SlopGuard flagged a possibly suspicious package:\n%s\n\n"
                 "Review before installing." % listing)
    except Exception:
        pass  # fail open
    sys.exit(0)


if __name__ == "__main__":
    main()
