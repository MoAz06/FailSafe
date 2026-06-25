#!/usr/bin/env python3
"""
FailSafe - Claude Code PreToolUse hook
-----------------------------------------------------------------------
The zero-config agent seatbelt for Claude Code. Blocks dangerous agent
actions even in --dangerously-skip-permissions (bypass) mode, where a
hook deny is the only safety layer that still fires.

Current rules:
  1. Slopsquatting defense - blocks installs of non-existent packages
     (AI hallucinated names attackers pre-register with malware).
  2. Destructive rm - blocks rm -rf on root, home, and system dirs.
  3. One-off runner defense - checks npx/npm exec/pnpm dlx/bunx targets
     before the agent executes registry code.
  4. Manifest install defense - reads package.json/requirements.txt/
     pyproject.toml on bare installs so a hallucinated dep hidden in a
     manifest is caught too.
  5. Curl-pipe-shell guard - blocks/flags remote scripts piped directly
     into a shell or interpreter (curl ... | bash, wget ... | python).
  6. Git disaster guard - blocks/flags force pushes to protected branches,
     hard resets, force cleans, and force branch deletions.
  7. Cloud/infra blast radius - flags terraform destroy, kubectl delete
     namespace, docker system prune -a, aws s3 rm --recursive, etc.
  8. Secrets exfiltration guard - flags sensitive files (.env, ~/.ssh,
     keys) piped or sent to network commands.

Design rules:
  - FAIL OPEN. Any unexpected error -> allow. A guard that breaks your
    workflow gets uninstalled.
  - FAST PATH. Non-relevant commands return instantly, no network.
  - CONSERVATIVE. Only near-certain danger hard-blocks. Fuzzy signals
    only escalate to a prompt.

Stdlib only -> zero install. Works wherever Python 3.8+ is present.
"""

import json
import os
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


def _load_config(cwd=None):
    """Load failsafe.toml (project-level first, then ~/.config/failsafe/). Returns {}."""
    search_cwd = cwd or os.getcwd()
    paths = [
        os.path.join(search_cwd, "failsafe.toml"),
        os.path.expanduser(os.path.join("~", ".config", "failsafe", "config.toml")),
    ]
    for p in paths:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except Exception:
            continue
        try:
            import tomllib
            return tomllib.loads(text).get("failsafe") or {}
        except Exception:
            return {}
    return {}


_CONFIG = _load_config()

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
POPULAR_CARGO = {
    "serde", "serde_json", "tokio", "async-std", "reqwest", "hyper",
    "clap", "log", "env_logger", "anyhow", "thiserror", "rand",
    "chrono", "uuid", "regex", "lazy_static", "once_cell", "rayon",
    "itertools", "futures", "async-trait", "tracing", "axum",
    "actix-web", "diesel", "sqlx", "rusqlite", "redis", "bytes",
    "tower", "syn", "quote", "proc-macro2", "nom", "bindgen",
    "wasm-bindgen", "pyo3", "crossbeam", "dashmap", "parking_lot",
}
PUBLIC_GO_DOMAINS = frozenset({
    "github.com", "gitlab.com", "bitbucket.org",
    "golang.org", "google.golang.org", "k8s.io", "sigs.k8s.io", "gopkg.in",
})

JS_MANAGERS = {
    "npm": {"install", "i", "add"},
    "pnpm": {"add", "install", "i"},
    "yarn": {"add"},
    "bun": {"add", "install", "i"},
}
CARGO_VALUE_FLAGS = frozenset({
    "--manifest-path", "--target", "--target-dir", "--features", "-F",
    "--branch", "--tag", "--rev", "--git", "--path", "--registry",
    "--vers", "--version", "--bin", "--example", "--root",
})
_CARGO_NON_REGISTRY = frozenset({"--git", "--path"})
CARGO_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")

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
JS_RUNNER_PACKAGE_FLAGS = {"--package", "-p"}
JS_RUNNER_VALUE_FLAGS = NPM_VALUE_FLAGS | {
    "--call", "-c", "--shell", "--script-shell", "--userconfig",
    "--node-arg", "-n",
}

SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"env", "sudo", "doas", "command", "time", "nice", "exec", "xargs"}
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
OPERATORS = {"&&", "||", ";", "|", "&", "|&"}

WRAPPER_VALUE_FLAGS = {
    "sudo": {
        "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
        "-C", "--close-from", "-T", "--command-timeout", "-D", "--chdir",
    },
    "doas": {"-u", "--user"},
    "env": {
        "-u", "--unset", "-C", "--chdir", "-S", "--split-string",
        "--block-signal", "--default-signal", "--ignore-signal",
    },
    "time": {"-o", "--output", "-f", "--format"},
    "nice": {"-n", "--adjustment"},
}

NPM_NAME_RE = re.compile(r"^(@[a-z0-9\-~][a-z0-9\-._~]*/)?[a-z0-9\-~][a-z0-9\-._~]*$", re.I)
PY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


# --------------------------------------------------------------- HTTP
def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "failsafe/0.5"})
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


def _consume_wrapper_options(tokens, i, wrapper):
    """Skip common wrapper flags so sudo -n rm ... still exposes rm."""
    value_flags = WRAPPER_VALUE_FLAGS.get(wrapper, set())
    while i < len(tokens):
        t = tokens[i]
        if t == "--":
            return i + 1
        if ENV_ASSIGN_RE.match(t):
            i += 1
            continue
        if not t.startswith("-") or t == "-":
            return i

        takes_value = t in value_flags
        has_inline_value = any(t.startswith(flag + "=") for flag in value_flags)
        has_short_inline_value = len(t) > 2 and t[:2] in value_flags

        i += 1
        if takes_value and not has_inline_value and not has_short_inline_value and i < len(tokens):
            i += 1
    return i


def strip_prefix(tokens):
    """Drop leading env assignments and wrappers: env FOO=bar sudo npm ..."""
    i = 0
    while i < len(tokens):
        if ENV_ASSIGN_RE.match(tokens[i]):
            i += 1
            continue
        if tokens[i] in WRAPPERS:
            wrapper = tokens[i]
            i += 1
            i = _consume_wrapper_options(tokens, i, wrapper)
            continue
        break
    return tokens[i:]


def split_segments(toks):
    """Split a token list into segments on shell control operators."""
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
    return segments


def add_js_target(arg, targets):
    if not arg or arg.startswith("-") or arg in (".", ".."):
        return False
    if is_js_local_or_url(arg):
        return False
    name = strip_npm_version(arg)
    if name and not name.startswith("-") and NPM_NAME_RE.match(name):
        targets.append(("npm", name))
        return True
    return False


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
        add_js_target(a, targets)


def _flag_value(token, flags):
    for flag in flags:
        prefix = flag + "="
        if token.startswith(prefix):
            return token[len(prefix):]
    return None


def collect_js_runner(args, targets):
    """Collect packages executed by npx/npm exec/pnpm dlx/bunx style runners."""
    skip_next = False
    explicit_package = False
    after_double_dash = False

    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue

        if not after_double_dash:
            if a == "--":
                after_double_dash = True
                continue

            value = _flag_value(a, JS_RUNNER_PACKAGE_FLAGS)
            if value is not None:
                if add_js_target(value, targets):
                    explicit_package = True
                continue

            if a in JS_RUNNER_PACKAGE_FLAGS:
                if i + 1 < len(args) and add_js_target(args[i + 1], targets):
                    explicit_package = True
                skip_next = True
                continue

            if a in JS_RUNNER_VALUE_FLAGS:
                skip_next = True
                continue
            if _flag_value(a, JS_RUNNER_VALUE_FLAGS) is not None:
                continue
            if a.startswith("-"):
                continue

        if explicit_package:
            return
        add_js_target(a, targets)
        return


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


def collect_cargo(args, targets):
    for a in args:
        if any(a == f or a.startswith(f + "=") for f in _CARGO_NON_REGISTRY):
            return  # --git or --path: not a registry install
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in CARGO_VALUE_FLAGS:
            skip_next = True
            continue
        if any(a.startswith(f + "=") for f in CARGO_VALUE_FLAGS):
            continue
        if a.startswith("-"):
            continue
        name = a.split("@")[0]
        if name and CARGO_NAME_RE.match(name):
            targets.append(("cargo", name))


def collect_go(args, targets):
    for a in args:
        if a.startswith("-"):
            continue
        mod = a.split("@")[0]
        parts = mod.split("/")
        if not parts or parts[0].lower() not in PUBLIC_GO_DOMAINS:
            continue  # private/unknown domain -> skip (avoid false positives)
        targets.append(("go", mod))


def tokenize(command):
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars="|&;")
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return command.split()


def parse_install_targets(command, _depth=0):
    toks = tokenize(command)
    targets = []
    for tokens in split_segments(toks):
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
        if mgr == "npx":
            collect_js_runner(rest, targets)
            continue
        if mgr == "npm":
            if rest and rest[0] in ("exec", "x"):
                collect_js_runner(rest[1:], targets)
                continue
        if mgr == "pnpm" and rest and rest[0] == "dlx":
            collect_js_runner(rest[1:], targets)
            continue
        if mgr == "bunx":
            collect_js_runner(rest, targets)
            continue
        if mgr == "bun" and rest and rest[0] == "x":
            collect_js_runner(rest[1:], targets)
            continue
        if mgr == "yarn" and rest and rest[0] == "dlx":
            collect_js_runner(rest[1:], targets)
            continue
        if mgr == "cargo":
            if rest and rest[0] in ("add", "install"):
                collect_cargo(rest[1:], targets)
            continue

        if mgr == "go":
            if rest and rest[0] in ("get", "install"):
                collect_go(rest[1:], targets)
            continue

        if mgr in JS_MANAGERS:
            if rest and rest[0] in JS_MANAGERS[mgr]:
                collect_js(rest[1:], targets, NPM_VALUE_FLAGS)
            continue
    return targets


# ----------------------------------------- manifest install check
#
# Threat model: an agent invents a package name, writes it into a manifest
# (requirements.txt, package.json, pyproject.toml), then runs a *bare* install
# such as `npm install` or `pip install -r requirements.txt`. The direct-arg
# parser above never sees the package because it lives in a file. Here we read
# the relevant source manifest and feed its declared packages through the same
# registry checks.
#
# Source manifests only -- generated lockfiles (package-lock.json,
# pnpm-lock.yaml, yarn.lock) are not parsed: an agent is unlikely to hand-edit
# them, and YAML has no stdlib parser. pyproject.toml needs tomllib (Python
# 3.11+); on older Python we fail open rather than guess at TOML.

MAX_MANIFEST_BYTES = 512 * 1024  # don't slurp a giant generated file

# npm bare-install verbs (no positional package => install from package.json)
JS_INSTALL_VERBS = {
    "npm": {"install", "i"},
    "pnpm": {"install", "i"},
    "yarn": {"install"},
    "bun": {"install", "i"},
}

# package.json spec values that point at something other than a registry name
_JS_SKIP_SPEC_PREFIXES = (
    "file:", "link:", "portal:", "workspace:", "git+", "git:",
    "github:", "gitlab:", "bitbucket:", "http:", "https:",
)


def _read_text(path):
    try:
        if os.path.getsize(path) > MAX_MANIFEST_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _abs(path, cwd):
    return path if os.path.isabs(path) else os.path.join(cwd, path)


def _parse_package_json(text):
    targets = []
    try:
        data = json.loads(text)
    except Exception:
        return targets
    if not isinstance(data, dict):
        return targets
    for key in ("dependencies", "devDependencies",
                "optionalDependencies", "peerDependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            if not isinstance(name, str):
                continue
            if isinstance(spec, str):
                sl = spec.lower()
                if sl.startswith(_JS_SKIP_SPEC_PREFIXES):
                    continue  # local path, git, url, or workspace alias
                # npm alias: "alias": "npm:real-pkg@version" -- check real pkg
                if sl.startswith("npm:"):
                    real = strip_npm_version(spec[4:])
                    if real and NPM_NAME_RE.match(real):
                        targets.append(("npm", real))
                    continue
            if NPM_NAME_RE.match(name):
                targets.append(("npm", name))
    return targets


def _parse_requirements(text):
    targets = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:  # strip trailing inline comment
            line = line.split(" #", 1)[0].strip()
        if line.startswith("-"):
            continue  # -r/-c includes, -e editable, --hash, other options
        if "://" in line or line.startswith("git+") or " @ " in line:
            continue  # url / direct reference
        if "/" in line or "\\" in line:
            continue  # local path
        name = strip_py_version(line).strip()
        if name and PY_NAME_RE.match(name):
            targets.append(("pypi", name))
    return targets


def _pep508_name(dep):
    if not isinstance(dep, str):
        return None
    name = strip_py_version(dep).strip()
    return name if name and PY_NAME_RE.match(name) else None


def _parse_pyproject(text):
    targets = []
    try:
        import tomllib
    except ImportError:
        return targets  # Python < 3.11: fail open
    try:
        data = tomllib.loads(text)
    except Exception:
        return targets
    if not isinstance(data, dict):
        return targets

    # PEP 621: [project] dependencies + optional-dependencies
    project = data.get("project") or {}
    if isinstance(project, dict):
        for dep in project.get("dependencies") or []:
            name = _pep508_name(dep)
            if name:
                targets.append(("pypi", name))
        opt = project.get("optional-dependencies") or {}
        if isinstance(opt, dict):
            for group in opt.values():
                for dep in group or []:
                    name = _pep508_name(dep)
                    if name:
                        targets.append(("pypi", name))

    # Poetry: [tool.poetry.dependencies] (table: name = version)
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    if isinstance(poetry, dict):
        tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for g in groups.values():
                if isinstance(g, dict):
                    tables.append(g.get("dependencies"))
        for table in tables:
            if not isinstance(table, dict):
                continue
            for name in table:
                if not isinstance(name, str) or name.lower() == "python":
                    continue
                if PY_NAME_RE.match(name):
                    targets.append(("pypi", name))
    return targets


def _parse_package_lock(text):
    """Parse npm package-lock.json v2/v3 -> list of (npm, name) targets."""
    targets = []
    try:
        data = json.loads(text)
    except Exception:
        return targets
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return targets
    for key in packages:
        if not key.startswith("node_modules/"):
            continue
        inner = key[len("node_modules/"):]
        if "/node_modules/" in inner:
            continue  # nested dep
        if inner.startswith("@"):
            if inner.count("/") != 1:
                continue  # not @scope/name
        elif "/" in inner:
            continue  # nested path
        if NPM_NAME_RE.match(inner):
            targets.append(("npm", inner))
    return targets


def _parse_yarn_lock(text):
    """Parse yarn.lock v1 -> list of (npm, name) targets."""
    targets, seen = [], set()
    for line in text.splitlines():
        if line.startswith(" ") or line.startswith("\t") or not line.strip():
            continue
        if line.startswith("#"):
            continue
        # Entry header: 'express@^4.0.0:' or '"@scope/pkg@^1.0.0, @scope/pkg@^2.0.0":'
        line = line.rstrip(":").strip().strip('"')
        for entry in line.split(", "):
            entry = entry.strip().strip('"')
            if not entry or "@" not in entry:
                continue
            if entry.startswith("@"):
                at = entry.find("@", 1)
                name = entry[:at] if at > 0 else entry
            else:
                name = entry.split("@")[0]
            name = name.strip()
            if name and name not in seen and NPM_NAME_RE.match(name):
                seen.add(name)
                targets.append(("npm", name))
    return targets


def _parse_poetry_lock(text):
    """Parse poetry.lock (TOML) -> list of (pypi, name) targets."""
    targets = []
    try:
        import tomllib
    except ImportError:
        return targets
    try:
        data = tomllib.loads(text)
    except Exception:
        return targets
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if name and PY_NAME_RE.match(name):
            targets.append(("pypi", name))
    return targets


def _npm_prefix_dir(args, cwd):
    """Honor --prefix DIR / -C DIR so we read the right package.json."""
    for i, a in enumerate(args):
        if a in ("--prefix", "-C", "--cwd") and i + 1 < len(args):
            return _abs(args[i + 1], cwd)
        for flag in ("--prefix=", "-C=", "--cwd="):
            if a.startswith(flag):
                return _abs(a[len(flag):], cwd)
    return cwd


def _requirement_files(args, cwd):
    files, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-r", "--requirement"):
            if i + 1 < len(args):
                files.append(_abs(args[i + 1], cwd))
                i += 2
                continue
        elif a.startswith("--requirement="):
            files.append(_abs(a.split("=", 1)[1], cwd))
        elif a.startswith("-r") and len(a) > 2:
            files.append(_abs(a[2:], cwd))
        i += 1
    return files


def _manifest_file(path, parser):
    text = _read_text(path)
    return parser(text) if text else []


def parse_manifest_targets(command, cwd, _depth=0):
    """Collect packages declared in a manifest that a bare install would pull."""
    if not cwd:
        cwd = os.getcwd()
    toks = tokenize(command)
    out = []
    for tokens in split_segments(toks):
        tokens = strip_prefix(tokens)
        if not tokens:
            continue
        mgr, rest = tokens[0], tokens[1:]

        if mgr in SHELLS and _depth < 2:
            for t in rest:
                if " " in t:
                    out.extend(parse_manifest_targets(t, cwd, _depth + 1))
            continue

        if mgr in ("python", "python3") and len(rest) >= 2 and rest[0] == "-m" and rest[1] == "pip":
            mgr, rest = "pip", rest[2:]

        # npm ci reads package-lock.json, not package.json
        if mgr == "npm" and rest and rest[0] == "ci":
            pkg_dir = _npm_prefix_dir(rest[1:], cwd)
            out += _manifest_file(os.path.join(pkg_dir, "package-lock.json"), _parse_package_lock)
            continue

        # JS bare install -> read package.json (only when no direct package arg)
        if mgr in JS_MANAGERS:
            is_install = (not rest and mgr == "yarn") or (rest and rest[0] in JS_INSTALL_VERBS[mgr])
            if is_install:
                direct = []
                collect_js(rest[1:] if rest else [], direct, NPM_VALUE_FLAGS)
                if not direct:  # direct args are handled by parse_install_targets
                    pkg_dir = _npm_prefix_dir(rest[1:] if rest else [], cwd)
                    out += _manifest_file(os.path.join(pkg_dir, "package.json"), _parse_package_json)
                    if mgr == "yarn":
                        out += _manifest_file(os.path.join(pkg_dir, "yarn.lock"), _parse_yarn_lock)
            continue

        if mgr in ("pip", "pip3") and rest and rest[0] == "install":
            for fp in _requirement_files(rest[1:], cwd):
                out += _manifest_file(fp, _parse_requirements)
            continue

        if mgr == "uv":
            if rest and rest[0] == "sync":
                out += _manifest_file(os.path.join(cwd, "pyproject.toml"), _parse_pyproject)
            elif len(rest) >= 2 and rest[0] == "pip" and rest[1] == "install":
                for fp in _requirement_files(rest[2:], cwd):
                    out += _manifest_file(fp, _parse_requirements)
            continue

        if mgr == "poetry" and rest and rest[0] == "install":
            lock = _manifest_file(os.path.join(cwd, "poetry.lock"), _parse_poetry_lock)
            out += lock if lock else _manifest_file(os.path.join(cwd, "pyproject.toml"), _parse_pyproject)
            continue

    return out


# ---------------------------------------- destructive command check

# Matches any rm flag combination that includes -r or -R
_RM_RECURSIVE_RE = re.compile(r"^-[a-zA-Z]*[rR][a-zA-Z]*$")

# Paths that are dangerous at the top level (rm -rf on these = catastrophe)
_SYSTEM_ROOTS = frozenset({
    "/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/lib32",
    "/boot", "/sys", "/proc", "/dev", "/opt", "/root", "/var", "/snap",
    "/run", "/srv",
})

# Home-dir aliases that mean "delete my entire home"
_HOME_ALIASES = frozenset({"~", "$HOME", "${HOME}", "$USERPROFILE", "${USERPROFILE}"})

_ROOT_GLOB_SUFFIXES = ("/*", "/**", "/{*,.*}")

# Git Bash maps Windows drives to /c/, /d/, etc. (single lowercase letter).
_WIN_DRIVE_RE = re.compile(r"^/([a-z])(/.*)?$", re.I)
_WIN_SYSTEM_SUBDIRS = frozenset({
    "windows", "program files", "program files (x86)", "programdata",
})
# Windows env vars for system dirs (Git Bash expands these as $VAR)
_WIN_ENV_SYSTEM = frozenset({
    "$systemroot", "${systemroot}", "$windir", "${windir}",
    "$programfiles", "${programfiles}",
})


def _path_is_dangerous(path):
    """Return a short description of why this path is dangerous, or None."""
    # Trailing slash does not change what you delete; keep "/" itself intact
    p = path.rstrip("/") or "/"

    if p == "/":
        return "the filesystem root (/)"

    if p in _HOME_ALIASES:
        return "your entire home directory (%s)" % p

    # ~/  with nothing meaningful after it (e.g. "~/" or "~/.")
    if re.match(r"^~/?\.?$", p):
        return "your entire home directory (~)"

    # Glob at root or home root: /* or ~/* or $HOME/*
    if p in {"/*", "~/*", "$HOME/*", "${HOME}/*"}:
        return "everything under %s" % p.rstrip("*")
    if p in {"~/{*,.*}", "$HOME/{*,.*}", "${HOME}/{*,.*}"}:
        return "everything in your home directory (%s)" % p

    for suffix in _ROOT_GLOB_SUFFIXES:
        if p.endswith(suffix):
            base = p[:-len(suffix)]
            if base in _SYSTEM_ROOTS:
                return "everything in a critical system directory (%s)" % p

    # Top-level system directories
    if p in _SYSTEM_ROOTS:
        return "a critical system directory (%s)" % p

    # /home or /home/<user> (one level: wipes a whole user account)
    if p == "/home":
        return "all user home directories (/home)"
    if re.match(r"^/home/[^/]+$", p):
        return "a user's entire home directory (%s)" % p

    # /home/<user>/* - glob that empties a home dir
    if re.match(r"^/home/[^/]+/\*$", p):
        return "everything in a home directory (%s)" % p
    if re.match(r"^/home/[^/]+/\{\*,\.\*\}$", p):
        return "everything in a home directory (%s)" % p

    # Repository metadata - wipes entire git history
    if p == ".git":
        return "the repository's git history (.git)"

    # Windows env var system dirs (Git Bash: $WINDIR, $SYSTEMROOT, $PROGRAMFILES)
    if p.lower() in _WIN_ENV_SYSTEM:
        return "a critical Windows system directory (%s)" % p

    # Git Bash Windows drive paths: /c = C:\, /c/Windows = C:\Windows, etc.
    m = _WIN_DRIVE_RE.match(p)
    if m:
        drive = m.group(1).upper()
        rest = (m.group(2) or "").strip("/")
        if not rest:
            return "the Windows %s:\\ drive root" % drive
        parts = [x for x in rest.split("/") if x]
        top = parts[0].lower()
        if top == "users":
            if len(parts) == 1:
                return "all Windows user home directories (%s:\\Users)" % drive
            sub = parts[1]
            if sub == "*":
                return "all Windows user home directories (%s:\\Users\\*)" % drive
            if len(parts) == 2:
                return "a Windows user's entire home directory (%s:\\Users\\%s)" % (drive, sub)
        if top in _WIN_SYSTEM_SUBDIRS:
            return "a critical Windows system directory (%s:\\%s)" % (drive, parts[0])

    return None


def check_destructive_rm(command, _depth=0):
    """Return (decision, reason) if command contains a dangerous rm, else None."""
    toks = tokenize(command)

    for tokens in split_segments(toks):
        tokens = strip_prefix(tokens)
        if not tokens:
            continue

        cmd = tokens[0]

        # Recurse into bash -c "rm -rf ..."
        if cmd in SHELLS and _depth < 2:
            for t in tokens[1:]:
                if " " in t:
                    result = check_destructive_rm(t, _depth + 1)
                    if result:
                        return result
            continue

        if cmd != "rm":
            continue

        # Parse flags and paths from rm arguments
        has_recursive = False
        paths = []
        end_of_flags = False

        for t in tokens[1:]:
            if end_of_flags:
                paths.append(t)
                continue
            if t == "--":
                end_of_flags = True
                continue
            if t.startswith("-") and len(t) > 1:
                if _RM_RECURSIVE_RE.match(t):
                    has_recursive = True
            else:
                paths.append(t)

        if not has_recursive:
            continue

        for path in paths:
            why = _path_is_dangerous(path)
            if why:
                return ("deny",
                    "FailSafe blocked a destructive command:\n\n"
                    "  rm -rf %s\n\n"
                    "This would permanently delete %s. "
                    "If you are certain this is correct, run it yourself outside the agent." % (path, why))

    return None


# ------------------------------------------ curl-pipe-shell guard

_FETCHERS = frozenset({"curl", "wget", "fetch", "aria2c", "http", "lwp-download"})
_PIPE_EXECUTORS = frozenset({
    "bash", "sh", "zsh", "dash", "ksh",
    "python", "python3", "ruby", "perl", "node", "nodejs",
})


def _segments_with_ops(toks):
    """Like split_segments but preserves the connecting operator per segment."""
    result, cur, op = [], [], None
    for t in toks:
        if t in OPERATORS:
            if cur:
                result.append((op, cur))
            cur, op = [], t
        else:
            cur.append(t)
    if cur:
        result.append((op, cur))
    return result


def _fetcher_url(args):
    for a in args:
        if a.startswith("http://") or a.startswith("https://"):
            return a
    return None


def check_curl_pipe_shell(command, _depth=0):
    """Return (decision, reason) if command pipes a remote fetch into a shell."""
    toks = tokenize(command)
    segs = _segments_with_ops(toks)

    for i, (_, seg) in enumerate(segs):
        seg_s = strip_prefix(seg)
        if not seg_s or seg_s[0] not in _FETCHERS:
            continue
        if i + 1 >= len(segs):
            continue
        next_op, next_seg = segs[i + 1]
        if next_op != "|":
            continue
        next_s = strip_prefix(next_seg)
        if not next_s or next_s[0] not in _PIPE_EXECUTORS:
            continue

        fetcher, executor = seg_s[0], next_s[0]
        url = _fetcher_url(seg_s[1:])

        if url and url.startswith("http://"):
            return ("deny",
                "FailSafe blocked a remote script over plain HTTP:\n\n"
                "  %s ... | %s\n\n"
                "Fetching over unencrypted HTTP lets a network attacker intercept "
                "and replace the script before it runs. "
                "If you need this script, switch to HTTPS and inspect it first." % (fetcher, executor))

        return ("ask",
            "FailSafe flagged a remote script execution:\n\n"
            "  %s ... | %s\n\n"
            "This downloads and immediately executes remote code without inspection. "
            "Review the script source before running it." % (fetcher, executor))

    if _depth < 2:
        for _, seg in segs:
            seg_s = strip_prefix(seg)
            if seg_s and seg_s[0] in SHELLS:
                for t in seg_s[1:]:
                    if " " in t:
                        result = check_curl_pipe_shell(t, _depth + 1)
                        if result:
                            return result
    return None


# ---------------------------------------------- git disaster guard

_GIT_PROTECTED_BRANCHES = frozenset({
    "main", "master", "production", "release", "prod", "staging",
})
_GIT_FORCE_FLAGS = frozenset({"--force", "-f", "--force-with-lease", "--force-if-includes"})
_GIT_SKIP_VALUE_FLAGS = frozenset({
    "--receive-pack", "--exec", "--repo", "-o", "--push-option",
    "--recurse-submodules", "--signed",
})


def _git_push_branch(subargs):
    """Return the destination branch from git push args, or None."""
    skip_next = False
    non_flag = []
    for a in subargs:
        if skip_next:
            skip_next = False
            continue
        if a in _GIT_SKIP_VALUE_FLAGS:
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        non_flag.append(a)
    # non_flag: [remote, refspec, ...]  refspec may be src:dst or branch
    for token in non_flag[1:]:
        dst = token.split(":")[-1].lstrip("+")
        if dst.startswith("refs/heads/"):
            dst = dst[len("refs/heads/"):]
        if dst:
            return dst
    return None


def check_git_disaster(command, _depth=0):
    """Return (decision, reason) for dangerous git operations, or None."""
    toks = tokenize(command)
    for tokens in split_segments(toks):
        tokens = strip_prefix(tokens)
        if not tokens:
            continue
        cmd = tokens[0]
        if cmd in SHELLS and _depth < 2:
            for t in tokens[1:]:
                if " " in t:
                    result = check_git_disaster(t, _depth + 1)
                    if result:
                        return result
            continue
        if cmd != "git":
            continue

        rest = tokens[1:]
        # Skip global git options like -C <dir>
        i = 0
        while i < len(rest):
            if rest[i] in ("-C", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(rest):
                i += 2
            elif rest[i].startswith("-"):
                i += 1
            else:
                break
        if i >= len(rest):
            continue
        subcmd, subargs = rest[i], rest[i + 1:]

        if subcmd == "reset" and ("--hard" in subargs or "--merge" in subargs):
            mode = "--hard" if "--hard" in subargs else "--merge"
            return ("ask",
                "FailSafe flagged a potentially destructive git operation:\n\n"
                "  git reset %s\n\n"
                "This discards all uncommitted changes and cannot be undone. "
                "Confirm this is intentional." % " ".join(subargs))

        if subcmd == "clean":
            flags_combined = "".join(
                a[1:] for a in subargs if re.match(r"^-[a-zA-Z]+$", a)
            )
            if "f" in flags_combined and "n" not in flags_combined:
                return ("ask",
                    "FailSafe flagged a potentially destructive git operation:\n\n"
                    "  git clean %s\n\n"
                    "This permanently deletes untracked files and cannot be undone. "
                    "Confirm this is intentional." % " ".join(subargs))

        if subcmd == "push":
            force_flags = [a for a in subargs if a in _GIT_FORCE_FLAGS
                           or a.startswith("--force-with-lease=")]
            plus_refspecs = [a for a in subargs
                             if not a.startswith("-") and a.startswith("+")]
            if force_flags or plus_refspecs:
                cfg_branches = _CONFIG.get("protected_branches")
                protected = (
                    frozenset(b.lower() for b in cfg_branches if isinstance(b, str))
                    if isinstance(cfg_branches, list)
                    else _GIT_PROTECTED_BRANCHES
                )
                branch = _git_push_branch(subargs)
                if branch and branch.lower() in protected:
                    return ("deny",
                        "FailSafe blocked a force push to a protected branch:\n\n"
                        "  git push %s\n\n"
                        "Force pushing to '%s' permanently overwrites remote history "
                        "and affects all collaborators. "
                        "If you are certain, run this yourself outside the agent." % (
                            " ".join(subargs), branch))
                return ("ask",
                    "FailSafe flagged a force push:\n\n"
                    "  git push %s\n\n"
                    "Force pushing rewrites remote history. "
                    "Confirm the target branch and that this is intentional." % " ".join(subargs))

        if subcmd == "branch":
            flags = [a for a in subargs if a.startswith("-")]
            branches = [a for a in subargs if not a.startswith("-")]
            flag_chars = "".join(a[1:] for a in flags if re.match(r"^-[a-zA-Z]+$", a))
            long_flags = set(flags)
            is_force_delete = (
                "D" in flag_chars
                or ("--delete" in long_flags and ("--force" in long_flags or "f" in flag_chars))
                or ("-d" in flags and ("--force" in long_flags or "f" in flag_chars))
            )
            if is_force_delete and branches:
                return ("ask",
                    "FailSafe flagged a force branch deletion:\n\n"
                    "  git branch -D %s\n\n"
                    "This deletes the branch even if it has unmerged commits. "
                    "Confirm this is intentional." % " ".join(branches))

    return None


# ------------------------------------------ cloud / infra blast-radius guard

_CLOUD_ASK_TMPL = (
    "FailSafe flagged a potentially destructive infrastructure command:\n\n"
    "  %s\n\n"
    "%s\n\n"
    "Confirm this is intentional before proceeding."
)


def check_cloud_infra(command, _depth=0):
    """Return (decision, reason) for high-blast-radius cloud/infra commands."""
    toks = tokenize(command)
    for tokens in split_segments(toks):
        tokens = strip_prefix(tokens)
        if not tokens:
            continue
        cmd = tokens[0]
        if cmd in SHELLS and _depth < 2:
            for t in tokens[1:]:
                if " " in t:
                    result = check_cloud_infra(t, _depth + 1)
                    if result:
                        return result
            continue
        rest = tokens[1:]

        if cmd == "terraform" and rest and rest[0] == "destroy":
            return ("ask", _CLOUD_ASK_TMPL % (
                "terraform destroy",
                "This tears down all infrastructure managed by this Terraform workspace."))

        if cmd == "kubectl" and rest and rest[0] == "delete":
            args = rest[1:]
            frag = "kubectl delete " + " ".join(args)
            if any(a in ("namespace", "ns") for a in args):
                return ("ask", _CLOUD_ASK_TMPL % (
                    frag, "This deletes an entire Kubernetes namespace and every resource in it."))
            if "--all" in args or "-A" in args or "--all-namespaces" in args:
                return ("ask", _CLOUD_ASK_TMPL % (
                    frag, "This deletes all matching Kubernetes resources."))

        if cmd == "docker":
            if (len(rest) >= 2 and rest[0] == "system" and rest[1] == "prune"
                    and ("--all" in rest or "-a" in rest)):
                return ("ask", _CLOUD_ASK_TMPL % (
                    "docker system prune -a",
                    "This removes all unused images, containers, networks, and build cache."))
            if len(rest) >= 2 and rest[0] == "volume" and rest[1] in ("rm", "remove"):
                return ("ask", _CLOUD_ASK_TMPL % (
                    "docker volume rm " + " ".join(rest[2:]),
                    "This permanently removes Docker volumes and their stored data."))

        if (cmd == "aws" and len(rest) >= 2 and rest[0] == "s3"
                and rest[1] in ("rm", "sync", "mv")
                and ("--recursive" in rest or "--delete" in rest)):
            return ("ask", _CLOUD_ASK_TMPL % (
                "aws s3 " + " ".join(rest[1:]),
                "This recursively deletes or overwrites S3 objects and cannot be undone."))

        if cmd == "gcloud" and len(rest) >= 2 and rest[0] == "projects" and rest[1] == "delete":
            return ("ask", _CLOUD_ASK_TMPL % (
                "gcloud projects delete " + " ".join(rest[2:]),
                "This schedules a GCP project for deletion, removing all its resources."))

        if cmd == "az" and len(rest) >= 2 and rest[0] == "group" and rest[1] == "delete":
            return ("ask", _CLOUD_ASK_TMPL % (
                "az group delete " + " ".join(rest[2:]),
                "This deletes an Azure resource group and all resources inside it."))

    return None


# ------------------------------------------ secrets exfiltration guard

_SENSITIVE_RE = [
    re.compile(r"(^|[\\/])\.env(\.[a-zA-Z]+)?$"),
    re.compile(r"(^|[\\/])\.ssh([\\/]|$)"),
    re.compile(r"\.(pem|key|p12|pfx|crt|cer|jks)$", re.I),
    re.compile(r"(^|[\\/])(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?$"),
    re.compile(r"(^|[\\/])(\.netrc|\.npmrc|\.pypirc)$"),
    re.compile(r"(^|[\\/])\.aws[\\/]credentials$"),
]

_NETWORK_SENDERS = frozenset({
    "curl", "wget", "scp", "rsync", "nc", "netcat", "ncat", "socat",
    "ftp", "sftp", "aws", "gcloud", "gsutil",
})
_FILE_READERS = frozenset({"cat", "head", "tail", "tee"})
_CURL_DATA_FLAGS = frozenset({
    "-d", "--data", "--data-binary", "--data-raw", "--data-ascii",
    "--data-urlencode", "-F", "--form", "--upload-file", "-T",
})


def _is_sensitive(path):
    for pat in _SENSITIVE_RE:
        if pat.search(path):
            return True
    return False


def _curl_sensitive_file(args):
    """Return sensitive filename if curl is reading one via @file or -T."""
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a in _CURL_DATA_FLAGS:
            skip_next = True
            if i + 1 < len(args):
                val = args[i + 1]
                # -F name=@file  or  -d @file
                f = val.split("=@", 1)[1] if "=@" in val else val.lstrip("@")
                if _is_sensitive(f):
                    return f
            continue
        if "=" in a:
            key, _, val = a.partition("=")
            if key in _CURL_DATA_FLAGS:
                val = val.lstrip("@")
                if _is_sensitive(val):
                    return val
    return None


def check_secrets_exfil(command, _depth=0):
    """Return (decision, reason) if command appears to leak sensitive files."""
    toks = tokenize(command)
    segs = _segments_with_ops(toks)

    # Pattern 1: cat/head/tail <sensitive> | <network_cmd>
    for i, (_, seg) in enumerate(segs):
        seg_s = strip_prefix(seg)
        if not seg_s or seg_s[0] not in _FILE_READERS:
            continue
        sensitive = [a for a in seg_s[1:] if not a.startswith("-") and _is_sensitive(a)]
        if not sensitive:
            continue
        for j in range(i + 1, len(segs)):
            jop, jseg = segs[j]
            if jop != "|":
                break
            jseg_s = strip_prefix(jseg)
            if jseg_s and jseg_s[0] in _NETWORK_SENDERS:
                return ("ask",
                    "FailSafe flagged a possible secrets leak:\n\n"
                    "  %s\n\n"
                    "A sensitive file (%s) is being piped into a network command. "
                    "Confirm this is intentional." % (" ".join(toks), sensitive[0]))

    # Pattern 2: curl/wget -d @<sensitive>
    for _, seg in segs:
        seg_s = strip_prefix(seg)
        if not seg_s or seg_s[0] not in {"curl", "wget", "http"}:
            continue
        f = _curl_sensitive_file(seg_s[1:])
        if f:
            return ("ask",
                "FailSafe flagged a possible secrets leak:\n\n"
                "  %s\n\n"
                "A sensitive file (%s) is being sent to a remote server. "
                "Confirm this is intentional." % (" ".join(toks), f))

    # Pattern 3a: tar <flags> <sensitive> | <network_cmd>
    for i, (_, seg) in enumerate(segs):
        seg_s = strip_prefix(seg)
        if not seg_s or seg_s[0] != "tar":
            continue
        sensitive = [a for a in seg_s[1:]
                     if a != "-" and not a.startswith("-") and _is_sensitive(a)]
        if not sensitive:
            continue
        for j in range(i + 1, len(segs)):
            jop, jseg = segs[j]
            if jop != "|":
                break
            jseg_s = strip_prefix(jseg)
            if jseg_s and jseg_s[0] in _NETWORK_SENDERS:
                return ("ask",
                    "FailSafe flagged a possible secrets leak:\n\n"
                    "  %s\n\n"
                    "Sensitive files (%s) are being archived and piped to a network command. "
                    "Confirm this is intentional." % (" ".join(toks), sensitive[0]))

    # Pattern 3: scp/rsync <sensitive> <remote:path>
    for _, seg in segs:
        seg_s = strip_prefix(seg)
        if not seg_s or seg_s[0] not in {"scp", "rsync"}:
            continue
        non_flags = [a for a in seg_s[1:] if not a.startswith("-")]
        if len(non_flags) >= 2:
            src, dst = non_flags[0], non_flags[-1]
            if ":" in dst and _is_sensitive(src):
                return ("ask",
                    "FailSafe flagged a possible secrets leak:\n\n"
                    "  %s\n\n"
                    "A sensitive file (%s) is being copied to a remote destination. "
                    "Confirm this is intentional." % (" ".join(toks), src))

    # Pattern 4: aws s3 cp/mv <sensitive> s3://...
    for _, seg in segs:
        seg_s = strip_prefix(seg)
        if not seg_s or seg_s[0] != "aws":
            continue
        rest = seg_s[1:]
        if len(rest) < 2 or rest[0] != "s3" or rest[1] not in ("cp", "mv"):
            continue
        non_flags = [a for a in rest[2:] if not a.startswith("-")]
        if len(non_flags) >= 2:
            src, dst = non_flags[0], non_flags[-1]
            if dst.startswith("s3://") and _is_sensitive(src):
                return ("ask",
                    "FailSafe flagged a possible secrets leak:\n\n"
                    "  %s\n\n"
                    "A sensitive file (%s) is being uploaded to S3. "
                    "Confirm this is intentional." % (" ".join(toks), src))

    if _depth < 2:
        for _, seg in segs:
            seg_s = strip_prefix(seg)
            if seg_s and seg_s[0] in SHELLS:
                for t in seg_s[1:]:
                    if " " in t:
                        result = check_secrets_exfil(t, _depth + 1)
                        if result:
                            return result

    return None


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
    downloads = None
    _, dd = http_get_json("https://pypistats.org/api/packages/" + urllib.parse.quote(name.lower()) + "/recent")
    if dd and isinstance((dd.get("data") or {}).get("last_month"), (int, float)):
        downloads = int(dd["data"]["last_month"])
    return {"exists": True, "age_days": age_days(earliest), "downloads": downloads}


LOW_CARGO_DOWNLOADS = 500  # recent_downloads threshold (90-day window from crates.io)


def check_cargo(name):
    req = urllib.request.Request(
        "https://crates.io/api/v1/crates/" + urllib.parse.quote(name, safe=""),
        headers={"User-Agent": "failsafe/0.5 (github.com/MoAz06/FailSafe)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            if getattr(r, "status", 200) != 200:
                return {"exists": None}
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"exists": False} if e.code == 404 else {"exists": None}
    except Exception:
        return {"exists": None}
    krate = data.get("crate") or {}
    created = parse_dt(krate.get("created_at"))
    downloads = krate.get("recent_downloads") or krate.get("downloads")
    return {"exists": True, "age_days": age_days(created), "downloads": downloads}


def check_go(module):
    # Go proxy encoding: uppercase letter X -> !x
    encoded = re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), module)
    url = "https://proxy.golang.org/" + encoded + "/@v/list"
    req = urllib.request.Request(url, headers={"User-Agent": "failsafe/0.5"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            return {"exists": getattr(r, "status", 200) == 200}
    except urllib.error.HTTPError as e:
        return {"exists": False} if e.code in (404, 410, 451) else {"exists": None}
    except Exception:
        return {"exists": None}


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

    allowed = _CONFIG.get("allowed_packages")
    if isinstance(allowed, list) and name.lower() in {a.lower() for a in allowed if isinstance(a, str)}:
        return ("allow", name, "")

    if ecosystem == "npm":
        info, registry, popular = check_npm(name), "the npm registry", POPULAR_NPM
    elif ecosystem == "pypi":
        info, registry, popular = check_pypi(name), "PyPI", POPULAR_PYPI
    elif ecosystem == "cargo":
        info, registry, popular = check_cargo(name), "crates.io", POPULAR_CARGO
    elif ecosystem == "go":
        info, registry, popular = check_go(name), "the Go module proxy", set()
    else:
        return ("allow", name, "")

    if info["exists"] is False:
        return ("deny", name, "not found on " + registry)
    if info["exists"] is not True:
        return ("allow", name, "")

    reasons = []
    if popular:
        look = nearest_popular(name.lower(), popular)
        if look:
            reasons.append('one character away from the popular package "%s" (possible look-alike)' % look)
    dl_threshold = LOW_CARGO_DOWNLOADS if ecosystem == "cargo" else LOW_DOWNLOADS
    if (info.get("age_days") is not None and info["age_days"] < NEW_PACKAGE_DAYS
            and info.get("downloads") is not None and info["downloads"] < dl_threshold):
        reasons.append("first published %d days ago with only ~%d downloads"
                       % (round(info["age_days"]), info["downloads"]))
    if reasons:
        return ("ask", name, "; ".join(reasons))
    return ("allow", name, "")


def _strict(result):
    """Upgrade 'ask' -> 'deny' when strict mode is enabled in config."""
    if result and result[0] == "ask" and _CONFIG.get("strict"):
        return ("deny", result[1])
    return result


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

        # Reload config using the project cwd from the payload.
        # The module-level _CONFIG was loaded at import using the hook's own
        # working directory, which may differ from the project being worked on.
        global _CONFIG
        cwd = data.get("cwd") or os.getcwd()
        _CONFIG = _load_config(cwd)

        # Rule 2: destructive rm (instant, no network)
        rm_result = check_destructive_rm(command)
        if rm_result:
            decision, reason = rm_result
            emit(decision, reason)

        # Rule 6: git disaster (instant, no network)
        git_result = _strict(check_git_disaster(command))
        if git_result:
            decision, reason = git_result
            emit(decision, reason)

        # Rule 7: cloud/infra blast radius (instant, no network)
        cloud_result = _strict(check_cloud_infra(command))
        if cloud_result:
            decision, reason = cloud_result
            emit(decision, reason)

        # Rule 5: curl/wget piped into shell (instant, no network)
        pipe_result = _strict(check_curl_pipe_shell(command))
        if pipe_result:
            decision, reason = pipe_result
            emit(decision, reason)

        # Rule 8: secrets exfiltration (instant, no network)
        exfil_result = _strict(check_secrets_exfil(command))
        if exfil_result:
            decision, reason = exfil_result
            emit(decision, reason)

        # Rules 1 + 3 + 4: slopsquatting / one-off runners / manifest installs
        targets = parse_install_targets(command)
        targets += parse_manifest_targets(command, cwd)
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
                 "FailSafe blocked this install:\n%s\n\n"
                 "AI assistants sometimes invent package names that don't exist; attackers "
                 "pre-register those names with malware (\"slopsquatting\"). Verify the correct "
                 "name on the official registry before installing. If you're certain it's "
                 "legitimate, install it yourself outside the agent." % listing)
        if asks:
            listing = "\n".join("  - %s: %s" % (n, r) for n, r in asks)
            pkg_ask = _strict(("ask",
                 "FailSafe flagged a possibly suspicious package:\n%s\n\n"
                 "Review before installing." % listing))
            emit(*pkg_ask)
    except Exception:
        pass  # fail open
    sys.exit(0)


if __name__ == "__main__":
    main()
