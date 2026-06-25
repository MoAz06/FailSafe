# FailSafe

**The zero-config agent seatbelt for Claude Code.**

When you run an AI agent in autonomous mode, one bad command can delete your home directory, drop a production database, or install malware from a hallucinated package name. Claude Code has a permissions system for this -- but `--dangerously-skip-permissions` turns it all off.

FailSafe runs as a `PreToolUse` hook. **A hook deny still fires in bypass mode.** That is the whole point.

---

## Install

**From PyPI:**

```bash
pip install failsafe-hook
python -m failsafe_hook --install
```

**From source:**

```bash
git clone https://github.com/MoAz06/FailSafe.git
cd FailSafe
python install.py
```

`install.py` runs `pip install -e .` automatically if needed, then wires the hook.

That's it. FailSafe now runs automatically on every Claude Code session, including bypass mode.

**Check status / uninstall:**

```bash
python -m failsafe_hook --check
python -m failsafe_hook --uninstall
```

**Requirements:** Python 3.8+ on your PATH. No other dependencies.

---

## What it blocks

**Module 1 -- Slopsquatting**

AI assistants hallucinate package names. Attackers pre-register those names with malware and wait. This is called slopsquatting. In 2025, an estimated 28% of malicious packages were LLM-hallucinated versions of real ones, and 43% of hallucinated names recur on every run of the same prompt.

| Situation | Action |
| :-- | :-- |
| Package **does not exist** on npm / PyPI / crates.io / RubyGems / Go proxy | Deny |
| Exists but **one edit away** from a popular package (`expres` vs `express`) | Ask |
| Package exists but **< 90 days old** with **< 100 downloads/month** (npm/PyPI), **< 500** (Cargo), **< 1 000** total (RubyGems) | Ask |
| Everything else | Allow (silent) |

**Module 2 -- Destructive commands**

| Situation | Action |
| :-- | :-- |
| `rm -rf` on `/`, `~`, `$HOME`, `/etc`, `/usr`, `/home/<user>`, system dirs, or root globs | Deny |
| `rm -rf .git` (destroys repo history) | Deny |
| Windows paths: `/c/`, `/c/Users`, `$USERPROFILE`, `$WINDIR`, `$SYSTEMROOT` | Deny |
| `rm -rf` on relative paths, `/tmp/...`, or deep subdirectories | Allow |

**Module 3 -- One-off runners**

| Situation | Action |
| :-- | :-- |
| `npx`, `npm exec`, `pnpm dlx`, `bunx`, `bun x`, `yarn dlx` runs a non-existent package | Deny |
| Runner target is a look-alike or suspiciously fresh | Ask |
| Local paths such as `npx ./scripts/tool.js` | Allow |

**Module 4 -- Manifest installs**

A bare install pulls every dependency from a manifest file. An agent can inject a hallucinated package into `package.json` or `requirements.txt` and then run a bare install. FailSafe reads the manifest first.

| Situation | Action |
| :-- | :-- |
| `npm/pnpm/yarn/bun install` reads `package.json` -- a dep does not exist | Deny |
| `pip install -r <file>` / `uv pip install -r <file>` -- a dep does not exist | Deny |
| `poetry install` / `uv sync` reads `pyproject.toml` -- a dep does not exist | Deny |
| Local/git/url/workspace specs | Ignored |

**Module 5 -- Curl-pipe-shell**

| Situation | Action |
| :-- | :-- |
| `curl http://... \| bash` -- plain HTTP remote script | Deny |
| `curl https://... \| bash/sh/python/node/ruby` | Ask |
| `wget ... \| sh` | Ask |
| `curl ... \| grep` or piped to non-shell | Allow |

**Module 6 -- Git disaster**

| Situation | Action |
| :-- | :-- |
| `git push --force` / `git push origin +main` to `main`, `master`, `production`, `release`, `prod`, `staging` | Deny |
| `git push --force` / `+refspec` to any other branch, or `--force-with-lease` | Ask |
| `git reset --hard` or `--merge` | Ask |
| `git clean -f` / `-fd` / `-fdx` (without dry-run) | Ask |
| `git branch -D <branch>` | Ask |
| Normal git operations | Allow |

**Module 7 -- Cloud / infra blast radius**

| Situation | Action |
| :-- | :-- |
| `terraform destroy` | Ask |
| `kubectl delete namespace` / `--all` / `-A` | Ask |
| `docker system prune -a` | Ask |
| `docker volume rm` | Ask |
| `aws s3 rm --recursive` / `sync --delete` | Ask |
| `gcloud projects delete` | Ask |
| `az group delete` | Ask |
| Normal read/plan operations | Allow |

**Module 8 -- Secrets exfiltration**

| Situation | Action |
| :-- | :-- |
| `cat .env \| curl` / `cat ~/.ssh/id_rsa \| nc` | Ask |
| `curl -d @.env https://...` / `curl -F file=@.env` | Ask |
| `scp .env user@host:.` / `rsync .env user@host:` | Ask |
| `tar czf - ~/.ssh \| curl --data-binary @- https://...` | Ask |
| `aws s3 cp .env s3://bucket` / `aws s3 mv id_rsa s3://...` | Ask |
| Reading `.env` locally without network | Allow |

Sensitive file patterns: `.env`, `.env.*`, `~/.ssh/*`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, `id_ed25519`, `.netrc`, `.npmrc`, `.aws/credentials`.

**Module 9 -- Cargo, Go, and RubyGems**

| Situation | Action |
| :-- | :-- |
| `cargo add` / `cargo install` -- crate not found on crates.io | Deny |
| Crate one edit away from a popular crate (`serde_jso` vs `serde_json`) | Ask |
| Crate < 90 days old with < 500 recent downloads | Ask |
| `go get` / `go install` -- module not found on the Go module proxy | Deny |
| `gem install` / `bundle add` -- gem not found on RubyGems | Deny |
| Gem one edit away from a popular gem (`railss` vs `rails`) | Ask |
| Gem < 90 days old with < 1 000 total downloads | Ask |
| `--git`, `--path`, or local `.gem` file sources | Ignored (not registry installs) |
| Private/unknown Go module domains | Ignored (avoids false positives) |

**Configuration (`failsafe.toml`)**

Place a `failsafe.toml` in your project root (or `~/.config/failsafe/config.toml`) to tune behavior:

```toml
[failsafe]
strict = false                          # true: upgrade all "ask" to "deny"
protected_branches = ["main", "prod"]   # replaces the default protected list
allowed_packages = ["my-internal-tool"] # always allow these names
```

All settings are optional. Zero-config remains the default.

---

## Blocked command examples

```
$ echo '{"tool_name":"Bash","tool_input":{"command":"npm install totally-not-real-pkg-xyz123"}}' \
    | python hooks/failsafe.py

permissionDecision: deny
reason: FailSafe blocked this install:
  - totally-not-real-pkg-xyz123: not found on the npm registry

AI assistants sometimes invent package names that don't exist; attackers
pre-register those names with malware ("slopsquatting"). Verify the correct
name on the official registry before installing.
```

```
$ echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
    | python hooks/failsafe.py

permissionDecision: deny
reason: FailSafe blocked a destructive command:
  rm -rf /
This would permanently delete the filesystem root (/).
```

```
$ echo '{"tool_name":"Bash","tool_input":{"command":"git push origin main --force"}}' \
    | python hooks/failsafe.py

permissionDecision: deny
reason: FailSafe blocked a force push to a protected branch:
  git push origin main --force
Force pushing to 'main' permanently overwrites remote history.
```

---

## Design principles

- **Fails open** -- any network error or unexpected failure allows the action. A guard that breaks your workflow gets uninstalled.
- **Fast path** -- non-network rules (rm, git, cloud, secrets) return instantly with zero I/O.
- **Conservative** -- only near-certain danger hard-blocks. Fuzzy signals escalate to a prompt.
- **Zero dependencies** -- pure Python 3 standard library.

---

## How it works

```
PreToolUse hook  ->  parse the Bash command
                 ->  run instant checks (rm, git, cloud, curl-pipe, secrets)
                 ->  for install commands, query npm / PyPI registries
                 ->  deny if dangerous  /  ask if suspicious  /  allow otherwise
```

`hooks/hooks.json` wires the hook on the `Bash` tool. `hooks/failsafe.py` does the work.

---

## What FailSafe will not do

- Score package reputation the way Socket.dev or Snyk do -- it checks existence and simple heuristics, not full supply chain analysis.
- Catch every possible dangerous command -- it targets the patterns agents actually produce, not a complete policy engine.
- Protect against a compromised package that already exists on the registry.
- Inspect `pnpm-lock.yaml` (no stdlib YAML parser).
- Parse `pyproject.toml` or `failsafe.toml` on Python < 3.11 (no `tomllib` -- fails open).
- Catch runner command strings that embed the package inside a shell snippet (`npm exec -c "eslint ."`).

---

## Requirements

- **Python 3.8+** on your PATH (`python3` or `python`).

---

## Scope: what it checks

**Install commands:** `npm install|i|add`, `pnpm add|install|i`, `yarn add`, `bun add|install|i`, `pip install`, `pip3 install`, `python -m pip install`, `poetry add`, `uv add`, `uv pip install`, `cargo add`, `cargo install`, `go get`, `go install`, `gem install`, `bundle add`

**One-off runners:** `npx`, `npm exec|x`, `pnpm dlx`, `bunx`, `bun x`, `yarn dlx`

**Manifest/lockfiles on bare install:** `package.json`, `package-lock.json` v2/v3 (npm ci), `yarn.lock` v1, `requirements.txt`, `pyproject.toml`, `poetry.lock`

Handles: quoted names, `;` and `&&` operators, `env FOO=bar` prefixes, wrapper flags (`sudo -n`, `env -i`, `time -p`), `bash -c "..."` inner commands.

Ignores: local paths, git URLs, `.tgz`/`.whl` files.

---

## Limitations

- npm, PyPI, crates.io, RubyGems, and Go proxy. Maven is next.
- Look-alike detection uses a curated list of popular packages, not a full corpus.
- `pnpm-lock.yaml` not inspected (no stdlib YAML parser).
- Deeply embedded runner command strings are not inspected (`npm exec -c "eslint ."`).
- `pyproject.toml`, `poetry.lock`, and `failsafe.toml` require Python 3.11+ (`tomllib`); fails open on older Python.

---

## Contributing

To add a new rule:

1. Add the detection logic to `hooks/failsafe.py` as a new `check_*` function.
2. Wire it into `main()` before the registry lookups (if it needs no network) or after (if it does).
3. Add a `hooks/test_<name>.py` with PASS/FAIL cases following the existing pattern.
4. Add an e2e case to `hooks/test_e2e.py`.
5. Run all tests: all existing 265+ cases must still pass.

To add a new package ecosystem:

1. Add a `check_<ecosystem>` registry function following `check_npm` / `check_pypi`.
2. Extend `parse_install_targets` to recognise the new package manager.
3. Add look-alike detection if a popular-package list exists for the ecosystem.
4. Add focused tests.

---

## License

MIT
