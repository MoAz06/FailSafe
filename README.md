# FailSafe

**The zero-config agent seatbelt for Claude Code.**

When you run an AI agent in autonomous mode, one bad command can delete your home directory, drop a production database, or install malware from a hallucinated package name. Claude Code has a permissions system for this - but `--dangerously-skip-permissions` turns it all off.

FailSafe runs as a `PreToolUse` hook. A hook deny still fires in bypass mode. That is the whole point.

---

## What it blocks

**Slopsquatting (module 1)**

| Situation | Action |
| :-- | :-- |
| Package **does not exist** on npm / PyPI | Deny - almost always a hallucination |
| Exists, but **one edit away** from a popular package (e.g. `expres` vs `express`, `loadsh` vs `lodash`) | Ask - possible typosquat or look-alike |
| Package exists, but was **published < 90 days ago** with **< 100 downloads/month** | Ask - suspiciously fresh |
| Everything else | Allow (silent, no slowdown) |

**Destructive commands (module 2)**

| Situation | Action |
| :-- | :-- |
| `rm -rf` on `/`, `~`, `$HOME`, `/etc`, `/usr`, `/home/<user>`, root-level system directories, or their root globs | Deny |
| `rm -rf` on relative paths, `/tmp/...`, or deep subdirectories | Allow |

**One-off runners (module 3)**

| Situation | Action |
| :-- | :-- |
| `npx`, `npm exec`, `npm x`, `pnpm dlx`, `bunx`, `bun x`, or `yarn dlx` runs a package that does not exist on npm | Deny |
| Runner target is one edit away from a popular package, or is suspiciously fresh/low-download | Ask |
| Local paths such as `npx ./scripts/tool.js` | Allow |

**Manifest installs (module 4)**

A bare install pulls every dependency declared in a manifest file. FailSafe reads the manifest and runs the same registry checks on each declared package, so a hallucinated dep hidden in a file is caught just like a direct argument.

| Situation | Action |
| :-- | :-- |
| `npm/pnpm/yarn/bun install` (no package arg) reads `package.json` and a dep does not exist | Deny |
| `pip install -r <file>`, `uv pip install -r <file>` reads the requirements file and a dep does not exist | Deny |
| `poetry install` / `uv sync` reads `pyproject.toml` and a dep does not exist | Deny |
| A declared dep is a look-alike or suspiciously fresh | Ask |
| Local/git/url/workspace specs in the manifest | Ignored |

Only source manifests are parsed (`package.json`, `requirements.txt`, `pyproject.toml`). Generated lockfiles and YAML lockfiles are not. `pyproject.toml` parsing requires Python 3.11+ (`tomllib`); on older Python it fails open.

More rules are coming.

**Design principles**
- Fails open - any network error or unexpected failure allows the action. A guard that breaks your workflow gets uninstalled.
- Fast path - non-install commands return instantly with zero network calls.
- Conservative - only "does not exist" hard-blocks. Fuzzy signals only escalate to a prompt.
- Zero dependencies - pure Python 3 standard library.

## Why this matters

Research shows **43% of hallucinated package names recur on every run of the same prompt**. Attackers watch for these names, pre-register them on npm/PyPI with malware, and wait. In 2025 an estimated **28% of malicious packages were LLM-hallucinated versions** of real ones. This attack is called slopsquatting.

And that is just packages. Agents running in bypass mode have deleted production databases and wiped developer machines. FailSafe is the last layer that cannot be skipped.

## Requirements

- **Python 3.8+** on your PATH (`python3` or `python`).

## Try it

```bash
claude --plugin-dir /path/to/failsafe
```

Then ask Claude to install a made-up package:

> "install the npm package `totally-not-a-real-pkg-xyz123`"

You can also run the hook directly to see the decision:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"npm install totally-not-a-real-pkg-xyz123"}}' \
  | python hooks/failsafe.py
```

## Scope: what it checks

FailSafe inspects packages passed as **direct arguments** to install commands and one-off runners:

`npm install|i|add`, `pnpm add|install|i`, `yarn add`, `bun add|install|i`,
`pip install`, `pip3 install`, `python -m pip install`, `poetry add`,
`uv add`, `uv pip install`, `npx`, `npm exec|x`, `pnpm dlx`, `bunx`,
`bun x`, `yarn dlx`

It handles quoted names, shell operators such as `;` and `&&`, `env FOO=bar`
prefixes, common wrapper flags (`sudo -n`, `env -i`, `time -p`), and `bash -c "..."`
inner commands. Local paths, git URLs, and `.tgz`/`.whl` are ignored.

It also reads source manifests on bare installs (see module 4): `package.json`
for `npm/pnpm/yarn/bun install` and `npm ci`, the requirements file for
`pip install -r` / `uv pip install -r`, and `pyproject.toml` for `poetry install`
/ `uv sync`.

**Not yet inspected:**
- Lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`).
- `pyproject.toml` on Python < 3.11 (no `tomllib`).
- Runner command strings that hide the package inside a shell snippet, such as `npm exec -c "eslint --fix ."`.

## How it works

```
PreToolUse hook  ->  parse the Bash command for install / runner intents
                 ->  for each package, query the registry (npmjs.org / pypi.org)
                 ->  deny if missing  /  ask if suspicious  /  allow otherwise
```

`hooks/hooks.json` wires the hook on the `Bash` tool. `hooks/failsafe.py` does the work.

## Limitations

- Direct arguments and source manifests are inspected; generated lockfiles and deeply embedded runner command strings are not.
- npm and PyPI only today. Cargo, Go modules, RubyGems, Maven are next.
- npm and PyPI checks cover existence, look-alikes, package age, and monthly download counts. PyPI download data comes from pypistats.org.
- The look-alike list is a small curated set of popular packages.
- Existence check trusts the registry. It does not score package reputation the way Socket/Snyk do - it is a free, zero-config first line of defense, not a full SCA.

## License

MIT
