# SlopGuard 🛡️

**A Claude Code plugin that blocks AI-hallucinated package installs before they hit your machine.**

When you let an AI agent install dependencies, it sometimes invents a package name that
doesn't exist. Attackers watch for these — research shows **43% of hallucinated package
names recur on every run of the same prompt**, so they pre-register the names with malware
and wait. This attack is called **slopsquatting**, and in 2025 an estimated **28% of
malicious packages were LLM-hallucinated versions**.

SlopGuard runs automatically as a `PreToolUse` hook. Before the agent runs any
`npm`/`pnpm`/`yarn`/`bun`/`pip`/`poetry`/`uv` install, it checks each package against the
official registry and **blocks the install if the package doesn't exist** — even in
`--dangerously-skip-permissions` / bypass mode, where a hook `deny` still wins.

---

## What it does

| Situation | Action |
| :-- | :-- |
| Package **does not exist** on npm / PyPI | 🛑 **Deny** — almost always a hallucination |
| Exists, but **one edit** from a popular package — typo or letter swap (e.g. `expres`→`express`, `loadsh`→`lodash`) | ⚠️ **Ask** — possible typosquat/look-alike |
| Exists, but **published < 90 days ago** with **< 100 downloads/month** | ⚠️ **Ask** — suspiciously fresh |
| Everything else | ✅ Allow (silent, no slowdown) |

**Design principles**
- **Fails open** — any network error or unexpected failure allows the install. A guard that
  breaks your workflow gets uninstalled.
- **Fast path** — non-install commands return instantly with zero network calls.
- **Conservative** — only "does not exist" hard-blocks. Fuzzy signals only escalate to a prompt.
- **Zero dependencies** — pure Python 3 standard library.

## Requirements

- **Python 3.8+** on your PATH (`python3` or `python`).

## Try it locally

```bash
# from anywhere
claude --plugin-dir /path/to/slopguard
```

Then ask Claude to install a made-up package and watch it get blocked:

> "install the npm package `totally-not-a-real-pkg-xyz123`"

You can also run the hook directly to see the decision JSON:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"npm install totally-not-a-real-pkg-xyz123"}}' \
  | python hooks/slopguard.py
```

## Scope: what it checks

SlopGuard inspects packages passed as **direct arguments** to an install command:

`npm install|i|add` · `pnpm add|install|i` · `yarn add` · `bun add|install|i` ·
`pip install` · `pip3 install` · `python -m pip install` · `poetry add` ·
`uv add` · `uv pip install`

It is robust to quoted names, `env FOO=bar` prefixes, wrappers (`sudo`, `env`), and
`bash -c "..."` wrappers. Local paths, git URLs, `.tgz`/`.whl`, `-r requirements.txt`
arguments, and lockfile installs (`npm ci`) are ignored — those are pinned or local.

**Not yet inspected** (so a hallucinated name here still slips through):
- Manifest installs that read names from a file: bare `npm install`, `pip install -r`,
  `poetry install`, `uv sync`.
- One-off runners: `npx`, `pnpm dlx`, `bunx`, `npm exec`.

## How it works

```
PreToolUse hook  ──▶  parse the Bash command for install intents
                 ──▶  for each package, query the registry (npmjs.org / pypi.org)
                 ──▶  deny if missing · ask if suspicious · allow otherwise
```

`hooks/hooks.json` wires the hook on the `Bash` tool. `hooks/slopguard.py` does the work.

## Limitations (and roadmap)

- **Direct arguments only.** Manifest installs (`npm install` from `package.json`,
  `pip install -r`, `poetry install`, `uv sync`) and one-off runners (`npx`, `dlx`, `bunx`)
  are not inspected yet. Scanning manifests before install is the top roadmap item.
- **npm + PyPI only** today. Cargo, Go modules, RubyGems, Maven are next.
- The look-alike list is a small curated set of popular packages — expanding it would catch
  more typosquats. The new+low-download signal uses live download counts for npm (incl.
  scoped); PyPI download counts are not exposed by the registry API, so that signal is
  npm-only for now.
- Existence check trusts the registry; it doesn't (yet) score package *reputation* the way
  Socket/Snyk do — it's a free, zero-config first line of defense, not a full SCA.

## License

MIT
