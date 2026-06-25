#!/usr/bin/env python3
"""
FailSafe installer logic.

Invoked via:
  python -m failsafe_hook --install
  python -m failsafe_hook --uninstall
  python -m failsafe_hook --check
"""
import importlib.util
import json
import os
import sys

HOOK_MATCHER = "Bash"
HOOK_MARKER = "failsafe"  # matches both old path-based and new module-based commands


def _settings_path():
    return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")


def _build_command():
    return "python3 -m failsafe_hook 2>/dev/null || python -m failsafe_hook 2>/dev/null || true"


def _read_settings(path):
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_settings(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _find_hook(pre_tool_use):
    """Return (bash_entry, hook_entry) if FailSafe is already installed, else (None, None)."""
    for entry in pre_tool_use:
        if entry.get("matcher") != HOOK_MATCHER:
            continue
        for h in entry.get("hooks") or []:
            if HOOK_MARKER in h.get("command", ""):
                return entry, h
    return None, None


def install():
    try:
        if importlib.util.find_spec("failsafe_hook") is None:
            raise ImportError
    except Exception:
        print("ERROR: failsafe_hook package is not installed.")
        print("Install it first:")
        print("  pip install -e .       (from repo root, for development)")
        print("  pip install failsafe-hook  (from PyPI)")
        sys.exit(1)

    sp = _settings_path()
    try:
        settings = _read_settings(sp)
    except Exception as e:
        print(f"ERROR: Could not read {sp}: {e}")
        sys.exit(1)

    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    bash_entry, existing = _find_hook(pre)

    if existing:
        print("FailSafe is already installed.")
        print(f"  settings : {sp}")
        print(f"  command  : {existing['command']}")
        sys.exit(0)

    if bash_entry is None:
        bash_entry = {"matcher": HOOK_MATCHER, "hooks": []}
        pre.append(bash_entry)

    bash_entry.setdefault("hooks", []).append({
        "type":    "command",
        "timeout": 12,
        "command": _build_command(),
    })

    _write_settings(sp, settings)

    print("FailSafe installed.")
    print(f"  settings : {sp}")
    print(f"  command  : {_build_command()}")
    print()
    print("Runs automatically on every Claude Code session.")
    print("To remove: python -m failsafe_hook --uninstall")


def uninstall():
    sp = _settings_path()
    try:
        settings = _read_settings(sp)
    except Exception as e:
        print(f"ERROR: Could not read {sp}: {e}")
        sys.exit(1)

    pre = (settings.get("hooks") or {}).get("PreToolUse", [])
    bash_entry, existing = _find_hook(pre)

    if not existing:
        print("FailSafe is not installed in ~/.claude/settings.json")
        sys.exit(0)

    bash_entry["hooks"] = [
        h for h in bash_entry.get("hooks", [])
        if HOOK_MARKER not in h.get("command", "")
    ]
    if not bash_entry["hooks"]:
        settings["hooks"]["PreToolUse"] = [
            e for e in pre if e is not bash_entry
        ]

    _write_settings(sp, settings)
    print("FailSafe uninstalled.")


def check():
    sp = _settings_path()
    try:
        settings = _read_settings(sp)
    except Exception as e:
        print(f"ERROR: Could not read {sp}: {e}")
        sys.exit(1)

    pre = (settings.get("hooks") or {}).get("PreToolUse", [])
    _, existing = _find_hook(pre)

    if existing:
        print("Status: INSTALLED")
        print(f"  settings : {sp}")
        print(f"  command  : {existing['command']}")
    else:
        print("Status: NOT INSTALLED")
        print(f"  settings : {sp}")
        print("Run:  python -m failsafe_hook --install")


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--uninstall":
        uninstall()
    elif arg == "--check":
        check()
    elif arg in ("", "--install"):
        install()
    else:
        print(f"Unknown argument: {arg}")
        sys.exit(1)


if __name__ == "__main__":
    main()
