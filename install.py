#!/usr/bin/env python3
"""
FailSafe installer

Patches ~/.claude/settings.json to add FailSafe as a permanent PreToolUse hook.
Safe to run multiple times (idempotent). Merges with existing hooks, never overwrites.

Usage:
  python install.py            # install
  python install.py --check    # show status without changing anything
  python install.py --uninstall
"""
import os
import subprocess
import sys


def _ensure_package():
    """Install the failsafe_hook package if not already importable."""
    import importlib.util
    try:
        if importlib.util.find_spec("failsafe_hook") is not None:
            return
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    print("Installing failsafe_hook package (editable) ...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", here, "--quiet"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("ERROR: pip install failed:")
        print(result.stderr or result.stdout)
        sys.exit(1)


def main():
    _ensure_package()
    from failsafe_hook._install import main as _install_main
    _install_main()


if __name__ == "__main__":
    main()
