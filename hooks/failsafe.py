#!/usr/bin/env python3
"""Shim -- real code lives in src/failsafe_hook/core.py.
Direct invocation (python hooks/failsafe.py) and test imports both work through this file."""
import os
import sys
import importlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from failsafe_hook import core as _core

_core = importlib.reload(_core)

for _name in dir(_core):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_core, _name)

main = _core.main

if __name__ == "__main__":
    main()
