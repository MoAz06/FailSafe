#!/usr/bin/env python3
import sys

_MGMT_ARGS = {"--install", "--uninstall", "--check"}

if any(a in _MGMT_ARGS for a in sys.argv[1:]):
    from failsafe_hook._install import main as _main
else:
    from failsafe_hook.core import main as _main

_main()
