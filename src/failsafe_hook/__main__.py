#!/usr/bin/env python3
import sys


def main():
    args = sys.argv[1:]
    if args or sys.stdin.isatty():
        from failsafe_hook._install import main as _main
    else:
        from failsafe_hook.core import main as _main
    _main()


if __name__ == "__main__":
    main()
