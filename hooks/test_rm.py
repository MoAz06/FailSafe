#!/usr/bin/env python3
"""Quick smoke test for the destructive rm rule."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from failsafe import check_destructive_rm

DENY = "deny"
ALLOW = None  # None means check_destructive_rm returned None

cases = [
    # (label, command, expected)
    # --- should DENY ---
    ("rm -rf /",             "rm -rf /",                   DENY),
    ("rm -rf ~",             "rm -rf ~",                   DENY),
    ("rm -rf $HOME",         "rm -rf $HOME",               DENY),
    ("rm -fr /etc",          "rm -fr /etc",                DENY),
    ("rm -Rf /usr",          "rm -Rf /usr",                DENY),
    ("rm -rf /home/user",    "rm -rf /home/mo24a",         DENY),
    ("rm -rf /*",            "rm -rf /*",                  DENY),
    ("rm -rf ~/",            "rm -rf ~/",                  DENY),
    ("sudo rm -rf /usr",     "sudo rm -rf /usr",           DENY),
    ("bash -c rm -rf ~",     'bash -c "rm -rf ~"',         DENY),
    ("rm -rf /boot",         "rm -rf /boot",               DENY),
    ("rm -rf /home",         "rm -rf /home",               DENY),
    ("semicolon no spaces",  "echo ok;rm -rf /",           DENY),
    ("and no spaces",        "echo ok&&rm -rf /",          DENY),
    ("pipe no spaces",       "printf ok|rm -rf /",         DENY),
    ("npm then dangerous",   "npm install express&&rm -rf /", DENY),
    ("sudo option",          "sudo -n rm -rf /",           DENY),
    ("sudo user option",     "sudo -u root rm -rf /",      DENY),
    ("env option",           "env -i rm -rf /",            DENY),
    ("env value option",     "env -u FOO rm -rf /",        DENY),
    ("time option",          "time -p rm -rf /",           DENY),
    ("nice option",          "nice -n 5 rm -rf /",         DENY),
    ("rm -rf /etc/*",        "rm -rf /etc/*",              DENY),
    ("rm -rf /usr/*",        "rm -rf /usr/*",              DENY),
    ("rm -rf /var/*",        "rm -rf /var/*",              DENY),
    ("rm home brace glob",   "rm -rf ~/{*,.*}",            DENY),
    ("rm user brace glob",   "rm -rf /home/mo24a/{*,.*}",  DENY),
    # --- should ALLOW ---
    ("rm -rf ./node_modules","rm -rf ./node_modules",      ALLOW),
    ("rm -rf dist",          "rm -rf dist",                ALLOW),
    ("rm -rf /tmp/stuff",    "rm -rf /tmp/myproject",      ALLOW),
    ("rm -rf ~/projects/app","rm -rf ~/projects/myapp",    ALLOW),
    ("rm -f file.txt",       "rm -f file.txt",             ALLOW),
    ("rm without -r",        "rm /etc/hosts",              ALLOW),
    ("rm -rf build/",        "rm -rf build/",              ALLOW),
    ("rm -rf /var/log/app",  "rm -rf /var/log/myapp",      ALLOW),
]

passed = failed = 0
for label, cmd, expected in cases:
    result = check_destructive_rm(cmd)
    got = result[0] if result else None
    ok = (got == expected)
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"{status}  {label!r:<35}  expected={expected}  got={got}")
    if ok:
        print(f"{status}  {label}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
