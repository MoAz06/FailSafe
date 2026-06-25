#!/usr/bin/env python3
"""Smoke test for git disaster guard (module 6)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from failsafe import check_git_disaster, check_destructive_rm

DENY = "deny"
ASK  = "ask"
ALLOW = None

git_cases = [
    # --- force push to protected branch -> DENY ---
    ("push --force main",           "git push origin main --force",              DENY),
    ("push -f master",              "git push -f origin master",                 DENY),
    ("push --force production",     "git push origin production --force",        DENY),
    ("push --force release",        "git push origin release --force",           DENY),
    ("push --force refspec :main",  "git push origin feature:main --force",      DENY),
    # --- force push unknown branch -> ASK ---
    ("push --force feature",        "git push origin feature --force",           ASK),
    ("push --force no branch",      "git push --force",                          ASK),
    ("push --force-with-lease",     "git push --force-with-lease",               ASK),
    ("push -f no remote",           "git push -f",                               ASK),
    # --- reset --hard -> ASK ---
    ("reset --hard",                "git reset --hard",                          ASK),
    ("reset --hard HEAD~1",         "git reset --hard HEAD~1",                   ASK),
    ("reset --merge",               "git reset --merge",                         ASK),
    # --- clean with -f -> ASK ---
    ("git clean -f",                "git clean -f",                              ASK),
    ("git clean -fd",               "git clean -fd",                             ASK),
    ("git clean -fdx",              "git clean -fdx",                            ASK),
    ("git clean -fX",               "git clean -fX",                             ASK),
    # --- branch -D -> ASK ---
    ("branch -D",                   "git branch -D feature",                     ASK),
    ("branch -D multiple",          "git branch -D feat1 feat2",                 ASK),
    # --- bash nested ---
    ("bash nested force push",      'bash -c "git push origin main --force"',    DENY),
    ("bash nested reset",           'bash -c "git reset --hard"',                ASK),
    # --- ALLOW ---
    ("normal push",                 "git push origin main",                      ALLOW),
    ("push to feature",             "git push origin feature",                   ALLOW),
    ("reset --soft",                "git reset --soft HEAD~1",                   ALLOW),
    ("reset --mixed",               "git reset --mixed HEAD~1",                  ALLOW),
    ("git clean -n",                "git clean -n",                              ALLOW),
    ("git clean -fn (dry run)",     "git clean -fn",                             ALLOW),
    ("branch -d safe",              "git branch -d merged-feat",                 ALLOW),
    ("git status",                  "git status",                                ALLOW),
    ("git commit",                  "git commit -m 'fix'",                       ALLOW),
]

# .git deletion is caught by the rm guard
rm_cases = [
    ("rm -rf .git",                 "rm -rf .git",                               DENY),
    ("rm -rf .git/",                "rm -rf .git/",                              DENY),
]

passed = failed = 0

for label, cmd, expected in git_cases:
    result = check_git_disaster(cmd)
    got = result[0] if result else None
    ok = (got == expected)
    if ok:
        passed += 1; print(f"PASS  {label}")
    else:
        failed += 1; print(f"FAIL  {label!r:<40}  expected={expected}  got={got}")

for label, cmd, expected in rm_cases:
    result = check_destructive_rm(cmd)
    got = result[0] if result else None
    ok = (got == expected)
    if ok:
        passed += 1; print(f"PASS  {label}")
    else:
        failed += 1; print(f"FAIL  {label!r:<40}  expected={expected}  got={got}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
