#!/usr/bin/env python3
"""Tests for RubyGems parsing (module 9 -- ecosystem expansion)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from failsafe import parse_install_targets, GEM_NAME_RE

passed = failed = 0


def check(label, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label!r:<50}  expected={expected!r}  got={got!r}")


# --- gem install ---

check("gem install single",
    parse_install_targets("gem install rails"),
    [("rubygems", "rails")])

check("gem install multiple",
    parse_install_targets("gem install rails nokogiri devise"),
    [("rubygems", "rails"), ("rubygems", "nokogiri"), ("rubygems", "devise")])

check("gem install --version skips value",
    parse_install_targets("gem install rails --version 7.0"),
    [("rubygems", "rails")])

check("gem install -v skips value",
    parse_install_targets("gem install rails -v '~> 7.0'"),
    [("rubygems", "rails")])

check("gem install local file -> skip",
    parse_install_targets("gem install ./local.gem"),
    [])

check("gem install absolute path -> skip",
    parse_install_targets("gem install /tmp/mygem.gem"),
    [])

check("gem install with hyphen name",
    parse_install_targets("gem install dry-validation"),
    [("rubygems", "dry-validation")])

check("gem install with underscore name",
    parse_install_targets("gem install factory_bot"),
    [("rubygems", "factory_bot")])

check("gem build -> skip (not install)",
    parse_install_targets("gem build myapp.gemspec"),
    [])

check("gem update -> skip",
    parse_install_targets("gem update rails"),
    [])

# --- bundle add ---

check("bundle add single",
    parse_install_targets("bundle add devise"),
    [("rubygems", "devise")])

check("bundle add multiple",
    parse_install_targets("bundle add devise sidekiq"),
    [("rubygems", "devise"), ("rubygems", "sidekiq")])

check("bundle install bare -> skip (manifest, not direct)",
    parse_install_targets("bundle install"),
    [])

# --- chaining ---

check("npm then gem",
    parse_install_targets("npm install express && gem install rails"),
    [("npm", "express"), ("rubygems", "rails")])

check("pip then bundle add",
    parse_install_targets("pip install requests && bundle add httparty"),
    [("pypi", "requests"), ("rubygems", "httparty")])

# --- GEM_NAME_RE ---

check("name regex: simple",       bool(GEM_NAME_RE.match("rails")),          True)
check("name regex: hyphen",       bool(GEM_NAME_RE.match("dry-validation")), True)
check("name regex: underscore",   bool(GEM_NAME_RE.match("factory_bot")),    True)
check("name regex: starts digit", bool(GEM_NAME_RE.match("2fast")),          True)
check("name regex: empty",        bool(GEM_NAME_RE.match("")),               False)
check("name regex: starts dash",  bool(GEM_NAME_RE.match("-bad")),           False)

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
