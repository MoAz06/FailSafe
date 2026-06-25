#!/usr/bin/env python3
"""Tests for Cargo crate parsing (module 9 — ecosystem expansion)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from failsafe import parse_install_targets, collect_cargo, CARGO_NAME_RE

passed = failed = 0


def check(label, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label!r:<45}  expected={expected!r}  got={got!r}")


# --- parse_install_targets: cargo ---

check("cargo add single",
    parse_install_targets("cargo add serde"),
    [("cargo", "serde")])

check("cargo add multiple",
    parse_install_targets("cargo add serde tokio clap"),
    [("cargo", "serde"), ("cargo", "tokio"), ("cargo", "clap")])

check("cargo add with version",
    parse_install_targets("cargo add serde@1.0"),
    [("cargo", "serde")])

check("cargo install",
    parse_install_targets("cargo install ripgrep"),
    [("cargo", "ripgrep")])

check("cargo install with hyphen",
    parse_install_targets("cargo install cargo-edit"),
    [("cargo", "cargo-edit")])

check("cargo add with underscore",
    parse_install_targets("cargo add serde_json"),
    [("cargo", "serde_json")])

check("cargo add --git -> skip (non-registry)",
    parse_install_targets("cargo add --git https://github.com/x/y serde"),
    [])

check("cargo add --path -> skip (non-registry)",
    parse_install_targets("cargo add --path ./local-crate"),
    [])

check("cargo build -> skip",
    parse_install_targets("cargo build"),
    [])

check("cargo test -> skip",
    parse_install_targets("cargo test"),
    [])

check("cargo add --features -> value flag skipped",
    parse_install_targets("cargo add serde --features derive"),
    [("cargo", "serde")])

check("cargo add scoped with flags",
    parse_install_targets("cargo add tokio --features full"),
    [("cargo", "tokio")])

# --- chaining ---

check("npm then cargo",
    parse_install_targets("npm install express && cargo add serde"),
    [("npm", "express"), ("cargo", "serde")])

# --- CARGO_NAME_RE ---

check("name regex: valid",     bool(CARGO_NAME_RE.match("serde")),      True)
check("name regex: hyphen",    bool(CARGO_NAME_RE.match("cargo-edit")), True)
check("name regex: underscore",bool(CARGO_NAME_RE.match("serde_json")), True)
check("name regex: numeric",   bool(CARGO_NAME_RE.match("h2")),         True)
check("name regex: starts num",bool(CARGO_NAME_RE.match("2fast")),      False)
check("name regex: empty",     bool(CARGO_NAME_RE.match("")),            False)

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
