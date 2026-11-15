#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN FRAMEWORK v3.0 — ADVANCED WEBSITE SECURITY DETECTIVE (المحقق كونان).

Launcher. The real code lives in the `conan/` package (same directory).
This file only loads the package explicitly (the file and the package share
the name `conan`, so a plain `import conan` would be ambiguous) and runs
the interactive shell / direct scan.

Developer: Hafed Mehdi Salah Eddine — Algeria 🇩🇿
GitHub: M-salah1 — Copyright © 2026
Python standard library only. Works on Android Termux, Linux and Windows.

Usage:
    python3 conan.py                        # interactive shell: conan >
    python3 conan.py https://example.com    # direct full scan
    python3 conan.py https://example.com --json
    python3 conan.py --version
"""
import importlib.util
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.join(_ROOT, "conan")

_spec = importlib.util.spec_from_file_location(
    "conan", os.path.join(_PKG_DIR, "__init__.py"),
    submodule_search_locations=[_PKG_DIR])
_pkg = importlib.util.module_from_spec(_spec)
sys.modules["conan"] = _pkg
_spec.loader.exec_module(_pkg)

from conan.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
