#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN FRAMEWORK v5.9 — ULTIMATE CYBER INVESTIGATION SYSTEM (المحقق كونان).

Launcher. The real code lives in the `conan/` package (same directory).
This file only loads the package explicitly (the file and the package share
the name `conan`, so a plain `import conan` would be ambiguous) and runs
the requested mode.

Developer: Hafed Mehdi Salah Eddine — Algeria 🇩🇿
GitHub: M-salah1 — Copyright © 2026
Python standard library only. Works on Android Termux, Linux and Windows.

Modes:
    python3 conan.py                        # menu (welcome + language + 20 options)
    python3 conan.py menu                   # menu mode
    python3 conan.py shell                  # interactive shell: conan >
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


def _main():
    argv = sys.argv[1:]
    if not argv:
        from conan.menu_app import main as menu_main
        return menu_main()
    if argv[0] in ("menu", "--menu"):
        from conan.menu_app import main as menu_main
        return menu_main(argv[1:], start_menu=True)
    if argv[0] == "shell":
        from conan.cli import main as cli_main
        return cli_main(argv[1:])
    # Flags that belong to the menu belong to the menu; the CLI also accepts
    # --no-animation/--lang, so only route to the menu when the user asked
    # for it explicitly or gave no URL at all.
    if argv[0] in ("--no-animation", "--lang") and len(argv) == 1:
        from conan.menu_app import main as menu_main
        return menu_main(argv)
    from conan.cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(_main())
