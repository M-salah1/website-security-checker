#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Menu entry point for CONAN FRAMEWORK v6.0 — welcome screen, language
selection, 20-option main menu, wizard-driven investigations."""
import argparse

from .core.menu import MenuApp


def main(argv=None, start_menu=False):
    ap = argparse.ArgumentParser(prog="conan",
                                 description="CONAN FRAMEWORK v6.0 — menu mode")
    ap.add_argument("--lang", choices=["ar", "fr", "en"], default=None)
    ap.add_argument("--no-animation", action="store_true")
    ap.add_argument("--menu", action="store_true",
                    help="open the classic 20-option menu instead of the mega scan")
    args = ap.parse_args(argv)
    app = MenuApp(no_animation=args.no_animation)
    if args.lang:
        from .core.configuration import save_settings
        app.i18n.set(args.lang)
        app.settings["language"] = args.lang
        save_settings(app.settings)
    return app.run(start_menu=start_menu or args.menu)


if __name__ == "__main__":
    raise SystemExit(main())
