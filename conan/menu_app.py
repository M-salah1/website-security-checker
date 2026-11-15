#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Menu entry point for CONAN FRAMEWORK v4.1 — welcome screen, language
selection, 17-option main menu, wizard-driven investigations."""
import argparse

from .core.menu import MenuApp


def main(argv=None):
    ap = argparse.ArgumentParser(prog="conan",
                                 description="CONAN FRAMEWORK v4.0 — menu mode")
    ap.add_argument("--lang", choices=["ar", "fr", "en"], default=None)
    ap.add_argument("--no-animation", action="store_true")
    args = ap.parse_args(argv)
    app = MenuApp(no_animation=args.no_animation)
    if args.lang:
        from .core.configuration import save_settings
        app.i18n.set(args.lang)
        app.settings["language"] = args.lang
        save_settings(app.settings)
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
