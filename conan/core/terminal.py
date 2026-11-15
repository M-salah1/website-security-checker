#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Terminal capabilities and brand colours for CONAN FRAMEWORK v5.0.

Brand: deep black background, charcoal surfaces, bright orange highlights,
white typography, green = passed, red = critical, yellow = warning,
blue = informational. Detects terminal size and colour support so the tool
also works on plain terminals (TERM=dumb, NO_COLOR, piped output).
"""
import os
import shutil
import sys

# ANSI colours (brand palette)
ORANGE = "38;5;208"
GREEN = "32"
RED = "31"
YELLOW = "33"
BLUE = "34"
WHITE = "37"
GREY = "90"
BOLD = "1"


def supports_color():
    """True only when the output is a TTY with colour support."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return sys.stdout.isatty()


def is_tty():
    return sys.stdout.isatty()


def term_width(default=80):
    try:
        return shutil.get_terminal_size().columns or default
    except Exception:
        return default


def paint(text, code):
    if not supports_color():
        return text
    return "\x1b[%sm%s\x1b[0m" % (code, text)


def orange(text):
    return paint(text, ORANGE)


def green(text):
    return paint(text, GREEN)


def red(text):
    return paint(text, RED)


def yellow(text):
    return paint(text, YELLOW)


def blue(text):
    return paint(text, BLUE)


def grey(text):
    return paint(text, GREY)


def bold(text):
    return paint(text, BOLD)


def rule(char="=", width=None):
    return char * (width or term_width())


def progress_bar(done, total, width=30):
    """Text progress bar: [██████----------] 42% — no dependencies."""
    if total <= 0:
        total = 1
    frac = max(0.0, min(1.0, done / float(total)))
    filled = int(frac * width)
    bar = "█" * filled + "─" * (width - filled)
    return "[%s] %d%%" % (bar, int(frac * 100))


def banner():
    """CONAN FRAMEWORK v5.0 ASCII identity — magnifying glass + shield."""
    lines = [
        orange("   🔍  CONAN FRAMEWORK v5.0"),
        orange("   ULTIMATE CYBER INVESTIGATION SYSTEM  •  المحقق كونان"),
        grey("   ────────────────────────────────────────────────"),
        "   Developer: " + bold("Hafed Mehdi Salah Eddine") + "  •  Algeria 🇩🇿",
        "   GitHub: M-salah1  •  Copyright © 2026",
        grey("   20 menu options  •  safe lab  •  defense center  •  0 exploits  •  3 languages (en/fr/ar)"),
        grey("   Use only on your own sites or with written authorization."),
    ]
    return "\n".join(lines)


def status_line(ok, text):
    mark = green("✓") if ok else red("✘")
    return " %s %s" % (mark, text)
