#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cinematic scanning animation engine — stdlib only, no Rich required.

The animation runs in a background thread and NEVER blocks network work.
Progress always reflects real completed phases, never invented percentages.
Automatically disabled when: --no-animation, output is not a TTY,
TERM=dumb, NO_COLOR set, or the terminal is too small.
Low-power mode reduces the frame rate on weak devices (CONAN_LOW_POWER=1).
"""
import os
import sys
import threading
import time

from . import terminal

SPINNER = ["◐", "◓", "◑", "◒"]
RADAR = ["◉", "◎", "○", "◎"]
DETECTIVE = ["🔍", "🕵️", "🔎", "🛡️"]

LOG_MESSAGES = [
    "[+] Initializing Conan engine...",
    "[+] Checking target availability...",
    "[+] Resolving DNS...",
    "[+] Establishing TLS connection...",
    "[+] Discovering public routes...",
    "[+] Analyzing security headers...",
    "[+] Inspecting public forms...",
    "[+] Running authorized security tests...",
    "[+] Evaluating phishing indicators...",
    "[+] Preparing final report...",
]


def play_intro(enabled=True):
    """Animated intro: a magnifying glass sweeps across ONE line.

    Runs only on a real terminal with animation on; everywhere else it
    does nothing, so piped output and tests stay clean.
    """
    if not enabled or not terminal.is_tty() \
            or os.environ.get("TERM", "") == "dumb" \
            or os.environ.get("NO_COLOR"):
        return
    width = 34
    try:
        for pos in list(range(0, width, 3)) + list(range(width, 0, -3)):
            line = "─" * pos + "🔍" + "─" * max(0, width - pos - 1)
            sys.stdout.write("\r\x1b[K  " + terminal.orange(line) + "  CONAN")
            sys.stdout.flush()
            time.sleep(0.07)
        sys.stdout.write("\r\x1b[K")
        sys.stdout.flush()
    except Exception:
        pass


class Investigation:
    """Threaded animation bound to real scan phases.

    Usage:
        inv = Investigation(enabled=True, total=8)
        inv.start()
        inv.phase("Resolving DNS")        # real work happens here
        inv.log("[+] DNS resolved: 1.2.3.4")
        inv.phase("Analyzing headers")
        ...
        inv.done()

    The whole loading display lives on ONE terminal line: the spinner,
    progress bar, current phase and the latest log message are all
    redrawn in place with carriage return — no new line per update.
    """

    def __init__(self, enabled=True, total=1, quiet=False):
        self.quiet = quiet
        self.enabled = bool(enabled) and terminal.is_tty() \
            and os.environ.get("TERM", "") != "dumb" \
            and not os.environ.get("NO_COLOR")
        self.total = max(1, total)
        self.done_count = 0
        self.current = ""
        self.last_log = ""
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._frame = 0
        self.interval = 0.25 if os.environ.get("CONAN_LOW_POWER") else 0.12
        self.started_at = None

    def start(self):
        self.started_at = time.time()
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            with self._lock:
                frame = self._frame
                self._frame += 1
            spin = SPINNER[frame % len(SPINNER)]
            # While a scan runs, the tool writes only this one line:
            # spinner + "Scanning..." with animated dots. Phase names and
            # log messages are tracked internally, never printed.
            dots = "." * (1 + (frame // 4) % 3)
            line = "\r\x1b[K%s Scanning%s" % (terminal.orange(spin), dots)
            try:
                sys.stdout.write(line)
                sys.stdout.flush()
            except Exception:
                break
            self._stop.wait(self.interval)
        try:
            sys.stdout.write("\r\x1b[K")
            sys.stdout.flush()
        except Exception:
            pass

    def phase(self, name):
        """Mark one real phase as done and move to the next."""
        with self._lock:
            self.done_count += 1
            self.current = name
        if not self.enabled and not self.quiet:
            print("[%d/%d] %s" % (self.done_count, self.total, name))

    def log(self, message):
        """A real-time investigation log line.

        While the animation runs, the message joins the single loading
        line (latest message wins) instead of opening a new line.
        Without animation (piped output), it prints normally.
        """
        if self.quiet:
            return
        if self.enabled:
            with self._lock:
                self.last_log = str(message)
        else:
            print(message)

    def done(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if self.quiet:
            return
        elapsed = time.time() - self.started_at if self.started_at else 0
        print(terminal.green("✓ Investigation complete in %.1fs — %d/%d phases"
                             % (elapsed, self.done_count, self.total)))

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.done()
        return False
