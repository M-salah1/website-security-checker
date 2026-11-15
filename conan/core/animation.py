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
    """

    def __init__(self, enabled=True, total=1, quiet=False):
        self.quiet = quiet
        self.enabled = bool(enabled) and terminal.is_tty() \
            and os.environ.get("TERM", "") != "dumb" \
            and not os.environ.get("NO_COLOR")
        self.total = max(1, total)
        self.done_count = 0
        self.current = ""
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
                done = self.done_count
                current = self.current
            spin = SPINNER[frame % len(SPINNER)]
            radar = RADAR[frame % len(RADAR)]
            det = DETECTIVE[frame % len(DETECTIVE)]
            bar = terminal.progress_bar(done, self.total, width=24)
            elapsed = time.time() - self.started_at if self.started_at else 0
            line = "\r%s %s %s %s  %s  %.1fs  %s" % (
                terminal.orange(spin), radar, det, terminal.orange("CONAN"),
                bar, elapsed, current[:40])
            try:
                sys.stdout.write(line)
                sys.stdout.flush()
            except Exception:
                break
            self._stop.wait(self.interval)
        try:
            sys.stdout.write("\r" + " " * (terminal.term_width() - 1) + "\r")
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
        """A real-time investigation log line (printed above the animation)."""
        if self.quiet:
            return
        if self.enabled:
            try:
                sys.stdout.write("\r" + " " * (terminal.term_width() - 1) + "\r")
                print(message)
                sys.stdout.flush()
            except Exception:
                print(message)
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
