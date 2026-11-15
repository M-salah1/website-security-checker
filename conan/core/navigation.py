#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Navigation stack + persistent investigation sessions.

Screens are pushed/popped; BACK returns to the previous screen and the
completed results of a case stay available (they live in the session store,
not on the screen). Sessions persist to conan-sessions.json so a case can
be reopened after the application restarts.

Navigation commands recognised in wizard inputs: BACK / HOME / MENU /
CANCEL / EXIT.
"""
import json
import os
import time

SESSIONS_FILE = "conan-sessions.json"
NAV_COMMANDS = ("BACK", "HOME", "MENU", "CANCEL", "EXIT")


class NavCommand(Exception):
    """Raised by input helpers when the user types a navigation command."""

    def __init__(self, command):
        super().__init__(command)
        self.command = command


def is_nav_command(text):
    return (text or "").strip().upper() in NAV_COMMANDS


class NavigationStack:
    def __init__(self):
        self.stack = []

    def push(self, screen, data=None):
        self.stack.append({"screen": screen, "data": data or {}})

    def pop(self):
        if len(self.stack) > 1:
            return self.stack.pop()
        return self.stack[0] if self.stack else None

    def current(self):
        return self.stack[-1] if self.stack else None

    def home(self):
        if self.stack:
            self.stack = [self.stack[0]]
        return self.current()

    def depth(self):
        return len(self.stack)


class SessionStore:
    """Persistent investigation sessions (summaries only — no secrets)."""

    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.getcwd()
        self.path = os.path.join(self.base_dir, SESSIONS_FILE)
        self.sessions = []
        self.load()

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.sessions = data
        except Exception:
            self.sessions = []

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.sessions, f, ensure_ascii=False, indent=2)

    def add(self, case_id, kind, target, summary):
        entry = {"case_id": case_id, "kind": kind, "target": target,
                 "summary": summary, "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.sessions = [s for s in self.sessions if s.get("case_id") != case_id]
        self.sessions.append(entry)
        self.save()
        return entry

    def get(self, case_id):
        for s in self.sessions:
            if s.get("case_id") == case_id:
                return s
        return None

    def list(self, limit=20):
        return list(reversed(self.sessions[-limit:]))
