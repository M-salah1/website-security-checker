#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authorization manager — the v4.0 name for the scope manager.

Wraps conan.core.scope.ScopeManager and adds the interactive wizard step:
ask the user whether the target is theirs or covered by written
authorization, and record the answer. Passive checks never need it; every
active or state-changing test does.
"""
from .scope import ScopeError, ScopeManager

__all__ = ["AuthorizationManager", "ScopeError"]


class AuthorizationManager(ScopeManager):
    def ask_and_authorize(self, url, kind="owned"):
        """Interactive wizard step. Returns True when authorized."""
        from .i18n import I18n
        i18n = I18n()
        try:
            from .configuration import load_settings
            i18n.set(load_settings().get("language", "ar"))
        except Exception:
            pass
        if self.is_authorized(url):
            return True
        print(i18n.t("authorize_prompt"))
        try:
            ans = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if ans in ("yes", "y", "oui", "o", "نعم", "ن", "si", "s"):
            self.authorize(url, kind)
            print(i18n.t("scope_saved"))
            return True
        return False

    def check_or_ask(self, url, what="active test"):
        """Authorize-or-ask; raises ScopeError when the user declines."""
        if self.is_authorized(url):
            return True
        if self.ask_and_authorize(url):
            return True
        raise ScopeError("Not authorized: %s (%s)" % (url, what))
