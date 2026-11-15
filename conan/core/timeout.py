#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run a function with a hard deadline.

If the function does not finish within `seconds`, the caller gets a
timeout marker and the scan continues — one slow or hung phase can
never freeze the whole investigation again. The hung work runs on a
daemon thread, so it cannot block the tool from finishing or exiting.
"""
import threading


def call_with_timeout(fn, seconds):
    """Call fn(); if it takes longer than `seconds`, return a timeout
    marker dict instead of waiting. Exceptions from fn are re-raised.
    """
    box = {}

    def run():
        try:
            box["value"] = fn()
        except Exception as exc:  # noqa: BLE001 - re-raised below
            box["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=seconds)
    if worker.is_alive():
        return {"timed_out": True,
                "error": "phase exceeded %ds and was skipped" % seconds}
    if "error" in box:
        raise box["error"]
    return box.get("value")
