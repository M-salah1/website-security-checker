#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Settings for CONAN FRAMEWORK v5.2 — plain JSON, no secrets inside.

Secrets (test credentials) are NEVER stored here; they live only in the
encrypted scope file managed by conan.core.scope.
"""
import json
import os

DEFAULTS = {
    "language": "ar",
    "animation": True,
    "reverse_arabic": True,
    "timeout": 15,
    "max_depth": 2,
    "max_pages": 50,
    "rate_limit": 0.5,
    "max_retries": 2,
    "max_duration": 300,
    "db_path": "conan-scans.db",
}

SETTINGS_FILE = "conan-settings.json"


def _settings_path(base_dir=None):
    return os.path.join(base_dir or os.getcwd(), SETTINGS_FILE)


def load_settings(base_dir=None):
    cfg = dict(DEFAULTS)
    try:
        with open(_settings_path(base_dir), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in data.items():
                if k in DEFAULTS:
                    cfg[k] = v
    except Exception:
        pass
    return cfg


def save_settings(cfg, base_dir=None):
    data = {k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS}
    with open(_settings_path(base_dir), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return data
