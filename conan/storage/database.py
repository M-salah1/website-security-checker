#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite scan storage with encrypted report payloads.

The report JSON is encrypted with AES-256-GCM using a device key stored in
`conan-key.txt` (mode 0600, generated once, never committed). The key file
lives next to the database; the database itself never contains plaintext
reports or secrets. If the key file is lost, stored reports cannot be read —
that is the intended trade-off.
"""
import base64
import json
import os
import sqlite3

from ..core.encryption import decrypt_text, encrypt_text, generate_key_file

KEY_FILE = "conan-key.txt"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    duration_s REAL,
    score INTEGER,
    grade TEXT,
    health TEXT,
    report_enc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS availability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    checked_at TEXT,
    classification TEXT,
    status INTEGER,
    total_ms INTEGER
);
CREATE TABLE IF NOT EXISTS module_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    module TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_s REAL,
    retries INTEGER,
    error TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
"""


def _key_path(base_dir):
    return os.path.join(base_dir or os.getcwd(), KEY_FILE)


def get_or_create_key(base_dir=None):
    path = _key_path(base_dir)
    try:
        with open(path, encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    except Exception:
        pass
    return generate_key_file(path)


def init_db(path):
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    return path


def save_scan(db_path, scan, base_dir=None):
    """Encrypt the full report and store one row. Returns the scan id."""
    key = get_or_create_key(base_dir)
    payload = json.dumps(scan, ensure_ascii=False)
    enc = encrypt_text(key, payload)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS module_runs ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " scan_id INTEGER NOT NULL, module TEXT NOT NULL,"
            " status TEXT NOT NULL, duration_s REAL, retries INTEGER,"
            " error TEXT);")
        cur = conn.execute(
            "INSERT INTO scans (target, started_at, finished_at, duration_s,"
            " score, grade, health, report_enc) VALUES (?,?,?,?,?,?,?,?)",
            (scan.get("target"), scan.get("started_at"), scan.get("finished_at"),
             scan.get("duration_s"), scan.get("score"), scan.get("grade"),
             (scan.get("health") or {}).get("classification"), enc))
        scan_id = cur.lastrowid
        for name, run in (scan.get("module_status") or {}).items():
            conn.execute(
                "INSERT INTO module_runs (scan_id, module, status,"
                " duration_s, retries, error) VALUES (?,?,?,?,?,?)",
                (scan_id, name, run.get("status"),
                 run.get("duration_s"), run.get("retries", 0),
                 (run.get("error") or "")[:500]))
        conn.commit()
        return scan_id
    finally:
        conn.close()


def save_availability(db_path, target, health, checked_at):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO availability (target, checked_at, classification,"
            " status, total_ms) VALUES (?,?,?,?,?)",
            (target, checked_at, health.get("classification"),
             health.get("status"), health.get("total_ms")))
        conn.commit()
    finally:
        conn.close()


def list_scans(db_path, limit=20):
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, target, started_at, score, grade, health FROM scans"
            " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0], "target": r[1], "started_at": r[2],
                 "score": r[3], "grade": r[4], "health": r[5]} for r in rows]
    finally:
        conn.close()


def get_scan(db_path, scan_id, base_dir=None):
    key = get_or_create_key(base_dir)
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT report_enc FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return json.loads(decrypt_text(key, row[0]))
    finally:
        conn.close()


def availability_history(db_path, target, limit=20):
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT checked_at, classification, status, total_ms FROM availability"
            " WHERE target = ? ORDER BY id DESC LIMIT ?", (target, limit)).fetchall()
        return [{"checked_at": r[0], "classification": r[1], "status": r[2],
                 "total_ms": r[3]} for r in rows]
    finally:
        conn.close()
