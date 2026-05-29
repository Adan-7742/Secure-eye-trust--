"""
database/locker_db.py
======================
Separate SQLite database for App Locker & Folder Locker.
File: locker.db  (separate from main logs.db)

Tables:
  locked_apps     — apps protected by password
  locked_folders  — folders protected by password
  lock_attempts   — all unlock attempts (success + fail)
  lock_captures   — webcam/screenshot captures on failed unlock
"""

import sqlite3, os, hashlib, secrets
from pathlib import Path
from datetime import datetime

_DB_PATH = Path(__file__).parent / "locker.db"

def _get_conn():
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_locker_db():
    conn = _get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS locked_apps (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        exe_path    TEXT NOT NULL UNIQUE,
        pw_hash     TEXT NOT NULL,
        enabled     INTEGER DEFAULT 1,
        created_at  TEXT NOT NULL,
        fail_count  INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS locked_folders (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        folder_path   TEXT NOT NULL UNIQUE,
        pw_hash       TEXT NOT NULL,
        enabled       INTEGER DEFAULT 1,
        created_at    TEXT NOT NULL,
        fail_count    INTEGER DEFAULT 0,
        acl_backup    TEXT DEFAULT \'\',
        shortcut_path TEXT DEFAULT \'\',
        is_locked     INTEGER DEFAULT 0,
        hidden_path   TEXT DEFAULT \'\',
        lock_token    TEXT DEFAULT \'\' 
    );

    CREATE TABLE IF NOT EXISTS lock_attempts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target_type TEXT NOT NULL,
        target_id   INTEGER NOT NULL,
        target_name TEXT NOT NULL,
        success     INTEGER NOT NULL DEFAULT 0,
        timestamp   TEXT NOT NULL,
        fail_streak INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS lock_captures (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target_type TEXT NOT NULL,
        target_name TEXT NOT NULL,
        target_path TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        photo_b64   TEXT,
        attempt_no  INTEGER DEFAULT 1,
        dismissed   INTEGER DEFAULT 0
    );
    """)
    conn.commit()
    conn.close()

init_locker_db()


def _migrate_locker_db():
    """
    Auto-migrate locker.db to latest schema.
    Safe to run on any DB version — adds missing tables and columns.
    """
    conn = _get_conn()
    try:
        # ── Ensure all tables exist (safe even if DB is brand new) ────────────
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS locked_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            exe_path TEXT NOT NULL UNIQUE,
            pw_hash TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            fail_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS locked_folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            folder_path TEXT NOT NULL UNIQUE,
            pw_hash TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            fail_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS lock_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_id INTEGER NOT NULL,
            target_name TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            timestamp TEXT NOT NULL,
            fail_streak INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS lock_captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_name TEXT NOT NULL,
            target_path TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            photo_b64 TEXT,
            attempt_no INTEGER DEFAULT 1,
            dismissed INTEGER DEFAULT 0
        );
        """)

        # ── Add missing columns to locked_folders ────────────────────────────
        existing = [r[1] for r in conn.execute("PRAGMA table_info(locked_folders)").fetchall()]
        needed = [
            ("acl_backup",    "TEXT",    "''"),
            ("shortcut_path", "TEXT",    "''"),
            ("is_locked",     "INTEGER", "0"),
            ("hidden_path",   "TEXT",    "''"),
            ("lock_token",    "TEXT",    "''"),
        ]
        for col, typ, default in needed:
            if col not in existing:
                conn.execute(f"ALTER TABLE locked_folders ADD COLUMN {col} {typ} DEFAULT {default}")
                print(f"[locker_db] Added column locked_folders.{col}")

        conn.commit()
    except Exception as e:
        print(f"[locker_db] Migration error: {e}")
        import traceback; traceback.print_exc()
    finally:
        conn.close()
_migrate_locker_db()

# ── Password helpers ────────────────────────────────────────────────────────

def _hash_pw(password: str) -> str:
    salt = secrets.token_hex(8)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"

def _check_pw(password: str, stored_hash: str) -> bool:
    try:
        salt, h = stored_hash.split(":", 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except Exception:
        return False

# ── Locked Apps ─────────────────────────────────────────────────────────────

def add_locked_app(name: str, exe_path: str, password: str) -> dict:
    conn = _get_conn(); c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO locked_apps (name, exe_path, pw_hash, created_at) VALUES (?,?,?,?)",
            (name, exe_path, _hash_pw(password), datetime.now().isoformat())
        )
        conn.commit()
        return {"ok": True, "id": c.lastrowid}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": "App already locked"}
    finally:
        conn.close()

def remove_locked_app(app_id: int, password: str) -> dict:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT pw_hash FROM locked_apps WHERE id=?", (app_id,))
    row = c.fetchone()
    if not row:
        conn.close(); return {"ok": False, "error": "Not found"}
    if not _check_pw(password, row["pw_hash"]):
        conn.close(); return {"ok": False, "error": "Wrong password"}
    c.execute("DELETE FROM locked_apps WHERE id=?", (app_id,))
    conn.commit(); conn.close()
    return {"ok": True}

def get_locked_apps() -> list:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT id, name, exe_path, enabled, created_at, fail_count FROM locked_apps ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close(); return rows

def toggle_app_lock(app_id: int, enabled: bool):
    conn = _get_conn()
    conn.execute("UPDATE locked_apps SET enabled=? WHERE id=?", (int(enabled), app_id))
    conn.commit(); conn.close()

def verify_app_password(app_id: int, password: str) -> bool:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT pw_hash FROM locked_apps WHERE id=? AND enabled=1", (app_id,))
    row = c.fetchone()
    conn.close()
    return _check_pw(password, row["pw_hash"]) if row else False

# ── Locked Folders ──────────────────────────────────────────────────────────

def add_locked_folder(name: str, folder_path: str, password: str) -> dict:
    conn = _get_conn(); c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO locked_folders (name, folder_path, pw_hash, created_at, is_locked) VALUES (?,?,?,?,1)",
            (name, folder_path, _hash_pw(password), datetime.now().isoformat())
        )
        conn.commit()
        return {"ok": True, "id": c.lastrowid}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": "Folder already registered"}
    finally:
        conn.close()


def update_folder_lock_state(folder_id: int, is_locked: bool, acl_backup: str = '',
                              shortcut_path: str = '', hidden_path: str = '', lock_token: str = ''):
    conn = _get_conn()
    conn.execute(
        "UPDATE locked_folders SET is_locked=?, acl_backup=?, shortcut_path=?, hidden_path=?, lock_token=? WHERE id=?",
        (int(is_locked), acl_backup, shortcut_path, hidden_path, lock_token, folder_id)
    )
    conn.commit(); conn.close()


def get_folder_by_path(folder_path: str) -> dict:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM locked_folders WHERE folder_path=?", (folder_path,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else {}

def remove_locked_folder(folder_id: int, password: str) -> dict:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT pw_hash FROM locked_folders WHERE id=?", (folder_id,))
    row = c.fetchone()
    if not row:
        conn.close(); return {"ok": False, "error": "Not found"}
    if not _check_pw(password, row["pw_hash"]):
        conn.close(); return {"ok": False, "error": "Wrong password"}
    c.execute("DELETE FROM locked_folders WHERE id=?", (folder_id,))
    conn.commit(); conn.close()
    return {"ok": True}

def get_locked_folders() -> list:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT id, name, folder_path, enabled, created_at, fail_count, is_locked, shortcut_path, hidden_path, lock_token FROM locked_folders ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close(); return rows

def verify_folder_password(folder_id: int, password: str) -> bool:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT pw_hash FROM locked_folders WHERE id=? AND enabled=1", (folder_id,))
    row = c.fetchone()
    conn.close()
    return _check_pw(password, row["pw_hash"]) if row else False

# ── Lock Attempts & Captures ────────────────────────────────────────────────

def log_lock_attempt(target_type: str, target_id: int, target_name: str, success: bool) -> int:
    """Log attempt, return current fail streak."""
    conn = _get_conn(); c = conn.cursor()
    c.execute("""
        SELECT COUNT(*) FROM lock_attempts
        WHERE target_type=? AND target_id=? AND success=0
        AND timestamp >= datetime('now','-10 minutes')
    """, (target_type, target_id))
    streak = c.fetchone()[0] + (0 if success else 1)
    c.execute(
        "INSERT INTO lock_attempts (target_type, target_id, target_name, success, timestamp, fail_streak) VALUES (?,?,?,?,?,?)",
        (target_type, target_id, target_name, int(success), datetime.now().isoformat(), streak)
    )
    # Update fail_count on parent record
    table = "locked_apps" if target_type == "app" else "locked_folders"
    if not success:
        conn.execute(f"UPDATE {table} SET fail_count = fail_count + 1 WHERE id=?", (target_id,))
    conn.commit(); conn.close()
    return streak

def save_lock_capture(target_type: str, target_name: str, target_path: str, photo_b64: str, attempt_no: int):
    conn = _get_conn(); c = conn.cursor()
    c.execute(
        "INSERT INTO lock_captures (target_type, target_name, target_path, timestamp, photo_b64, attempt_no) VALUES (?,?,?,?,?,?)",
        (target_type, target_name, target_path, datetime.now().isoformat(), photo_b64, attempt_no)
    )
    conn.commit(); conn.close()

def get_lock_captures(limit=100) -> list:
    conn = _get_conn(); c = conn.cursor()
    c.execute("""
        SELECT id, target_type, target_name, target_path, timestamp, photo_b64, attempt_no, dismissed
        FROM lock_captures ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close(); return rows

def delete_lock_capture(capture_id: int, password: str) -> dict:
    """Delete a capture — requires dashboard master password."""
    from database.db import get_conn as main_conn
    import os
    # Verify against APP_PASSWORD
    stored = os.environ.get("APP_PASSWORD", "admin123")
    if password != stored:
        return {"ok": False, "error": "Wrong credentials"}
    conn = _get_conn()
    conn.execute("DELETE FROM lock_captures WHERE id=?", (capture_id,))
    conn.commit(); conn.close()
    return {"ok": True}

def dismiss_lock_capture(capture_id: int):
    conn = _get_conn()
    conn.execute("UPDATE lock_captures SET dismissed=1 WHERE id=?", (capture_id,))
    conn.commit(); conn.close()

def get_locker_stats() -> dict:
    conn = _get_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM locked_folders WHERE is_locked=1")
    folders = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM lock_attempts WHERE success=0")
    failed = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM lock_captures WHERE dismissed=0")
    unreviewed = c.fetchone()[0]
    conn.close()
    return {"locked_folders": folders, "failed_unlocks": failed,
            "unreviewed_captures": unreviewed}
