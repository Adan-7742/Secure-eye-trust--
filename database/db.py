"""
database/db.py
==============
Single source of truth for SQLite schema.
- Creates all tables on first run
- Auto-migrates (adds missing columns) on upgrades
- All other modules import DB_PATH and get_conn() from here

DATA FLOW:
  Windows Event Log  →  core/event_collector/windows_reader.py
      ↓ parsed dicts
  database/db.py  (INSERT into logs_*)
      ↓ SQL
  api/*.py  (SELECT → JSON)
      ↓ HTTP/JSON
  static/js/*.js  (renders in browser)
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "logs.db")

CATEGORIES = ["application", "system", "security", "windows_update"]
LOG_CATEGORIES = CATEGORIES   # alias used by some api modules

CREATE_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS logs_{cat} (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT,
    date            TEXT,          -- YYYY-MM-DD  (indexed for day-filter)
    level           TEXT,          -- ERROR / WARNING / INFO / SUCCESS / FAILURE
    source          TEXT,
    message         TEXT,
    event_id        INTEGER,
    raw             TEXT,          -- original message before parsing
    norm_user       TEXT,
    norm_ip         TEXT,
    norm_logon_type INTEGER,
    norm_process    TEXT,
    risk_score      INTEGER DEFAULT 0,
    risk_category   TEXT,
    content_hash    TEXT,
    uploaded_at     TEXT DEFAULT (datetime('now'))
)
"""

CREATE_HE_CACHE = """
CREATE TABLE IF NOT EXISTS he_analysis_cache (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    category     TEXT,
    metric       TEXT,
    encrypted_data TEXT,
    computed_at  TEXT DEFAULT (datetime('now'))
)
"""

CREATE_EVENTS_LOG = """
CREATE TABLE IF NOT EXISTS app_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT,   -- fetch_start / fetch_done / chat_query / analysis_run / error
    payload    TEXT,   -- JSON string with details
    ts         TEXT DEFAULT (datetime('now'))
)
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_{cat}_date      ON logs_{cat}(date)",
    "CREATE INDEX IF NOT EXISTS idx_{cat}_level     ON logs_{cat}(level)",
    "CREATE INDEX IF NOT EXISTS idx_{cat}_norm_user ON logs_{cat}(norm_user)",
    "CREATE INDEX IF NOT EXISTS idx_{cat}_risk      ON logs_{cat}(risk_score)",
]

REQUIRED_COLUMNS = {
    "date":          "TEXT",
    "event_id":      "INTEGER",
    "raw":           "TEXT",
    "norm_user":     "TEXT",
    "norm_ip":       "TEXT",
    "norm_logon_type":"INTEGER",
    "norm_process":  "TEXT",
    "risk_score":    "INTEGER DEFAULT 0",
    "risk_category": "TEXT",
    "content_hash":  "TEXT",
    # NEW: Windows Event Log RecordNumber — drives the Event-Viewer-style
    # incremental fetch. Per-channel monotonic ID assigned by Windows.
    "record_number": "INTEGER",
}


def get_conn():
    """Return a new SQLite connection. Always use this rather than sqlite3.connect() directly."""
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row   # rows accessible by column name
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


CREATE_ANALYSIS_REPORTS = """
CREATE TABLE IF NOT EXISTS analysis_reports (
    id           TEXT PRIMARY KEY,
    name         TEXT,
    generated_at TEXT,
    risk_label   TEXT,
    risk_score   INTEGER,
    report_json  TEXT,
    trigger      TEXT DEFAULT 'manual'
)
"""

CREATE_SECURITY_ALERTS = """
CREATE TABLE IF NOT EXISTS security_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id     TEXT UNIQUE,
    timestamp    TEXT,
    severity     TEXT,
    alert_type   TEXT,
    category     TEXT,
    event_id     INTEGER,
    source       TEXT,
    user_name    TEXT,
    ip_address   TEXT,
    risk_score   INTEGER DEFAULT 0,
    title        TEXT,
    description  TEXT,
    raw_json     TEXT,
    read         INTEGER DEFAULT 0,
    resolved     INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now'))
)
"""

# Columns that must exist in security_alerts (for auto-migration)
SECURITY_ALERTS_REQUIRED_COLS = {
    "alert_id":    "TEXT",
    "alert_type":  "TEXT",
    "category":    "TEXT",
    "event_id":    "INTEGER",
    "source":      "TEXT",
    "user_name":   "TEXT",
    "ip_address":  "TEXT",
    "risk_score":  "INTEGER",
    "raw_json":    "TEXT",
    "resolved":    "INTEGER",
    "created_at":  "TEXT",
}

def init_db():
    """Create tables + auto-migrate existing DBs."""
    # Backup existing DB before performing migrations/dedupe
    try:
        import shutil
        if os.path.exists(DB_PATH) and not os.path.exists(DB_PATH + ".bak"):
            shutil.copy2(DB_PATH, DB_PATH + ".bak")
    except Exception:
        pass

    conn = get_conn()
    c = conn.cursor()

    for cat in CATEGORIES:
        c.execute(CREATE_LOGS_TABLE.format(cat=cat))
        _rebuild_logs_table_without_unique_content_hash(conn, cat)

        # Auto-migrate: add any missing columns before creating indexes.
        c.execute(f"PRAGMA table_info(logs_{cat})")
        existing_cols = {row[1] for row in c.fetchall()}
        for col, col_type in REQUIRED_COLUMNS.items():
            if col not in existing_cols:
                c.execute(f"ALTER TABLE logs_{cat} ADD COLUMN {col} {col_type}")
                if col == "date":
                    c.execute(f"UPDATE logs_{cat} SET date = substr(timestamp, 1, 10)")

        for idx_sql in INDEXES:
            c.execute(idx_sql.format(cat=cat))

        # Remove old strict uniqueness index that was preventing legitimate event duplicates.
        try:
            c.execute(f"DROP INDEX IF EXISTS uniq_logs_{cat}_ts_eid_src")
        except Exception:
            pass

    c.execute(CREATE_HE_CACHE)
    c.execute(CREATE_EVENTS_LOG)
    c.execute(CREATE_ANALYSIS_REPORTS)

    # Create security_alerts table
    c.execute(CREATE_SECURITY_ALERTS)

    # Auto-migrate security_alerts: add any missing columns
    c.execute("PRAGMA table_info(security_alerts)")
    existing_alert_cols = {row[1] for row in c.fetchall()}
    for col, col_type in SECURITY_ALERTS_REQUIRED_COLS.items():
        if col not in existing_alert_cols:
            c.execute(f"ALTER TABLE security_alerts ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()
    print(f"Database ready: {DB_PATH}")


def _rebuild_logs_table_without_unique_content_hash(conn, cat):
    c = conn.cursor()
    create_sql = c.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (f"logs_{cat}",)
    ).fetchone()
    if not create_sql:
        return

    create_sql = create_sql[0] or ""
    if "content_hash TEXT UNIQUE" not in create_sql:
        return

    print(f"Rebuilding logs_{cat} without UNIQUE(content_hash)")
    c.execute(f"ALTER TABLE logs_{cat} RENAME TO logs_{cat}_old")
    c.execute(CREATE_LOGS_TABLE.format(cat=cat))

    new_cols = [row[1] for row in c.execute(f"PRAGMA table_info(logs_{cat})")]
    old_cols = {row[1] for row in c.execute(f"PRAGMA table_info(logs_{cat}_old)")}
    insert_cols = [col for col in new_cols if col in old_cols]
    if insert_cols:
        cols_sql = ", ".join(insert_cols)
        c.execute(
            f"INSERT INTO logs_{cat} ({cols_sql}) SELECT {cols_sql} FROM logs_{cat}_old"
        )

    c.execute(f"DROP TABLE logs_{cat}_old")


def log_app_event(event_type: str, payload: dict):
    """Record an internal app event (fetch, analysis, chat query, etc.)."""
    import json
    conn = get_conn()
    conn.execute(
        "INSERT INTO app_events (event_type, payload) VALUES (?,?)",
        (event_type, json.dumps(payload))
    )
    conn.commit()
    conn.close()


# Alias used by some api modules
log_activity = log_app_event


# ── Intruder / Login tables ────────────────────────────────────────────────────

_INTRUDER_SCHEMA = """
CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    ip          TEXT,
    user_agent  TEXT,
    success     INTEGER NOT NULL DEFAULT 0,
    timestamp   TEXT NOT NULL,
    session_id  TEXT
);

CREATE TABLE IF NOT EXISTS intruder_captures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    ip          TEXT,
    timestamp   TEXT NOT NULL,
    photo_b64   TEXT,           -- base64 JPEG from webcam
    attempt_no  INTEGER,        -- which attempt triggered this (3, 4, 5…)
    dismissed   INTEGER DEFAULT 0
);
"""

def init_auth_db():
    """Create login/intruder tables if they don't exist."""
    conn = get_conn()
    conn.executescript(_INTRUDER_SCHEMA)
    conn.commit()
    conn.close()


def log_login_attempt(username: str, ip: str, user_agent: str, success: bool, session_id: str = ""):
    conn = get_conn(); c = conn.cursor()
    from datetime import datetime
    c.execute(
        "INSERT INTO login_attempts (username, ip, user_agent, success, timestamp, session_id) VALUES (?,?,?,?,?,?)",
        (username, ip, user_agent, int(success), datetime.now().isoformat(), session_id)
    )
    conn.commit()
    # Return count of recent failed attempts from this IP
    c.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND timestamp >= datetime('now','-10 minutes')",
        (ip,)
    )
    count = c.fetchone()[0]
    conn.close()
    return count


def save_intruder_capture(username: str, ip: str, photo_b64: str, attempt_no: int):
    conn = get_conn(); c = conn.cursor()
    from datetime import datetime
    c.execute(
        "INSERT INTO intruder_captures (username, ip, timestamp, photo_b64, attempt_no) VALUES (?,?,?,?,?)",
        (username, ip, datetime.now().isoformat(), photo_b64, attempt_no)
    )
    conn.commit()
    conn.close()


def get_intruder_captures(limit=50):
    conn = get_conn(); c = conn.cursor()
    c.execute(
        "SELECT id, username, ip, timestamp, photo_b64, attempt_no, dismissed FROM intruder_captures ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = [dict(zip(['id','username','ip','timestamp','photo_b64','attempt_no','dismissed'], r)) for r in c.fetchall()]
    conn.close()
    return rows


def dismiss_intruder(capture_id: int):
    conn = get_conn()
    conn.execute("UPDATE intruder_captures SET dismissed=1 WHERE id=?", (capture_id,))
    conn.commit()
    conn.close()


def get_failed_attempts(ip: str, minutes: int = 10):
    conn = get_conn(); c = conn.cursor()
    c.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND timestamp >= datetime('now', ? || ' minutes')",
        (ip, f"-{minutes}")
    )
    count = c.fetchone()[0]
    conn.close()
    return count


# ── Fetch cursors (incremental fetch like Event Viewer) ───────────────────────
#
# Stores the highest Windows EventLog RecordNumber we've ingested per channel,
# plus the wall-clock timestamp of the last successful pull. The fetch endpoint
# reads this on every click and asks Windows for events *newer* than the cursor.

_FETCH_CURSORS_SCHEMA = """
CREATE TABLE IF NOT EXISTS fetch_cursors (
    category        TEXT PRIMARY KEY,        -- application / system / security / windows_update
    last_record_no  INTEGER NOT NULL DEFAULT 0,
    last_fetched_at TEXT,
    note            TEXT
);
"""


def ensure_fetch_cursors_table(conn=None):
    """Create the fetch_cursors table on demand. Safe to call repeatedly."""
    close = conn is None
    if conn is None:
        conn = get_conn()
    conn.execute(_FETCH_CURSORS_SCHEMA)
    # Seed any missing categories with a zero cursor
    for cat in CATEGORIES:
        conn.execute(
            "INSERT OR IGNORE INTO fetch_cursors (category, last_record_no) VALUES (?, 0)",
            (cat,)
        )
    conn.commit()
    if close:
        conn.close()


def ensure_record_number_column(conn=None):
    """Auto-migrate: add record_number column to logs_* tables if missing."""
    close = conn is None
    if conn is None:
        conn = get_conn()
    c = conn.cursor()
    for cat in CATEGORIES:
        try:
            c.execute(f"PRAGMA table_info(logs_{cat})")
            cols = {row[1] for row in c.fetchall()}
            if "record_number" not in cols:
                c.execute(f"ALTER TABLE logs_{cat} ADD COLUMN record_number INTEGER")
            # Helpful index for "what was the highest record I have?" lookups
            c.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{cat}_record_no "
                f"ON logs_{cat}(record_number)"
            )
        except Exception:
            pass
    conn.commit()
    if close:
        conn.close()


def get_cursor(conn, category: str) -> int:
    """Return the last RecordNumber we ingested for this channel (0 = none)."""
    try:
        r = conn.execute(
            "SELECT last_record_no FROM fetch_cursors WHERE category=?",
            (category,)
        ).fetchone()
        return int(r[0]) if r and r[0] is not None else 0
    except Exception:
        return 0


def set_cursor(conn, category: str, record_no: int, note: str = ""):
    """Persist the new RecordNumber for this channel."""
    from datetime import datetime
    conn.execute("""
        INSERT INTO fetch_cursors (category, last_record_no, last_fetched_at, note)
            VALUES (?, ?, ?, ?)
        ON CONFLICT(category) DO UPDATE SET
            last_record_no  = excluded.last_record_no,
            last_fetched_at = excluded.last_fetched_at,
            note            = excluded.note
    """, (category, int(record_no), datetime.now().isoformat(), note))
    conn.commit()
