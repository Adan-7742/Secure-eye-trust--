"""
database/db_sysmon_patch.py
============================
ADD THESE BLOCKS INTO database/db.py  — do not replace db.py, patch it.

INSTRUCTIONS
------------
1. Copy CREATE_SYSMON_TABLE (the SQL string) into db.py alongside
   CREATE_LOGS_TABLE and CREATE_HE_CACHE.

2. Copy SYSMON_INDEXES into db.py alongside the existing INDEXES list.

3. In init_db(), after the loop that creates logs_{cat} tables, add
   the two lines shown in the  ── init_db patch ──  section below.

4. Add SYSMON_REQUIRED_COLUMNS to the auto-migrate block if you want
   future schema changes to be picked up automatically.

No existing tables, columns, or functions need to change.
"""

# ── 1. Table DDL ─────────────────────────────────────────────────────────────

CREATE_SYSMON_TABLE = """
CREATE TABLE IF NOT EXISTS logs_sysmon (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Standard pipeline columns (matches logs_security / logs_system schema)
    timestamp        TEXT,
    date             TEXT,                       -- YYYY-MM-DD
    level            TEXT,                       -- INFO / WARNING / HIGH / CRITICAL
    source           TEXT DEFAULT 'Sysmon',
    message          TEXT,
    event_id         INTEGER,
    raw              TEXT,
    risk_score       INTEGER DEFAULT 0,
    risk_category    TEXT,
    content_hash     TEXT UNIQUE,
    uploaded_at      TEXT DEFAULT (datetime('now')),

    -- EID 1: Process Create
    process_guid     TEXT,
    process_id       INTEGER,
    command_line     TEXT,
    parent_image     TEXT,
    hashes           TEXT,

    -- EID 3: Network Connection
    source_ip        TEXT,
    dest_ip          TEXT,
    source_port      INTEGER,
    dest_port        INTEGER,
    protocol         TEXT,

    -- EID 11: File Create
    target_filename  TEXT,

    -- EID 13: Registry Value Set
    target_object    TEXT,

    -- EID 22: DNS Query
    query_name       TEXT
)
"""

# ── 2. Indexes ────────────────────────────────────────────────────────────────

SYSMON_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_sysmon_date         ON logs_sysmon(date)",
    "CREATE INDEX IF NOT EXISTS idx_sysmon_event_id     ON logs_sysmon(event_id)",
    "CREATE INDEX IF NOT EXISTS idx_sysmon_timestamp    ON logs_sysmon(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_sysmon_process_guid ON logs_sysmon(process_guid)",
    "CREATE INDEX IF NOT EXISTS idx_sysmon_parent_image ON logs_sysmon(parent_image)",
    "CREATE INDEX IF NOT EXISTS idx_sysmon_dest_ip      ON logs_sysmon(dest_ip)",
    "CREATE INDEX IF NOT EXISTS idx_sysmon_target_obj   ON logs_sysmon(target_object)",
    "CREATE INDEX IF NOT EXISTS idx_sysmon_risk         ON logs_sysmon(risk_score)",
]

# ── 3. Auto-migrate columns (optional safety net) ─────────────────────────────

SYSMON_REQUIRED_COLUMNS = {
    "date":           "TEXT",
    "risk_score":     "INTEGER DEFAULT 0",
    "risk_category":  "TEXT",
    "content_hash":   "TEXT",
    "process_guid":   "TEXT",
    "process_id":     "INTEGER",
    "command_line":   "TEXT",
    "parent_image":   "TEXT",
    "hashes":         "TEXT",
    "source_ip":      "TEXT",
    "dest_ip":        "TEXT",
    "source_port":    "INTEGER",
    "dest_port":      "INTEGER",
    "protocol":       "TEXT",
    "target_filename":"TEXT",
    "target_object":  "TEXT",
    "query_name":     "TEXT",
}


# ─────────────────────────────────────────────────────────────────────────────
# ── init_db patch ─────────────────────────────────────────────────────────────
# Add this block inside init_db() in database/db.py, right after
# the closing line:   conn.commit()
# that finishes the existing CATEGORIES loop.
#
# PASTE THESE LINES:
#
#     # ── Sysmon table ─────────────────────────────────────────────────
#     c.execute(CREATE_SYSMON_TABLE)
#
#     # Auto-migrate: add any missing Sysmon columns
#     c.execute("PRAGMA table_info(logs_sysmon)")
#     existing_sysmon_cols = {row[1] for row in c.fetchall()}
#     for col, col_type in SYSMON_REQUIRED_COLUMNS.items():
#         if col not in existing_sysmon_cols:
#             c.execute(f"ALTER TABLE logs_sysmon ADD COLUMN {col} {col_type}")
#
#     for idx_sql in SYSMON_INDEXES:
#         c.execute(idx_sql)
#
# ─────────────────────────────────────────────────────────────────────────────


def _apply_sysmon_schema():
    """
    Standalone helper — call this from app.py startup or from db.init_db()
    to ensure logs_sysmon exists with all required columns and indexes.

    This is the safe, additive approach: it creates the table if absent,
    adds any missing columns, and creates all indexes — it never drops anything.

    Usage in app.py:
        from database.db_sysmon_patch import _apply_sysmon_schema
        _apply_sysmon_schema()
    """
    import sqlite3
    import os

    # Resolve DB_PATH the same way db.py does
    db_path = os.path.join(os.path.dirname(__file__), "logs.db")

    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    c = conn.cursor()

    # Create table
    c.execute(CREATE_SYSMON_TABLE)

    # Auto-migrate columns
    c.execute("PRAGMA table_info(logs_sysmon)")
    existing_cols = {row[1] for row in c.fetchall()}
    for col, col_type in SYSMON_REQUIRED_COLUMNS.items():
        if col not in existing_cols:
            try:
                c.execute(f"ALTER TABLE logs_sysmon ADD COLUMN {col} {col_type}")
            except Exception:
                pass

    # Create indexes
    for idx_sql in SYSMON_INDEXES:
        try:
            c.execute(idx_sql)
        except Exception:
            pass

    conn.commit()
    conn.close()
    print("✅ logs_sysmon table ready")
