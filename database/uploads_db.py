"""
database/uploads_db.py
======================
Separate SQLite DB for uploaded log files.
Completely isolated from main logs.db — never touches it.
"""
import os, sqlite3

_DB_PATH = os.path.join(os.path.dirname(__file__), "uploads.db")

CATEGORIES = ["application", "system", "security", "windows_update"]

def get_upload_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_uploads_db():
    conn = get_upload_conn()
    c = conn.cursor()
    for cat in CATEGORIES:
        c.execute(f"""
            CREATE TABLE IF NOT EXISTS logs_{cat} (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                date      TEXT,
                level     TEXT,
                source    TEXT,
                message   TEXT,
                event_id  TEXT,
                raw       TEXT,
                filename  TEXT,
                uploaded_at TEXT DEFAULT (datetime('now'))
            )
        """)
    conn.commit()
    conn.close()
    print(f"✅ Uploads DB ready: {_DB_PATH}")
