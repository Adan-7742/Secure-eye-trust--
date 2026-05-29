"""
database/he_migration.py
==========================
FR02-04: Adds encrypted field columns to all logs_* tables.
FR02-05: Creates he_key_store table for Windows CSP key metadata.

Run ONCE after installing the new HE files:
    python database/he_migration.py

Safe to re-run — uses ALTER TABLE only when column is missing.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import get_conn, CATEGORIES

# Encrypted PII columns (FR02-01, FR02-03)
ENC_COLUMNS = [
    ("enc_username",     "TEXT"),   # JSON: AES-GCM encrypted username
    ("enc_ip_address",   "TEXT"),   # JSON: AES-GCM encrypted IP address
    ("enc_machine_name", "TEXT"),   # JSON: AES-GCM encrypted machine name
    ("ip_pseudonym",     "TEXT"),   # HMAC pseudonym of IP (indexable, private)
    ("user_pseudonym",   "TEXT"),   # HMAC pseudonym of username
    ("he_kid",           "TEXT"),   # Key-id for decryption routing (FR02-04)
]

# HE key store table (FR02-04, FR02-05)
CREATE_HE_KEY_STORE = """
CREATE TABLE IF NOT EXISTS he_key_store (
    kid          TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    is_active    INTEGER NOT NULL DEFAULT 1,
    cert_thumb   TEXT DEFAULT '',
    dpapi_bound  INTEGER NOT NULL DEFAULT 0,
    wincred_stored INTEGER NOT NULL DEFAULT 0,
    notes        TEXT DEFAULT ''
)
"""

# HE audit log — records every encrypt/decrypt operation (FR02-04)
CREATE_HE_AUDIT = """
CREATE TABLE IF NOT EXISTS he_audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    operation    TEXT NOT NULL,   -- 'encrypt_field' | 'decrypt_field' | 'key_rotate' | 'key_load'
    kid          TEXT,
    field_name   TEXT,
    category     TEXT,
    performed_by TEXT DEFAULT 'system',
    ts           TEXT DEFAULT (datetime('now'))
)
"""


def migrate():
    conn = get_conn()
    c    = conn.cursor()

    print("─" * 60)
    print("HE Migration — FR02-04, FR02-05")
    print("─" * 60)

    # 1. Add encrypted columns to all logs_* tables
    for cat in CATEGORIES:
        table = f"logs_{cat}"
        c.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in c.fetchall()}

        for col_name, col_type in ENC_COLUMNS:
            if col_name not in existing:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                print(f"  ✅  {table}: added '{col_name}' ({col_type})")
            else:
                print(f"  ──  {table}: '{col_name}' already exists")

    # 2. Create he_key_store table (FR02-04)
    conn.execute(CREATE_HE_KEY_STORE)
    print("  ✅  he_key_store table ready")

    # 3. Create he_audit_log table (FR02-04)
    conn.execute(CREATE_HE_AUDIT)
    print("  ✅  he_audit_log table ready")

    conn.commit()
    conn.close()
    print("─" * 60)
    print("Migration complete.")
    print()
    print("Next steps:")
    print("  1. Set master passphrase:")
    print("     Windows: python -c \"from core.key_management.key_manager import KeyManager; KeyManager.store_passphrase_in_credential_manager('your-strong-passphrase')\"")
    print("     Other:   set SECURE_EYE_MASTER_KEY=your-strong-passphrase")
    print()
    print("  2. Verify HE engine:")
    print("     python database/he_migration.py --verify")


def verify():
    """Quick verification that migration was applied correctly."""
    conn = get_conn()
    c    = conn.cursor()
    ok   = True

    for cat in CATEGORIES:
        c.execute(f"PRAGMA table_info(logs_{cat})")
        cols = {row[1] for row in c.fetchall()}
        for col_name, _ in ENC_COLUMNS:
            if col_name not in cols:
                print(f"  ❌  logs_{cat} missing column '{col_name}'")
                ok = False

    # Check tables
    for tbl in ("he_key_store", "he_audit_log", "he_analysis_cache"):
        c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (tbl,))
        if not c.fetchone():
            print(f"  ❌  Table '{tbl}' missing")
            ok = False

    conn.close()
    if ok:
        print("  ✅  All HE columns and tables present — migration verified")
    return ok


if __name__ == "__main__":
    if "--verify" in sys.argv:
        verify()
    else:
        migrate()
        verify()
