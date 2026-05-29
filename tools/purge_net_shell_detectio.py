"""
tools/purge_net_shell_detection.py
===================================
Standalone script — kisi bhi import ki zaroorat nahi.
Seedha SQLite DB file dhundh kar SIGMA_NET_SHELL_EXTERNAL
aur saare SET_TEST fixture rows delete karta hai.

USAGE:
    python tools/purge_net_shell_detection.py
    python tools/purge_net_shell_detection.py --dry-run
"""

from __future__ import annotations
import argparse
import os
import sqlite3
import sys
from pathlib import Path


# ── DB file dhundho ────────────────────────────────────────────────────────────
def find_db() -> Path | None:
    """
    logs.db ya locker.db dhundho — pehle script ke paas,
    phir upar jaate hue app root tak.
    """
    candidates = ["logs.db", "locker.db", "uploads.db"]
    # Script ke folder se shuru karke upar jaao
    start = Path(__file__).resolve().parent
    for folder in [start, start.parent, start.parent / "database"]:
        for name in candidates:
            p = folder / name
            if p.exists():
                return p
    # Kuch aur common locations
    extra = [
        Path(__file__).resolve().parent.parent / "database" / "logs.db",
        Path(__file__).resolve().parent.parent / "database" / "locker.db",
    ]
    for p in extra:
        if p.exists():
            return p
    return None


def purge(dry_run: bool = False) -> None:

    db_path = find_db()
    if db_path is None:
        print("✗  Database file nahi mila.")
        print("   Script ko app ke root folder se chalao, ya db_path variable set karo.")
        sys.exit(1)

    print(f"   DB: {db_path}\n")
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()

    # ── Table check ───────────────────────────────────────────────────────────
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    all_tables = [r[0] for r in c.fetchall()]

    if "logs_sysmon" not in all_tables:
        print("✗  logs_sysmon table nahi mili.")
        print(f"   Available tables: {all_tables}")
        conn.close()
        sys.exit(1)

    # ── Actual columns dhundho ────────────────────────────────────────────────
    c.execute("PRAGMA table_info(logs_sysmon)")
    cols = {row[1] for row in c.fetchall()}
    print(f"   Columns found: {sorted(cols)}\n")

    # ── WHERE conditions — sirf jo columns exist karti hain ──────────────────
    # Har condition safely wrapped hai COALESCE mein
    def col_like(col: str, pattern: str) -> str | None:
        if col in cols:
            return f"COALESCE({col},'') LIKE '{pattern}'"
        return None

    def col_between(col: str, lo: int, hi: int) -> str | None:
        if col in cols:
            return f"{col} BETWEEN {lo} AND {hi}"
        return None

    raw_conditions = [
        # PID range reserved for all SET_TEST fixtures
        col_between("sysmon_process_id", 39700, 39720),
        # The injected RFC-5737 test-net IP (never real traffic)
        col_like("sysmon_target_object", "%192.0.2.%"),
        col_like("target_object",        "%192.0.2.%"),
        # SET_TEST tagged rows — all column variants
        col_like("sysmon_image",         "%SET_TEST%"),
        col_like("sysmon_parent_image",  "%SET_TEST%"),
        col_like("sysmon_target_file",   "%SET_TEST%"),
        col_like("sysmon_target_object", "%SET_TEST%"),
        col_like("sysmon_command_line",  "%SET_TEST%"),
        col_like("image",                "%SET_TEST%"),
        col_like("parent_image",         "%SET_TEST%"),
        col_like("target_filename",      "%SET_TEST%"),
        col_like("target_object",        "%SET_TEST%"),
        col_like("command_line",         "%SET_TEST%"),
        col_like("group_id",             "SET_TEST-%"),
        col_like("synthetic_attack_id",  "SET_TEST-%"),
    ]

    conditions = [c_ for c_ in raw_conditions if c_ is not None]

    if not conditions:
        print("✗  Koi bhi matching column nahi mili — schema check karo.")
        conn.close()
        return

    where = " OR ".join(conditions)

    # ── Preview ───────────────────────────────────────────────────────────────
    # Select karo ID aur jo bhi image column exist karti hai
    img_col = (
        "sysmon_image" if "sysmon_image" in cols else
        "image"        if "image"        in cols else
        "NULL"
    )
    eid_col = "event_id" if "event_id" in cols else "NULL"

    c.execute(f"SELECT id, {eid_col}, COALESCE({img_col},'(none)') FROM logs_sysmon WHERE {where}")
    rows = c.fetchall()

    if not rows:
        print("✓  Kuch nahi mila — database already clean hai.")
        conn.close()
        return

    print(f"{'[DRY RUN] ' if dry_run else ''}Delete hone wale rows ({len(rows)} total):\n")
    for row_id, eid, img in rows:
        print(f"  id={row_id:<6} EID={eid!s:<6} image={img}")

    if dry_run:
        print(f"\n  (Dry-run: kuch delete nahi hua — bina --dry-run ke chalao)\n")
        conn.close()
        return

    # ── Delete ────────────────────────────────────────────────────────────────
    c.execute(f"DELETE FROM logs_sysmon WHERE {where}")
    deleted = c.rowcount or 0
    conn.commit()
    conn.close()

    print(f"\n✓  {deleted} row(s) delete ho gaye logs_sysmon se.")
    print("   Ab app mein:  Perform Analysis → Start Hunting  chalao.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SIGMA_NET_SHELL_EXTERNAL aur SET_TEST rows ko DB se hataao."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Sirf dikhao kya delete hoga — actually delete mat karo",
    )
    args = parser.parse_args()
    purge(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
