"""
tools/purge_net_shell_detection.py
===================================
One-shot script to permanently remove the SIGMA_NET_SHELL_EXTERNAL
detection from the SecureEyeTrust+ database.

WHY THIS IS NEEDED
------------------
The old setup_malware_test.py injected a Sysmon EID 3 (network connection)
event with image = certutil.exe and target = 192.0.2.200:80.
That event did NOT contain "SET_TEST" in the image column, so the normal
--cleanup pass missed it. This script deletes it directly.

WHAT IT DELETES
---------------
  logs_sysmon rows where:
    • event_id = 3  AND  (image LIKE '%certutil%' OR pid IN (39700-39720))
    • OR target_object LIKE '%192.0.2.%'          (the injected IP)
    • OR target_object LIKE '%SET_TEST%'           (any leftover tagged rows)
    • OR sysmon_process_id BETWEEN 39700 AND 39720 (full fixture PID range)

WHAT IT DOES NOT TOUCH
-----------------------
  • Real Sysmon events (different PIDs, no fixture IP)
  • Any other table
  • Any files on disk

USAGE
-----
  python tools/purge_net_shell_detection.py
  python tools/purge_net_shell_detection.py --dry-run   # preview only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def get_conn():
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))
    from database.db import get_conn as _gc
    return _gc()


def purge(dry_run: bool = False) -> None:
    try:
        conn = get_conn()
    except Exception as e:
        print(f"✗  Could not connect to database: {e}")
        print("   Make sure you run this from the app root folder.")
        return

    c = conn.cursor()

    # ── Introspect schema ──────────────────────────────────────────────────────
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs_sysmon'")
    if not c.fetchone():
        print("✗  logs_sysmon table not found — run the app once first.")
        conn.close()
        return

    c.execute("PRAGMA table_info(logs_sysmon)")
    cols = {row[1] for row in c.fetchall()}

    # ── Build WHERE clause dynamically (handles both schema variants) ──────────
    # Matches ONLY the synthetic EID-3 fixture rows, never real traffic.
    conditions = [
        # PID range reserved for all SET_TEST fixtures
        "sysmon_process_id BETWEEN 39700 AND 39720",
        # The injected test-net IP (192.0.2.x is RFC 5737 — never real traffic)
        "COALESCE(target_object,'')      LIKE '%192.0.2.%'",
        "COALESCE(sysmon_target_object,'') LIKE '%192.0.2.%'",
        # Any remaining SET_TEST-tagged rows missed by previous cleanup
        "COALESCE(target_object,'')      LIKE '%SET_TEST%'",
        "COALESCE(sysmon_target_object,'') LIKE '%SET_TEST%'",
        "COALESCE(image,'')              LIKE '%SET_TEST%'",
        "COALESCE(sysmon_image,'')       LIKE '%SET_TEST%'",
        "COALESCE(parent_image,'')       LIKE '%SET_TEST%'",
        "COALESCE(sysmon_parent_image,'') LIKE '%SET_TEST%'",
        "COALESCE(target_filename,'')    LIKE '%SET_TEST%'",
        "COALESCE(sysmon_target_file,'') LIKE '%SET_TEST%'",
        "COALESCE(command_line,'')       LIKE '%SET_TEST%'",
        "COALESCE(sysmon_command_line,'') LIKE '%SET_TEST%'",
    ]

    # Optional enrichment columns (only if they exist)
    for col in ("group_id", "synthetic_attack_id"):
        if col in cols:
            conditions.append(f"COALESCE({col},'') LIKE 'SET_TEST-%'")

    where = " OR ".join(conditions)

    # ── Preview rows that will be deleted ─────────────────────────────────────
    c.execute(f"SELECT id, event_id, COALESCE(image, sysmon_image, '') FROM logs_sysmon WHERE {where}")
    rows = c.fetchall()

    if not rows:
        print("✓  Nothing to delete — database is already clean.")
        conn.close()
        return

    print(f"\n{'DRY RUN — ' if dry_run else ''}Rows matched for deletion ({len(rows)} total):\n")
    for row_id, eid, img in rows:
        print(f"  id={row_id:<6} EID={eid:<5} image={img or '(none)'}")

    if dry_run:
        print(f"\n  (dry-run: nothing deleted — rerun without --dry-run to apply)\n")
        conn.close()
        return

    # ── Delete ─────────────────────────────────────────────────────────────────
    c.execute(f"DELETE FROM logs_sysmon WHERE {where}")
    deleted = c.rowcount or 0
    conn.commit()
    conn.close()

    print(f"\n✓  Deleted {deleted} row(s) from logs_sysmon.")
    print("   Run  Perform Analysis → Start Hunting  to refresh the dashboard.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Purge SIGMA_NET_SHELL_EXTERNAL and all SET_TEST fixture rows from logs_sysmon."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be deleted without actually deleting anything",
    )
    args = parser.parse_args()
    purge(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
