"""
core/event_collector/collector.py
==================================
Reads real Windows Event Logs using pywin32.
Falls back to demo data if pywin32 is not installed (non-Windows dev).

DATA FLOW:
    Windows OS → win32evtlog.OpenEventLog()
               → ReadEventLog() [reads backwards, newest first]
               → _parse_event()    [converts to our standard dict]
               → caller inserts into database via database/db.py

HOW IT WORKS WITH PYTHON:
    pywin32 is a Python binding to the Windows API.
    win32evtlog.ReadEventLog() returns a list of EventLogRecord objects.
    Each record has: EventID, TimeGenerated, SourceName, StringInserts, EventType
    We convert those to our standard schema: timestamp, level, source, message, event_id

WHAT EVENTS ARE CAPTURED:
    Application log → all app crashes, errors, warnings
    System log      → hardware, driver, service, power events
    Security log    → logon/logoff, account changes, policy changes (ADMIN REQUIRED)
    Windows Update  → filtered from System log by known WU source names
"""

from datetime import datetime
from utils.logger import get_logger

log = get_logger("event_collector")

# ── Try to import pywin32 ─────────────────────────────────────────────────────
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import pywintypes
    WIN32_AVAILABLE = True
    log.info("pywin32 available — reading real Windows Event Logs")
except ImportError:
    WIN32_AVAILABLE = False
    log.warning("pywin32 not installed. Install: pip install pywin32")

# ── Windows Update source names ───────────────────────────────────────────────
WU_SOURCES = {
    "windowsupdateclient",
    "wuauclt",
    "wudfhost",
    "microsoft-windows-windowsupdateclient",
    "cbshandler",
    "servicing",
}

# ── Map Windows event type codes → readable level strings ────────────────────
WIN_TYPE_MAP = {
    win32con.EVENTLOG_ERROR_TYPE:         "ERROR",
    win32con.EVENTLOG_WARNING_TYPE:       "WARNING",
    win32con.EVENTLOG_INFORMATION_TYPE:   "INFO",
    win32con.EVENTLOG_AUDIT_SUCCESS:      "SUCCESS",
    win32con.EVENTLOG_AUDIT_FAILURE:      "FAILURE",
} if WIN32_AVAILABLE else {}


def _safe_format_message(ev) -> str:
    """
    Convert a Windows EventLogRecord to a human-readable string.
    Uses message DLL resolution first, falls back to StringInserts.
    """
    try:
        return win32evtlogutil.SafeFormatMessage(ev, ev.SourceName)
    except Exception:
        if ev.StringInserts:
            return " | ".join(str(s) for s in ev.StringInserts)
        return f"Event ID {ev.EventID & 0xFFFF}"


def _parse_event(ev, category: str) -> dict:
    """
    Convert a win32evtlog EventLogRecord → our standard dict schema.
    event_id masking: ev.EventID & 0xFFFF strips the facility/severity bits
    that Windows packs into the high bits of the 32-bit EventID field.
    """
    ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S") if hasattr(ev.TimeGenerated, "Format") else str(ev.TimeGenerated)
    date = ts[:10]  # YYYY-MM-DD

    return {
        "timestamp":     ts,
        "date":          date,
        "level":         WIN_TYPE_MAP.get(ev.EventType, "INFO"),
        "source":        ev.SourceName or "",
        "message":       _safe_format_message(ev),
        "event_id":      ev.EventID & 0xFFFF,
        "record_number": int(getattr(ev, "RecordNumber", 0) or 0),
        "raw":           f"[{category.upper()}] {ts} EID={ev.EventID & 0xFFFF} src={ev.SourceName}",
        "uploaded_at":   datetime.now().isoformat(),
    }


import ctypes
import ctypes.wintypes


def _grant_se_security_privilege() -> bool:
    """
    Enable SeSecurityPrivilege on the current process using raw ctypes.
    This is the most reliable method — pywin32's AdjustTokenPrivileges
    often silently fails due to how it maps privilege constants.
    Returns True if the privilege was successfully enabled.
    """
    try:
        ADVAPI = ctypes.windll.advapi32
        KERNEL  = ctypes.windll.kernel32

        SE_SECURITY_NAME = "SeSecurityPrivilege"
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY             = 0x0008
        SE_PRIVILEGE_ENABLED    = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.wintypes.DWORD),
                        ("HighPart", ctypes.c_long)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", ctypes.wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        # Open our own process token
        h_token = ctypes.wintypes.HANDLE()
        if not ADVAPI.OpenProcessToken(
            KERNEL.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token)
        ):
            return False

        # Look up SeSecurityPrivilege LUID
        luid = LUID()
        if not ADVAPI.LookupPrivilegeValueW(None, SE_SECURITY_NAME, ctypes.byref(luid)):
            KERNEL.CloseHandle(h_token)
            return False

        # Build TOKEN_PRIVILEGES struct and call AdjustTokenPrivileges
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ADVAPI.AdjustTokenPrivileges(
            h_token, False, ctypes.byref(tp),
            ctypes.sizeof(tp), None, None
        )
        KERNEL.CloseHandle(h_token)
        return True
    except Exception as e:
        log.warning(f"SeSecurityPrivilege grant failed: {e}")
        return False


def read_channel(channel: str) -> list[dict]:
    """
    Read ALL events from a Windows Event Log channel.
    For Security: enables SeSecurityPrivilege via ctypes before reading.
    """
    if not WIN32_AVAILABLE:
        log.warning(f"pywin32 not available — skipping {channel}")
        return []

    if channel == "Security":
        _grant_se_security_privilege()

    results = []
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        total  = win32evtlog.GetNumberOfEventLogRecords(handle)
        log.info(f"{channel}: {total} records available")

        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        cat   = channel.lower().replace(" ", "_")

        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                results.append(_parse_event(ev, cat))

        win32evtlog.CloseEventLog(handle)
        log.info(f"{channel}: read {len(results)} events")

    except Exception as e:
        log.error(f"Could not read {channel}: {e}")
        if channel == "Security":
            log.error("  → Make sure app.py is launched via: Right-click → Run as administrator")

    return results


def read_windows_update() -> list[dict]:
    """
    Windows Update events are inside the System log, not their own channel.
    We filter System log events by known Windows Update source names.
    """
    if not WIN32_AVAILABLE:
        return []

    results = []
    try:
        handle = win32evtlog.OpenEventLog(None, "System")
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                if ev.SourceName and ev.SourceName.lower() in WU_SOURCES:
                    r = _parse_event(ev, "windows_update")
                    results.append(r)
        win32evtlog.CloseEventLog(handle)
        log.info(f"Windows Update: found {len(results)} events in System log")
    except Exception as e:
        log.error(f"Failed to read Windows Update events: {e}")

    return results


def fetch_all_logs() -> dict:
    """
    Main entry point. Reads all four categories.
    Returns: { "application": [...], "system": [...], "security": [...], "windows_update": [...] }
    Also returns metadata about how many were fetched.
    """
    log.info("Starting full Windows Event Log fetch...")
    result = {
        "application":    read_channel("Application"),
        "system":         read_channel("System"),
        "security":       read_channel("Security"),
        "windows_update": read_windows_update(),
    }
    totals = {k: len(v) for k, v in result.items()}
    log.info(f"Fetch complete: {totals}")
    return result, totals


# ─────────────────────────────────────────────────────────────────────────────
# INCREMENTAL READERS — like Event Viewer's "Refresh" button.
#
# These read backwards from the newest event and STOP the moment they
# encounter a record we've already ingested. Used by api/fetch_api.py.
# ─────────────────────────────────────────────────────────────────────────────

def read_channel_since(channel: str, since_record: int) -> tuple[list[dict], int]:
    """
    Read events newer than `since_record` from a Windows Event Log channel.

    Reads BACKWARDS (newest first) and stops as soon as RecordNumber <= cursor.
    On the first ever run, `since_record` is 0 so we collect everything.

    Returns:
        (events, max_record_number_seen)
    """
    if not WIN32_AVAILABLE:
        log.warning(f"pywin32 not available — skipping {channel}")
        return [], since_record

    if channel == "Security":
        _grant_se_security_privilege()

    results: list[dict] = []
    highest = since_record
    handle  = None

    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        total  = win32evtlog.GetNumberOfEventLogRecords(handle)
        log.info(f"{channel}: {total} records in log, cursor at {since_record}")

        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        cat   = channel.lower().replace(" ", "_")
        done  = False

        while not done:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                rn = int(getattr(ev, "RecordNumber", 0) or 0)
                # Reading backwards: once we hit a record we've already seen,
                # everything older has also been seen — stop here.
                if since_record and rn <= since_record:
                    done = True
                    break
                if rn > highest:
                    highest = rn
                results.append(_parse_event(ev, cat))

        log.info(f"{channel}: collected {len(results)} new events (max RecordNumber={highest})")

    except Exception as e:
        log.error(f"read_channel_since({channel}) failed: {e}")
        if channel == "Security":
            log.error("  → Make sure app.py is launched via: Right-click → Run as administrator")
    finally:
        if handle is not None:
            try: win32evtlog.CloseEventLog(handle)
            except Exception: pass

    return results, highest


def read_windows_update_since(since_record: int) -> tuple[list[dict], int]:
    """
    Windows Update events are filtered out of the System channel by source name.
    We carry our own cursor for them so System and WU can advance independently.
    """
    if not WIN32_AVAILABLE:
        return [], since_record

    results: list[dict] = []
    highest = since_record
    handle  = None

    try:
        handle = win32evtlog.OpenEventLog(None, "System")
        flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                  win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        done   = False

        while not done:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                rn = int(getattr(ev, "RecordNumber", 0) or 0)
                if since_record and rn <= since_record:
                    done = True
                    break
                if rn > highest:
                    highest = rn
                # Filter to WU sources
                if ev.SourceName and ev.SourceName.lower() in WU_SOURCES:
                    results.append(_parse_event(ev, "windows_update"))

        log.info(f"WindowsUpdate: collected {len(results)} new events (max RecordNumber={highest})")

    except Exception as e:
        log.error(f"read_windows_update_since failed: {e}")
    finally:
        if handle is not None:
            try: win32evtlog.CloseEventLog(handle)
            except Exception: pass

    return results, highest
