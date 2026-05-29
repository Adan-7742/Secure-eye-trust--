"""
core/event_collector/windows_reader.py
=======================================
Reads REAL Windows Event Logs using pywin32.
Falls back to simulated data on non-Windows or missing pywin32.

DATA SOURCE:
  Windows Event Log Service  ──(win32evtlog API)──►  This module
      ↓
  List of dicts:
      { timestamp, date, level, source, message, event_id, raw }
      ↓
  Caller (api/system_api.py fetch endpoint) inserts to SQLite

CHANNELS READ:
  - Application  →  logs_application
  - System       →  logs_system
  - Security     →  logs_security  (requires Administrator)
  - System (filtered by WU sources) → logs_windows_update
"""

import ctypes
import re
from datetime import datetime

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

# Windows Update event sources
WU_SOURCES = {
    "windowsupdateclient",
    "wuauclt",
    "wudfhost",
    "microsoft-windows-windowsupdateclient",
}

WIN_TYPE_MAP = {
    win32con.EVENTLOG_ERROR_TYPE:         "ERROR"   if WIN32_AVAILABLE else "",
    win32con.EVENTLOG_WARNING_TYPE:       "WARNING" if WIN32_AVAILABLE else "",
    win32con.EVENTLOG_INFORMATION_TYPE:   "INFO"    if WIN32_AVAILABLE else "",
    win32con.EVENTLOG_AUDIT_SUCCESS:      "SUCCESS" if WIN32_AVAILABLE else "",
    win32con.EVENTLOG_AUDIT_FAILURE:      "FAILURE" if WIN32_AVAILABLE else "",
} if WIN32_AVAILABLE else {}


def is_admin() -> bool:
    """True if current process has Windows Administrator rights."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _safe_format_message(ev) -> str:
    """Resolve human-readable message from event DLL. Never raises."""
    try:
        return win32evtlogutil.SafeFormatMessage(ev, ev.SourceName) or ""
    except Exception:
        inserts = ev.StringInserts
        return " | ".join(inserts) if inserts else f"Event {ev.EventID & 0xFFFF}"


def _enable_security_privilege() -> bool:
    """Enable SeSecurityPrivilege on the current process token — needed to read the Security log."""
    if not WIN32_AVAILABLE:
        return False
    try:
        import win32security, win32api, ntsecuritycon
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        )
        luid = win32security.LookupPrivilegeValue(None, ntsecuritycon.SE_SECURITY_NAME)
        win32security.AdjustTokenPrivileges(token, False, [(luid, win32security.SE_PRIVILEGE_ENABLED)])
        return True
    except Exception:
        return False


def read_channel(channel: str) -> list[dict]:
    """
    Read ALL events from a Windows Event Log channel.
    Returns list of parsed dicts.

    channel: "Application" | "System" | "Security"
    """
    if not WIN32_AVAILABLE:
        return []

    # Elevate privilege before touching the Security log
    if channel == "Security":
        _enable_security_privilege()

    results = []
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                ts_obj    = ev.TimeGenerated
                ts_str    = ts_obj.strftime("%Y-%m-%d %H:%M:%S") if ts_obj else ""
                date_str  = ts_str[:10]
                level     = WIN_TYPE_MAP.get(ev.EventType, "INFO")
                source    = ev.SourceName or ""
                msg       = _safe_format_message(ev)
                eid       = ev.EventID & 0xFFFF

                results.append({
                    "timestamp": ts_str,
                    "date":      date_str,
                    "level":     level,
                    "source":    source,
                    "message":   msg[:2000],
                    "event_id":  eid,
                    "raw":       msg[:500],
                })

        win32evtlog.CloseEventLog(handle)

    except Exception as e:
        err_str = str(e)
        if "5" in err_str or "access" in err_str.lower() or "1314" in err_str:
            print(f"⛔ Access denied reading '{channel}' — run as Administrator")
        else:
            print(f"⚠  Error reading '{channel}': {e}")

    return results


def read_windows_update_events() -> list[dict]:
    """
    Filter System log for Windows Update sources.
    Returns only WU-related events.
    """
    all_system = read_channel("System")
    return [
        e for e in all_system
        if e["source"].lower() in WU_SOURCES
    ]


def fetch_all() -> dict[str, list]:
    """
    Fetch all four categories.
    Returns { "application": [...], "system": [...], "security": [...], "windows_update": [...] }
    """
    print("📥 Reading Application log ...")
    app_logs = read_channel("Application")
    print(f"   → {len(app_logs)} events")

    print("📥 Reading System log ...")
    sys_logs = read_channel("System")
    print(f"   → {len(sys_logs)} events")

    print("📥 Reading Security log ...")
    sec_logs = read_channel("Security")
    print(f"   → {len(sec_logs)} events")

    print("📥 Filtering Windows Update events from System ...")
    wu_logs = [e for e in sys_logs if e["source"].lower() in WU_SOURCES]
    print(f"   → {len(wu_logs)} events")

    return {
        "application":    app_logs,
        "system":         sys_logs,
        "security":       sec_logs,
        "windows_update": wu_logs,
    }
