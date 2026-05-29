"""
core/event_collector/defender_collector.py
===========================================
FR01-04: Windows Defender / Antivirus Log Collection

Reads Defender events from TWO sources:
  1. Windows Event Log channel: "Microsoft-Windows-Windows Defender/Operational"
     (most complete — includes all EIDs)
  2. Fallback: Application + System channels for Defender-sourced events

DEFENDER EVENT IDs MAPPED:
  1116 — Malware detected
  1117 — Action taken on malware
  1118 — Action failed (threat still present)
  1119 — Remediation succeeded
  1120 — Remediation failed (CRITICAL)
  2001 — Scan started
  2002 — Scan completed
  2003 — Scan cancelled
  5001 — Real-time protection disabled  ← CRITICAL
  5004 — Real-time protection config changed
  5007 — Antivirus settings changed
  5010 — Scan for malware and other threats disabled
  5012 — On-access protection disabled

All events are normalized to:
{
  "timestamp":   "...",
  "event_id":    1116,
  "level":       "CRITICAL|HIGH|WARNING|INFO",
  "threat_name": "Trojan:Win32/...",
  "action":      "Quarantine|Remove|Allow|...",
  "path":        "C:\\Users\\...",
  "severity":    "CRITICAL",
  "category":    "malware|defense_evasion|scan",
  "source":      "Windows Defender",
  "raw":         "...",
}
"""

import threading
import time
import re
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("defender_collector")

POLL_INTERVAL = 3   # seconds

# Defender-specific Event ID definitions
DEFENDER_EIDS = {
    1116: {"level": "CRITICAL", "category": "malware",          "name": "Malware Detected"},
    1117: {"level": "CRITICAL", "category": "malware",          "name": "Malware Action Taken"},
    1118: {"level": "CRITICAL", "category": "malware",          "name": "Malware Action Failed"},
    1119: {"level": "HIGH",     "category": "malware",          "name": "Malware Remediation Succeeded"},
    1120: {"level": "CRITICAL", "category": "malware",          "name": "Malware Remediation Failed"},
    2001: {"level": "INFO",     "category": "scan",             "name": "Scan Started"},
    2002: {"level": "INFO",     "category": "scan",             "name": "Scan Completed"},
    2003: {"level": "WARNING",  "category": "scan",             "name": "Scan Cancelled"},
    5001: {"level": "CRITICAL", "category": "defense_evasion",  "name": "Real-Time Protection Disabled"},
    5004: {"level": "WARNING",  "category": "defense_evasion",  "name": "Real-Time Protection Config Changed"},
    5007: {"level": "HIGH",     "category": "defense_evasion",  "name": "Antivirus Settings Changed"},
    5010: {"level": "CRITICAL", "category": "defense_evasion",  "name": "Antivirus Scan Disabled"},
    5012: {"level": "CRITICAL", "category": "defense_evasion",  "name": "On-Access Protection Disabled"},
}

# Defender source names found in Application/System logs
DEFENDER_SOURCES = {
    "windows defender",
    "microsoft antimalware",
    "windefend",
    "microsoft-windows-windows defender",
    "security center",
}

# Regex to extract threat details from Defender messages
_RE_THREAT_NAME = re.compile(r"Threat Name:\s*([^\r\n]+)", re.IGNORECASE)
_RE_ACTION      = re.compile(r"Action:\s*([^\r\n]+)", re.IGNORECASE)
_RE_PATH        = re.compile(r"(?:Path|File):\s*([^\r\n]+)", re.IGNORECASE)
_RE_SEVERITY    = re.compile(r"Severity:\s*([^\r\n]+)", re.IGNORECASE)
_RE_PROCESS     = re.compile(r"Process Name:\s*([^\r\n]+)", re.IGNORECASE)
_RE_USER        = re.compile(r"User:\s*([^\r\n]+)", re.IGNORECASE)


def _extract_defender_fields(message: str) -> dict:
    """Extract structured fields from Defender event message text."""
    def _get(pattern):
        m = pattern.search(message)
        return m.group(1).strip() if m else None

    return {
        "threat_name": _get(_RE_THREAT_NAME),
        "action":      _get(_RE_ACTION),
        "path":        _get(_RE_PATH),
        "severity":    _get(_RE_SEVERITY),
        "process":     _get(_RE_PROCESS),
        "user":        _get(_RE_USER),
    }


def _normalize_defender_event(ev_dict: dict) -> dict:
    """
    Enrich a raw event dict with Defender-specific structured fields.
    Returns a fully normalized Defender event.
    """
    eid     = int(ev_dict.get("event_id") or 0)
    msg     = ev_dict.get("message") or ""
    meta    = DEFENDER_EIDS.get(eid, {})
    fields  = _extract_defender_fields(msg)

    return {
        "timestamp":   ev_dict.get("timestamp"),
        "date":        ev_dict.get("date") or (ev_dict.get("timestamp") or "")[:10],
        "event_id":    eid,
        "level":       meta.get("level", ev_dict.get("level", "INFO")),
        "category":    meta.get("category", "malware"),
        "event_name":  meta.get("name", f"Defender Event {eid}"),
        "source":      ev_dict.get("source") or "Windows Defender",
        "threat_name": fields["threat_name"],
        "action":      fields["action"],
        "path":        fields["path"],
        "threat_severity": fields["severity"],
        "process":     fields["process"],
        "user":        fields["user"],
        "message":     msg[:2000],
        "raw":         msg[:500],
        "channel":     ev_dict.get("channel", "Defender"),
        "hostname":    ev_dict.get("hostname"),
        "collected_at": ev_dict.get("collected_at") or datetime.now().isoformat(),
    }


class DefenderCollector:
    """
    FR01-04 — Streams Windows Defender events in real time.

    Primary source:  Microsoft-Windows-Windows Defender/Operational
    Fallback source: Application log filtered by Defender source names

    Pushes critical Defender events (malware detected, AV disabled)
    directly to AlertBus with CRITICAL severity.
    """

    def __init__(self):
        self._stop        = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_record = 0
        self._last_record_app = 0
        self._events_found = 0
        self._win32ok      = False
        self._TYPE_MAP     = {}
        self._use_defender_channel = True   # try Defender channel first

    def _init_win32(self) -> bool:
        if self._win32ok:
            return True
        try:
            import win32evtlog, win32evtlogutil, win32con
            self._win32evtlog     = win32evtlog
            self._win32evtlogutil = win32evtlogutil
            self._TYPE_MAP = {
                win32con.EVENTLOG_ERROR_TYPE:       "ERROR",
                win32con.EVENTLOG_WARNING_TYPE:     "WARNING",
                win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
                win32con.EVENTLOG_AUDIT_SUCCESS:    "SUCCESS",
                win32con.EVENTLOG_AUDIT_FAILURE:    "FAILURE",
            }
            self._win32ok = True
            return True
        except ImportError:
            return False

    def _safe_msg(self, ev) -> str:
        try:
            return self._win32evtlogutil.SafeFormatMessage(ev, ev.SourceName) or ""
        except Exception:
            if ev.StringInserts:
                return " | ".join(str(s) for s in ev.StringInserts)
            return f"Event {ev.EventID & 0xFFFF}"

    def _read_defender_channel(self) -> list[dict]:
        """Read from Microsoft-Windows-Windows Defender/Operational channel."""
        results = []
        CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
        highest = self._last_record

        try:
            import socket
            handle = self._win32evtlog.OpenEventLog(None, CHANNEL)
            flags  = (self._win32evtlog.EVENTLOG_BACKWARDS_READ |
                      self._win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            done   = False

            while not done:
                batch = self._win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for ev in batch:
                    if ev.RecordNumber <= self._last_record:
                        done = True
                        break
                    if ev.RecordNumber > highest:
                        highest = ev.RecordNumber

                    eid = ev.EventID & 0xFFFF
                    # Only process known Defender EIDs
                    if eid not in DEFENDER_EIDS:
                        continue

                    try:
                        ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                    except Exception:
                        ts = datetime.now().isoformat()

                    msg = self._safe_msg(ev)
                    results.append({
                        "timestamp": ts, "date": ts[:10],
                        "event_id": eid,
                        "level": self._TYPE_MAP.get(ev.EventType, "INFO"),
                        "source": ev.SourceName or "Windows Defender",
                        "message": msg[:2000], "raw": msg[:500],
                        "channel": CHANNEL,
                        "hostname": socket.gethostname(),
                        "collected_at": datetime.now().isoformat(),
                        "record_number": ev.RecordNumber,
                    })

            self._win32evtlog.CloseEventLog(handle)
            if highest > self._last_record:
                self._last_record = highest

        except Exception as e:
            err = str(e)
            if "1314" in err or "not found" in err.lower() or "2" in err:
                # Defender Operational channel not available — fallback
                self._use_defender_channel = False
                log.info("Defender/Operational channel unavailable — using Application log fallback")
            elif "5" not in err and "access" not in err.lower():
                log.error(f"Defender channel read error: {e}")

        return results

    def _read_application_fallback(self) -> list[dict]:
        """Fallback: read Application log filtered by Defender sources."""
        results  = []
        highest  = self._last_record_app
        CHANNEL  = "Application"

        try:
            import socket
            handle = self._win32evtlog.OpenEventLog(None, CHANNEL)
            flags  = (self._win32evtlog.EVENTLOG_BACKWARDS_READ |
                      self._win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            done   = False

            while not done:
                batch = self._win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for ev in batch:
                    if ev.RecordNumber <= self._last_record_app:
                        done = True
                        break
                    if ev.RecordNumber > highest:
                        highest = ev.RecordNumber

                    src = (ev.SourceName or "").lower()
                    eid = ev.EventID & 0xFFFF
                    if src not in DEFENDER_SOURCES and eid not in DEFENDER_EIDS:
                        continue

                    try:
                        ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                    except Exception:
                        ts = datetime.now().isoformat()

                    msg = self._safe_msg(ev)
                    results.append({
                        "timestamp": ts, "date": ts[:10],
                        "event_id": eid,
                        "level": self._TYPE_MAP.get(ev.EventType, "INFO"),
                        "source": ev.SourceName or "Windows Defender",
                        "message": msg[:2000], "raw": msg[:500],
                        "channel": CHANNEL,
                        "hostname": socket.gethostname(),
                        "collected_at": datetime.now().isoformat(),
                        "record_number": ev.RecordNumber,
                    })

            self._win32evtlog.CloseEventLog(handle)
            if highest > self._last_record_app:
                self._last_record_app = highest

        except Exception as e:
            if "5" not in str(e) and "access" not in str(e).lower():
                log.error(f"Application log fallback error: {e}")

        return results

    def _seed_cursors(self):
        """Set cursors to current log end so only future events are captured."""
        try:
            for channel, attr in [
                ("Microsoft-Windows-Windows Defender/Operational", "_last_record"),
                ("Application", "_last_record_app"),
            ]:
                try:
                    h      = self._win32evtlog.OpenEventLog(None, channel)
                    total  = self._win32evtlog.GetNumberOfEventLogRecords(h)
                    oldest = self._win32evtlog.GetOldestEventLogRecord(h)
                    setattr(self, attr, oldest + total - 1)
                    self._win32evtlog.CloseEventLog(h)
                except Exception:
                    pass
        except Exception:
            pass

    def _push_alerts(self, events: list[dict]):
        """Push critical Defender events to AlertBus immediately."""
        try:
            from core.pipeline.alert_bus import get_alert_bus
            bus = get_alert_bus()

            for ev in events:
                eid  = ev.get("event_id", 0)
                meta = DEFENDER_EIDS.get(eid, {})
                if meta.get("level") not in ("CRITICAL", "HIGH"):
                    continue

                fields = _extract_defender_fields(ev.get("message") or "")
                threat = fields.get("threat_name") or ""
                path   = fields.get("path") or ""

                bus.push({
                    "type":        "defender_alert",
                    "severity":    meta["level"],
                    "category":    meta["category"],
                    "title":       meta["name"] + (f": {threat}" if threat else ""),
                    "description": (
                        f"Defender Event {eid}. "
                        + (f"Threat: {threat}. " if threat else "")
                        + (f"Path: {path}." if path else "")
                    ),
                    "event_id":    eid,
                    "source":      "Windows Defender",
                    "risk_score":  25 if meta["level"] == "CRITICAL" else 15,
                    "threat_name": threat,
                    "path":        path,
                })
        except Exception as e:
            log.warning(f"Defender alert push failed: {e}")

    def _store_events(self, events: list[dict]):
        """Write Defender events to security log table."""
        if not events:
            return
        try:
            from database.db import get_conn
            conn = get_conn()
            for ev in events:
                conn.execute("""
                    INSERT INTO logs_security
                        (timestamp, date, level, source, message, event_id, raw)
                    VALUES (?,?,?,?,?,?,?)
                """, (
                    ev["timestamp"], ev["date"], ev["level"],
                    ev["source"], ev["message"], ev["event_id"], ev["raw"],
                ))
            conn.commit()
            conn.close()
            self._events_found += len(events)
        except Exception as e:
            log.warning(f"Defender store failed: {e}")

    def _poll(self):
        if self._use_defender_channel:
            raw = self._read_defender_channel()
        else:
            raw = self._read_application_fallback()

        if not raw:
            return

        # Normalize each event to structured JSON
        normalized = [_normalize_defender_event(ev) for ev in raw]

        self._push_alerts(normalized)
        self._store_events(normalized)

        log.info(f"[Defender] {len(normalized)} events — EIDs: "
                 f"{list(set(e['event_id'] for e in normalized))}")

    def _loop(self):
        log.info("DefenderCollector started")
        if self._init_win32():
            self._seed_cursors()

        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"DefenderCollector poll error: {e}")
            self._stop.wait(POLL_INTERVAL)

        log.info(f"DefenderCollector stopped — {self._events_found} total events found")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="defender-collector"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[DefenderCollector] = None
_lock = threading.Lock()


def get_defender_collector() -> DefenderCollector:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = DefenderCollector()
    return _instance
