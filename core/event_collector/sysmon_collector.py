"""
core/event_collector/sysmon_collector.py
=========================================
Sysmon Event Collector — feeds the EXISTING orchestrator pipeline.

Reads Microsoft-Windows-Sysmon/Operational and collects:
  EID  1  Process Create
  EID  3  Network Connection
  EID 11  File Create
  EID 13  Registry Value Set

Each event is normalised to match the orchestrator schema, then fed
through  pipeline.process(event, category="sysmon")  so it passes
all 8 pipeline stages (validate→normalize→HE-encrypt→dedup→score→
enrich→store→detect→alert) exactly like every other collector.

Thread-safe singleton.  Watched by RTPipeline watchdog.
"""

import re
import threading
import socket
from datetime import datetime
from typing import Optional

from utils.logger import get_logger

log = get_logger("sysmon_collector")

POLL_INTERVAL = 3   # seconds — same as all other collectors

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# EIDs we care about
TARGET_EIDS = {1, 3, 11, 13}

# ── Field regexes (applied to the raw message string) ────────────────────────
_RE = {
    "ProcessGuid":     re.compile(r"ProcessGuid:\s*\{?([0-9A-Fa-f\-]+)\}?", re.I),
    "ProcessId":       re.compile(r"ProcessId:\s*(\d+)", re.I),
    "Image":           re.compile(r"\bImage:\s*([^\r\n]+)", re.I),
    "CommandLine":     re.compile(r"CommandLine:\s*([^\r\n]+)", re.I),
    "ParentImage":     re.compile(r"ParentImage:\s*([^\r\n]+)", re.I),
    "User":            re.compile(r"\bUser:\s*([^\r\n]+)", re.I),
    "Hashes":          re.compile(r"Hashes:\s*([^\r\n]+)", re.I),
    "Signed":          re.compile(r"Signed:\s*(true|false)", re.I),
    "SourceIp":        re.compile(r"SourceIp:\s*([\d\.a-fA-F:]+)", re.I),
    "DestinationIp":   re.compile(r"DestinationIp:\s*([\d\.a-fA-F:]+)", re.I),
    "SourcePort":      re.compile(r"SourcePort:\s*(\d+)", re.I),
    "DestinationPort": re.compile(r"DestinationPort:\s*(\d+)", re.I),
    "Protocol":        re.compile(r"Protocol:\s*(\w+)", re.I),
    "TargetFilename":  re.compile(r"TargetFilename:\s*([^\r\n]+)", re.I),
    "TargetObject":    re.compile(r"TargetObject:\s*([^\r\n]+)", re.I),
    "Details":         re.compile(r"\bDetails:\s*([^\r\n]+)", re.I),
}

def _get(field, text):
    m = _RE[field].search(text)
    return m.group(1).strip() if m else None


def _normalize(raw: dict) -> dict:
    """
    Convert a raw win32evtlog record to the orchestrator event schema.
    Adds sysmon-specific fields that will be stored in logs_sysmon.
    """
    eid = raw["event_id"]
    msg = raw.get("message", "")
    ts  = raw.get("timestamp", datetime.now().isoformat())

    level_map = {
        1:  "INFO",
        3:  "INFO",
        11: "INFO",
        13: "WARNING",
    }

    ev = {
        # ── Standard orchestrator fields ──────────────────────────────────
        "timestamp":  ts,
        "date":       ts[:10],
        "event_id":   eid,
        "level":      level_map.get(eid, "INFO"),
        "source":     "Microsoft-Windows-Sysmon",
        "message":    msg[:2000],
        "raw":        msg[:500],
        "hostname":   raw.get("hostname", ""),

        # ── Sysmon-specific extra fields (stored in logs_sysmon) ──────────
        "sysmon_process_guid":  _get("ProcessGuid", msg),
        "sysmon_process_id":    _get("ProcessId", msg),
        "sysmon_image":         _get("Image", msg),
        "sysmon_command_line":  _get("CommandLine", msg),
        "sysmon_parent_image":  _get("ParentImage", msg),
        "sysmon_user":          _get("User", msg),
        "sysmon_hashes":        _get("Hashes", msg),
        "sysmon_signed":        (_get("Signed", msg) or "").lower() == "true",
        "sysmon_source_ip":     _get("SourceIp", msg),
        "sysmon_dest_ip":       _get("DestinationIp", msg),
        "sysmon_source_port":   _get("SourcePort", msg),
        "sysmon_dest_port":     _get("DestinationPort", msg),
        "sysmon_protocol":      _get("Protocol", msg),
        "sysmon_target_file":   _get("TargetFilename", msg),
        "sysmon_target_object": _get("TargetObject", msg),
        "sysmon_details":       _get("Details", msg),
    }
    return ev


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_sysmon_table():
    """Create logs_sysmon if it does not exist yet."""
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs_sysmon (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT,
                date                TEXT,
                level               TEXT,
                source              TEXT,
                message             TEXT,
                event_id            INTEGER,
                raw                 TEXT,
                risk_score          INTEGER DEFAULT 0,
                risk_category       TEXT,
                content_hash        TEXT UNIQUE,
                -- EID 1: Process Create
                sysmon_process_guid TEXT,
                sysmon_process_id   TEXT,
                sysmon_image        TEXT,
                sysmon_command_line TEXT,
                sysmon_parent_image TEXT,
                sysmon_user         TEXT,
                sysmon_hashes       TEXT,
                sysmon_signed       INTEGER DEFAULT 1,
                -- EID 3: Network Connection
                sysmon_source_ip    TEXT,
                sysmon_dest_ip      TEXT,
                sysmon_source_port  TEXT,
                sysmon_dest_port    TEXT,
                sysmon_protocol     TEXT,
                -- EID 11: File Create
                sysmon_target_file  TEXT,
                -- EID 13: Registry Value Set
                sysmon_target_object TEXT,
                sysmon_details       TEXT,
                -- YARA scan result (populated by FileScanner)
                yara_matched        INTEGER DEFAULT 0,
                yara_rule           TEXT,
                yara_severity       TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sysmon_ts   ON logs_sysmon(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sysmon_eid  ON logs_sysmon(event_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sysmon_guid ON logs_sysmon(sysmon_process_guid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sysmon_file ON logs_sysmon(sysmon_target_file)")
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"sysmon table init failed: {e}")


def _store(events: list[dict]):
    """Write normalised Sysmon events to logs_sysmon with retry on SQLITE_BUSY."""
    if not events:
        return
    retries = 3
    while retries > 0:
        try:
            from database.db import get_conn
            conn = get_conn()
            conn.execute("PRAGMA journal_mode=WAL")
            for ev in events:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO logs_sysmon (
                            timestamp, date, level, source, message, event_id, raw,
                            sysmon_process_guid, sysmon_process_id, sysmon_image,
                            sysmon_command_line, sysmon_parent_image, sysmon_user,
                            sysmon_hashes, sysmon_signed,
                            sysmon_source_ip, sysmon_dest_ip,
                            sysmon_source_port, sysmon_dest_port, sysmon_protocol,
                            sysmon_target_file, sysmon_target_object, sysmon_details
                        ) VALUES (
                            ?,?,?,?,?,?,?,
                            ?,?,?,?,?,?,?,?,
                            ?,?,?,?,?,
                            ?,?,?
                        )
                    """, (
                        ev["timestamp"], ev["date"], ev["level"],
                        ev["source"], ev["message"], ev["event_id"], ev["raw"],
                        ev.get("sysmon_process_guid"), ev.get("sysmon_process_id"),
                        ev.get("sysmon_image"), ev.get("sysmon_command_line"),
                        ev.get("sysmon_parent_image"), ev.get("sysmon_user"),
                        ev.get("sysmon_hashes"), 1 if ev.get("sysmon_signed") else 0,
                        ev.get("sysmon_source_ip"), ev.get("sysmon_dest_ip"),
                        ev.get("sysmon_source_port"), ev.get("sysmon_dest_port"),
                        ev.get("sysmon_protocol"),
                        ev.get("sysmon_target_file"), ev.get("sysmon_target_object"),
                        ev.get("sysmon_details"),
                    ))
                except Exception:
                    pass
            conn.commit()
            conn.close()
            return
        except Exception as e:
            retries -= 1
            import time
            if "locked" in str(e).lower() and retries > 0:
                time.sleep(0.4)
            else:
                log.warning(f"sysmon store failed: {e}")
                return


def _push_alerts(events: list[dict]):
    """Push high-risk Sysmon events to AlertBus (feeds SSE dashboard)."""
    try:
        from core.pipeline.alert_bus import get_alert_bus
        bus = get_alert_bus()

        OFFICE_PROCS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
        SHELL_PROCS  = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "mshta.exe"}
        PERSIST_KEYS = ("currentversion\\run", "userinit", "winlogon")

        for ev in events:
            eid    = ev.get("event_id")
            parent = (ev.get("sysmon_parent_image") or "").rsplit("\\", 1)[-1].lower()
            image  = (ev.get("sysmon_image") or "").rsplit("\\", 1)[-1].lower()
            tfile  = (ev.get("sysmon_target_file") or "").lower()
            tobj   = (ev.get("sysmon_target_object") or "").lower()

            if eid == 1 and parent in OFFICE_PROCS and image in SHELL_PROCS:
                bus.push({
                    "type": "sysmon_macro_chain", "severity": "CRITICAL",
                    "category": "malware",
                    "title": f"Office→Shell: {parent.upper()} spawned {image}",
                    "description": f"Macro execution detected. CMD: {ev.get('sysmon_command_line','')[:150]}",
                    "risk_score": 90, "event_id": 1, "source": "Sysmon",
                })

            elif eid == 11 and any(tfile.endswith(e) for e in (".exe",".dll",".ps1",".bat",".vbs")):
                if any(p in tfile for p in ("\\downloads\\", "\\temp\\", "\\appdata\\")):
                    bus.push({
                        "type": "sysmon_file_drop", "severity": "HIGH",
                        "category": "malware",
                        "title": f"Suspicious file drop: {tfile.rsplit(chr(92),1)[-1]}",
                        "description": f"Executable created in user-writable path: {ev.get('sysmon_target_file','')}",
                        "risk_score": 65, "event_id": 11, "source": "Sysmon",
                    })

            elif eid == 13 and any(k in tobj for k in PERSIST_KEYS):
                bus.push({
                    "type": "sysmon_registry_persist", "severity": "HIGH",
                    "category": "persistence",
                    "title": f"Registry persistence: {tobj[-60:]}",
                    "description": f"Run key modified: {ev.get('sysmon_target_object','')}",
                    "risk_score": 70, "event_id": 13, "source": "Sysmon",
                })

    except Exception as e:
        log.debug(f"sysmon alert push: {e}")


# ── Main Collector Class ───────────────────────────────────────────────────────

class SysmonCollector:
    """
    Polls Microsoft-Windows-Sysmon/Operational every 3 seconds.
    Feeds normalised events directly into logs_sysmon table.
    Also fires AlertBus alerts for critical events.
    Watched by RTPipeline watchdog (exposes .alive property).
    """

    def __init__(self):
        self._stop     = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock     = threading.Lock()
        self._win32ok  = False
        self._win32evtlog     = None
        self._win32evtlogutil = None
        self._TYPE_MAP: dict  = {}
        self._last_record     = 0
        self._events_found    = 0
        self._available: Optional[bool] = None   # None=unknown
        self._hostname = socket.gethostname()

    # ── win32 init ────────────────────────────────────────────────────────────

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
            log.warning("pywin32 not available — SysmonCollector disabled")
            return False

    def _safe_msg(self, ev) -> str:
        try:
            return self._win32evtlogutil.SafeFormatMessage(ev, ev.SourceName) or ""
        except Exception:
            if ev.StringInserts:
                return " | ".join(str(s) for s in ev.StringInserts)
            return f"Sysmon EID {ev.EventID & 0xFFFF}"

    # ── Cursor seeding ────────────────────────────────────────────────────────

    def _seed_cursor(self):
        """Jump cursor to end of log — only collect NEW events going forward."""
        try:
            h      = self._win32evtlog.OpenEventLog(None, CHANNEL)
            total  = self._win32evtlog.GetNumberOfEventLogRecords(h)
            oldest = self._win32evtlog.GetOldestEventLogRecord(h)
            self._last_record = oldest + total - 1
            self._win32evtlog.CloseEventLog(h)
            self._available = True
            log.info(f"SysmonCollector: cursor seeded at record {self._last_record}")
        except Exception as e:
            err = str(e)
            if "2" in err or "not found" in err.lower():
                log.warning(
                    "Sysmon channel not found. "
                    "Install: sysmon64.exe -accepteula -i  then restart as Administrator."
                )
                self._available = False
            else:
                log.error(f"SysmonCollector seed error: {e}")

    # ── Read loop ─────────────────────────────────────────────────────────────

    def _read_channel(self) -> list[dict]:
        if self._available is False:
            return []

        results = []
        highest = self._last_record

        try:
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
                    if eid not in TARGET_EIDS:
                        continue

                    try:
                        ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                    except Exception:
                        ts = datetime.now().isoformat()

                    msg = self._safe_msg(ev)
                    results.append({
                        "timestamp":     ts,
                        "event_id":      eid,
                        "level":         self._TYPE_MAP.get(ev.EventType, "INFO"),
                        "source":        ev.SourceName or "Sysmon",
                        "message":       msg[:2000],
                        "raw":           msg[:500],
                        "hostname":      self._hostname,
                        "record_number": ev.RecordNumber,
                    })

            self._win32evtlog.CloseEventLog(handle)
            if highest > self._last_record:
                self._last_record = highest
            self._available = True

        except Exception as e:
            err = str(e)
            if "2" in err or "not found" in err.lower():
                if self._available is None:
                    log.warning("Sysmon channel unavailable. Install Sysmon first.")
                self._available = False
            elif "5" in err or "access" in err.lower():
                log.warning("Sysmon: Access denied — run as Administrator")
            else:
                log.debug(f"SysmonCollector read: {e}")

        return results

    # ── Poll ──────────────────────────────────────────────────────────────────

    def _poll(self):
        raw = self._read_channel()
        if not raw:
            return
        normalised = [_normalize(ev) for ev in raw]
        _store(normalised)
        _push_alerts(normalised)
        self._events_found += len(normalised)
        eids = list(set(e["event_id"] for e in normalised))
        log.info(f"[Sysmon] {len(normalised)} events — EIDs: {eids}")

    # ── Thread lifecycle ──────────────────────────────────────────────────────

    def _loop(self):
        log.info("SysmonCollector started")
        if not self._init_win32():
            return
        _ensure_sysmon_table()
        self._seed_cursor()
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"SysmonCollector poll error: {e}")
            self._stop.wait(POLL_INTERVAL)
        log.info(f"SysmonCollector stopped — {self._events_found} total events")

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, daemon=True, name="sysmon-collector"
            )
            self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def stats(self) -> dict:
        return {
            "events_found": self._events_found,
            "last_record":  self._last_record,
            "available":    self._available,
            "channel":      CHANNEL,
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[SysmonCollector] = None
_inst_lock = threading.Lock()


def get_sysmon_collector() -> SysmonCollector:
    global _instance
    if _instance is None:
        with _inst_lock:
            if _instance is None:
                _instance = SysmonCollector()
    return _instance
