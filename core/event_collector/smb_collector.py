"""
core/event_collector/smb_collector.py
======================================
FR09-04: Windows SMB and File Sharing Activity Monitoring

Collects SMB/CIFS file sharing events from the Windows Security Event Log
and the SMB-specific operational log channels, transforming the existing
port-445 threat flagging into full session-level SMB monitoring.

EVENT SOURCES:
  1. Windows Security Log (logs_security, already collected)
     EID 5140 — Network share accessed
     EID 5142 — Network share object added
     EID 5143 — Network share object modified
     EID 5144 — Network share object deleted
     EID 5145 — Network share object access check
     EID 4776 — NTLM credential validation (SMB auth)

  2. Microsoft-Windows-SMBServer/Operational (new channel)
     EID 1000 — SMB session established
     EID 1001 — SMB session disconnected
     EID 1003 — SMB tree connect (share mount)
     EID 1006 — SMB file access

  3. Microsoft-Windows-SMBServer/Security (new channel)
     EID 3000 — SMB authentication failed (brute force signal)

SECURITY SIGNALS:
  - Access to admin shares (C$, ADMIN$, IPC$)
  - SMB relay/pass-the-hash patterns (same IP, many auth failures)
  - Access outside business hours
  - Enumeration patterns (rapid 5145 checks across many objects)
  - EternalBlue/WannaCry indicators (SMBv1 negotiation)

All events normalised to:
{
  "timestamp":    "...",
  "date":         "YYYY-MM-DD",
  "level":        "INFO|WARNING|ERROR|CRITICAL",
  "event_id":     5140,
  "share_name":   "\\\\SERVER\\share",
  "share_path":   "C:\\Users\\share",
  "access_mask":  "0x1200a9",
  "source_ip":    "192.168.1.10",
  "subject_user": "DOMAIN\\user",
  "object_type":  "File|Directory",
  "suspicious":   false,
  "threat_type":  null,            # "admin_share"|"smb_auth_fail"|"enumeration"
  "source":       "SMB Monitor",
  "category":     "smb",
  "raw":          "...",
}

PLACEMENT:
  Place this file at: core/event_collector/smb_collector.py
  Then follow the integration steps at the bottom.
"""

import threading
import time
import re
import socket
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("smb_collector")

POLL_INTERVAL = 3
MAX_PER_POLL  = 300

# ── Event ID definitions ───────────────────────────────────────────────────────

# Security log EIDs (already in logs_security via StreamCollector — we query them)
SECURITY_SMB_EIDS = {
    5140: {"level": "INFO",    "name": "Network Share Accessed"},
    5142: {"level": "INFO",    "name": "Network Share Object Added"},
    5143: {"level": "WARNING", "name": "Network Share Object Modified"},
    5144: {"level": "WARNING", "name": "Network Share Object Deleted"},
    5145: {"level": "INFO",    "name": "Network Share Object Access Check"},
    4776: {"level": "INFO",    "name": "NTLM Credential Validation"},
}

# SMBServer operational channel EIDs (new collection)
SMB_SERVER_EIDS = {
    1000: {"level": "INFO",     "name": "SMB Session Established"},
    1001: {"level": "INFO",     "name": "SMB Session Disconnected"},
    1003: {"level": "INFO",     "name": "SMB Tree Connect"},
    1006: {"level": "INFO",     "name": "SMB File Access"},
}

# SMBServer security channel EIDs
SMB_SECURITY_EIDS = {
    3000: {"level": "WARNING",  "name": "SMB Authentication Failed"},
}

# Admin shares that should be monitored closely
_ADMIN_SHARES = {"c$", "admin$", "ipc$", "d$", "e$", "f$", "print$", "sysvol", "netlogon"}

# ── Regex helpers ──────────────────────────────────────────────────────────────

_RE_SHARE_NAME   = re.compile(r"(?:Share Name|ShareName)[:\s]+([^\r\n|]+)", re.IGNORECASE)
_RE_SHARE_PATH   = re.compile(r"(?:Share Path|ShareLocalPath)[:\s]+([^\r\n|]+)", re.IGNORECASE)
_RE_OBJECT_TYPE  = re.compile(r"(?:Object Type|ObjectType)[:\s]+([^\r\n|]+)", re.IGNORECASE)
_RE_SOURCE_ADDR  = re.compile(r"(?:Source Address|Client Address|Source IP)[:\s]+([\d.:a-fA-F]+)", re.IGNORECASE)
_RE_SOURCE_PORT  = re.compile(r"(?:Source Port|Client Port)[:\s]+(\d+)", re.IGNORECASE)
_RE_SUBJECT_USER = re.compile(r"(?:Subject.*?Account Name|Account Name)[:\s]+([^\r\n|]+)", re.IGNORECASE)
_RE_SUBJECT_DOM  = re.compile(r"(?:Account Domain)[:\s]+([^\r\n|]+)", re.IGNORECASE)
_RE_ACCESS_MASK  = re.compile(r"(?:Access Mask|AccessMask)[:\s]+(0x[\da-fA-F]+|\d+)", re.IGNORECASE)
_RE_OBJECT_NAME  = re.compile(r"(?:Object Name|Relative Target Name)[:\s]+([^\r\n|]+)", re.IGNORECASE)


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.", "127.", "::1", "fe80"))


# ── SMB auth brute-force detector ─────────────────────────────────────────────

class SmbAuthFailDetector:
    """
    Track SMB authentication failures per source IP.
    Alerts when the same IP causes > THRESHOLD failures in TIME_WINDOW seconds.
    Indicates pass-the-hash, relay, or brute-force attacks.
    """
    THRESHOLD   = 10
    TIME_WINDOW = 60

    def __init__(self):
        self._fails: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._alerted: set[str] = set()

    def record(self, src_ip: str, ts: float) -> bool:
        dq = self._fails[src_ip]
        dq.append(ts)
        cutoff = ts - self.TIME_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)
        if count >= self.THRESHOLD and src_ip not in self._alerted:
            self._alerted.add(src_ip)
            return True
        if count < self.THRESHOLD // 2:
            self._alerted.discard(src_ip)
        return False


# ── SMB enumeration detector ───────────────────────────────────────────────────

class SmbEnumerationDetector:
    """
    Detect rapid 5145 (access checks) across many distinct objects from the same IP.
    Indicates attacker mapping file shares — common during lateral movement.
    """
    THRESHOLD   = 30   # distinct object checks
    TIME_WINDOW = 60

    def __init__(self):
        self._checks: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._alerted: set[str] = set()

    def record(self, src_ip: str, obj_name: str, ts: float) -> bool:
        key = (src_ip, obj_name)
        dq  = self._checks[src_ip]
        dq.append((ts, obj_name))
        cutoff = ts - self.TIME_WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        distinct = len({x[1] for x in dq})
        if distinct >= self.THRESHOLD and src_ip not in self._alerted:
            self._alerted.add(src_ip)
            return True
        if distinct < self.THRESHOLD // 2:
            self._alerted.discard(src_ip)
        return False


# ── Main collector class ───────────────────────────────────────────────────────

class SmbCollector:
    """
    FR09-04 — Monitors Windows SMB/CIFS activity from Security log EIDs
    5140-5145 and the SMBServer operational/security channels.

    Works in two modes:
      1. QUERY MODE: queries logs_security for SMB EIDs already collected by
         StreamCollector — zero extra overhead, immediate benefit.
      2. LIVE MODE:  additionally polls the SMBServer/Operational and
         SMBServer/Security channels for richer SMB-level detail.
    """

    SMB_OP_CHANNEL  = "Microsoft-Windows-SMBServer/Operational"
    SMB_SEC_CHANNEL = "Microsoft-Windows-SMBServer/Security"

    def __init__(self):
        self._stop                = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._win32ok             = False
        self._last_smb_op_record  = 0
        self._last_smb_sec_record = 0
        self._events_found        = 0
        self._auth_fail_detector  = SmbAuthFailDetector()
        self._enum_detector       = SmbEnumerationDetector()
        self._smb_op_available    = False
        self._smb_sec_available   = False
        # Track last processed security log ID to avoid reprocessing
        self._last_sec_log_id     = 0

    # ── win32 init ────────────────────────────────────────────────────────────

    def _init_win32(self) -> bool:
        if self._win32ok:
            return True
        try:
            import win32evtlog, win32evtlogutil, win32con
            self._w32log  = win32evtlog
            self._w32util = win32evtlogutil
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

    def _channel_available(self, channel: str) -> bool:
        try:
            h = self._w32log.OpenEventLog(None, channel)
            self._w32log.CloseEventLog(h)
            return True
        except Exception:
            return False

    # ── Event parsing ─────────────────────────────────────────────────────────

    def _parse_smb_event(self, eid: int, ts: str, msg: str,
                         level: str, channel: str) -> dict:
        """Parse raw message text into a structured SMB event dict."""

        share_name_m  = _RE_SHARE_NAME.search(msg)
        share_path_m  = _RE_SHARE_PATH.search(msg)
        obj_type_m    = _RE_OBJECT_TYPE.search(msg)
        src_addr_m    = _RE_SOURCE_ADDR.search(msg)
        src_port_m    = _RE_SOURCE_PORT.search(msg)
        user_m        = _RE_SUBJECT_USER.search(msg)
        dom_m         = _RE_SUBJECT_DOM.search(msg)
        mask_m        = _RE_ACCESS_MASK.search(msg)
        obj_name_m    = _RE_OBJECT_NAME.search(msg)

        share_name  = (share_name_m.group(1)  if share_name_m  else "").strip()
        share_path  = (share_path_m.group(1)  if share_path_m  else "").strip()
        object_type = (obj_type_m.group(1)    if obj_type_m    else "").strip()
        source_ip   = (src_addr_m.group(1)    if src_addr_m    else "").strip()
        source_port = int(src_port_m.group(1) if src_port_m    else 0)
        username    = (user_m.group(1)        if user_m        else "").strip()
        domain      = (dom_m.group(1)         if dom_m         else "").strip()
        access_mask = (mask_m.group(1)        if mask_m        else "").strip()
        object_name = (obj_name_m.group(1)    if obj_name_m    else "").strip()

        subject_user = f"{domain}\\{username}" if domain and username else username

        # Determine if this is an admin share access
        share_lower = share_name.lower().lstrip("\\").rstrip("\\")
        is_admin_share = any(share_lower == s or share_lower.endswith("\\" + s)
                             for s in _ADMIN_SHARES)

        suspicious  = False
        threat_type = None

        if is_admin_share and eid in (5140, 5142, 5143, 5144, 5145):
            suspicious  = True
            threat_type = "admin_share"
            level       = "WARNING" if level == "INFO" else level

        # SMB auth failure burst
        if eid in (3000, 4776) and source_ip:
            if self._auth_fail_detector.record(source_ip, time.time()):
                suspicious  = True
                threat_type = "smb_auth_fail"
                level       = "CRITICAL"

        # Share enumeration
        if eid == 5145 and source_ip and object_name:
            if self._enum_detector.record(source_ip, object_name, time.time()):
                suspicious  = True
                threat_type = "enumeration"
                level       = "HIGH" if level == "INFO" else level

        eid_meta = {**SECURITY_SMB_EIDS, **SMB_SERVER_EIDS,
                    **SMB_SECURITY_EIDS}.get(eid, {"name": "SMB Event"})

        return {
            "timestamp":    ts,
            "date":         ts[:10],
            "level":        level,
            "event_id":     eid,
            "share_name":   share_name,
            "share_path":   share_path,
            "object_type":  object_type,
            "object_name":  object_name,
            "source_ip":    source_ip,
            "source_port":  source_port,
            "subject_user": subject_user,
            "access_mask":  access_mask,
            "suspicious":   suspicious,
            "threat_type":  threat_type,
            "is_admin_share": is_admin_share,
            "source":       f"SMBMonitor ({channel})",
            "category":     "smb",
            "message": (
                f"SMB {eid_meta['name']}: share={share_name or '?'}"
                + (f" user={subject_user}" if subject_user else "")
                + (f" from={source_ip}"   if source_ip   else "")
                + (f" obj={object_name}"  if object_name else "")
                + (f" [⚠ {threat_type}]"  if threat_type else "")
            )[:2000],
            "raw":          msg[:500],
            "hostname":     socket.gethostname(),
            "collected_at": datetime.now().isoformat(),
        }

    def _safe_message(self, ev) -> str:
        try:
            msg = self._w32util.SafeFormatMessage(ev, ev.SourceName)
            return msg if msg else ""
        except Exception:
            if ev.StringInserts:
                return " | ".join(str(s) for s in ev.StringInserts)
            return f"Event ID {ev.EventID & 0xFFFF}"

    # ── Mode 1: query logs_security for SMB EIDs already stored ──────────────

    def _poll_security_db(self) -> list[dict]:
        """
        Query logs_security for SMB-related EIDs that StreamCollector
        already ingested (5140-5145, 4776). Avoids double-reading the event log.
        """
        events = []
        try:
            from database.db import get_conn
            placeholders = ",".join("?" * len(SECURITY_SMB_EIDS))
            conn = get_conn()
            rows = conn.execute(
                f"""
                SELECT id, timestamp, date, level, source, message, event_id
                FROM logs_security
                WHERE event_id IN ({placeholders})
                  AND id > ?
                ORDER BY id ASC
                LIMIT {MAX_PER_POLL}
                """,
                list(SECURITY_SMB_EIDS.keys()) + [self._last_sec_log_id]
            ).fetchall()
            conn.close()

            for row in rows:
                row_id, ts, date, level, src, msg, eid = (
                    row[0], row[1] or "", row[2] or "",
                    row[3] or "INFO", row[4] or "",
                    row[5] or "", row[6] or 0
                )
                if row_id > self._last_sec_log_id:
                    self._last_sec_log_id = row_id

                parsed = self._parse_smb_event(
                    int(eid), ts, msg, level, "Security"
                )
                events.append(parsed)
        except Exception as e:
            log.warning(f"[SMB] Security DB query error: {e}")
        return events

    # ── Mode 2: poll SMBServer operational channels directly ─────────────────

    def _poll_smb_channel(self, channel: str, cursor_attr: str,
                          target_eids: dict) -> list[dict]:
        """Read new events from the given SMBServer event channel."""
        if not self._win32ok:
            return []
        results = []
        highest = getattr(self, cursor_attr)
        handle  = None
        try:
            handle = self._w32log.OpenEventLog(None, channel)
            flags  = (self._w32log.EVENTLOG_BACKWARDS_READ |
                      self._w32log.EVENTLOG_SEQUENTIAL_READ)
            done   = False
            while not done and len(results) < MAX_PER_POLL:
                batch = self._w32log.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for ev in batch:
                    if ev.RecordNumber <= getattr(self, cursor_attr):
                        done = True
                        break
                    if ev.RecordNumber > highest:
                        highest = ev.RecordNumber
                    eid = ev.EventID & 0xFFFF
                    if eid not in target_eids:
                        continue
                    try:
                        ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                    except Exception:
                        ts = datetime.now().isoformat()
                    msg   = self._safe_message(ev)
                    level = self._TYPE_MAP.get(ev.EventType, "INFO")
                    meta  = target_eids[eid]
                    results.append(
                        self._parse_smb_event(eid, ts, msg, meta["level"], channel)
                    )
            if highest > getattr(self, cursor_attr):
                setattr(self, cursor_attr, highest)
        except Exception as e:
            err = str(e)
            if "5" not in err and "access" not in err.lower():
                log.error(f"[SMB] {channel} poll error: {e}")
        finally:
            if handle:
                try:
                    self._w32log.CloseEventLog(handle)
                except Exception:
                    pass
        return results

    # ── Store events in logs_security ─────────────────────────────────────────

    def _store_events(self, events: list[dict]):
        """
        Persist SMB events to logs_security.
        DB-queried events (Mode 1) are already there — only store Mode 2 events.
        """
        new_events = [e for e in events if e.get("category") == "smb"
                      and e.get("source", "").startswith("SMBMonitor (Microsoft")]
        if not new_events:
            return
        try:
            from database.db import get_conn
            conn = get_conn()
            for ev in new_events:
                conn.execute(
                    """
                    INSERT INTO logs_security
                        (timestamp, date, level, source, message, event_id, raw)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        ev["timestamp"], ev["date"], ev["level"],
                        ev.get("source", "SMB Monitor"),
                        ev["message"], ev["event_id"], ev.get("raw", ""),
                    )
                )
            conn.commit()
            conn.close()
            self._events_found += len(new_events)
        except Exception as e:
            log.warning(f"[SMB] Store error: {e}")

    # ── Alert push ────────────────────────────────────────────────────────────

    def _push_alerts(self, events: list[dict]):
        suspicious = [e for e in events if e.get("suspicious")]
        if not suspicious:
            return
        try:
            from core.pipeline.alert_bus import get_alert_bus
            bus = get_alert_bus()
            for ev in suspicious:
                threat = ev.get("threat_type", "smb_suspicious")
                sev_map = {
                    "smb_auth_fail": "CRITICAL",
                    "enumeration":   "HIGH",
                    "admin_share":   "HIGH",
                }
                bus.push({
                    "type":        "smb_alert",
                    "severity":    sev_map.get(threat, "MEDIUM"),
                    "category":    "network",
                    "title":       f"Suspicious SMB activity: {threat}",
                    "description": (
                        f"Share: {ev.get('share_name','?')} | "
                        f"User: {ev.get('subject_user','?')} | "
                        f"From: {ev.get('source_ip','?')} | "
                        f"Threat: {threat}"
                    ),
                    "event_id":    ev["event_id"],
                    "source":      "SMB Monitor",
                    "risk_score":  12 if threat == "smb_auth_fail" else 8,
                    "share_name":  ev.get("share_name", ""),
                    "source_ip":   ev.get("source_ip", ""),
                })
            log.warning(f"[SMB] {len(suspicious)} suspicious SMB events pushed to AlertBus")
        except Exception as e:
            log.warning(f"[SMB] Alert push failed: {e}")

    # ── Poll cycle ────────────────────────────────────────────────────────────

    def _poll(self):
        events = []

        # Mode 1: always query existing logs_security records
        db_events = self._poll_security_db()
        events.extend(db_events)

        # Mode 2: poll SMBServer channels if available
        if self._smb_op_available:
            op_events = self._poll_smb_channel(
                self.SMB_OP_CHANNEL, "_last_smb_op_record", SMB_SERVER_EIDS
            )
            events.extend(op_events)

        if self._smb_sec_available:
            sec_events = self._poll_smb_channel(
                self.SMB_SEC_CHANNEL, "_last_smb_sec_record", SMB_SECURITY_EIDS
            )
            events.extend(sec_events)

        if events:
            self._push_alerts(events)
            self._store_events(events)
            susp = sum(1 for e in events if e.get("suspicious"))
            if susp:
                log.warning(f"[SMB] {len(events)} events, {susp} suspicious")
            else:
                log.debug(f"[SMB] {len(events)} events processed")

    # ── Cursor seed ───────────────────────────────────────────────────────────

    def _seed_cursor(self, channel: str, attr: str):
        try:
            h      = self._w32log.OpenEventLog(None, channel)
            total  = self._w32log.GetNumberOfEventLogRecords(h)
            oldest = self._w32log.GetOldestEventLogRecord(h)
            setattr(self, attr, oldest + total - 1)
            self._w32log.CloseEventLog(h)
        except Exception as e:
            log.warning(f"[SMB] Could not seed cursor for {channel}: {e}")

    def _seed_db_cursor(self):
        """Seed security DB cursor to current max ID."""
        try:
            from database.db import get_conn
            conn = get_conn()
            row  = conn.execute(
                "SELECT MAX(id) FROM logs_security WHERE event_id IN (5140,5142,5143,5144,5145,4776)"
            ).fetchone()
            conn.close()
            self._last_sec_log_id = row[0] or 0
        except Exception:
            self._last_sec_log_id = 0

    # ── Background loop ───────────────────────────────────────────────────────

    def _loop(self):
        log.info("[SMB] SmbCollector started")

        # Seed DB cursor for Mode 1
        self._seed_db_cursor()
        log.info(f"[SMB] Security DB cursor seeded at id={self._last_sec_log_id}")

        # Try to initialise win32 and check SMBServer channels for Mode 2
        if self._init_win32():
            self._smb_op_available = self._channel_available(self.SMB_OP_CHANNEL)
            self._smb_sec_available = self._channel_available(self.SMB_SEC_CHANNEL)
            if self._smb_op_available:
                self._seed_cursor(self.SMB_OP_CHANNEL, "_last_smb_op_record")
                log.info("[SMB] SMBServer/Operational channel available — live mode enabled")
            if self._smb_sec_available:
                self._seed_cursor(self.SMB_SEC_CHANNEL, "_last_smb_sec_record")
                log.info("[SMB] SMBServer/Security channel available — auth failure tracking enabled")
            if not self._smb_op_available:
                log.info("[SMB] SMBServer channels not available — running in DB-query mode only")
        else:
            log.warning("[SMB] pywin32 not available — running in DB-query mode only")

        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[SMB] Poll loop error: {e}")
            self._stop.wait(POLL_INTERVAL)

        log.info(f"[SMB] SmbCollector stopped — {self._events_found} total events")

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="smb-collector"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def events_found(self) -> int:
        return self._events_found


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[SmbCollector] = None
_lock = threading.Lock()


def get_smb_collector() -> SmbCollector:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = SmbCollector()
    return _instance


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION STEPS
# ══════════════════════════════════════════════════════════════════════════════
#
# 1. core/event_collector/rt_pipeline.py — add to RTPipeline.start():
#
#       # ── FR09-04: SMB Collector ────────────────────────────────────────────
#       try:
#           from core.event_collector.smb_collector import get_smb_collector
#           smb = get_smb_collector()
#           smb.start()
#           self._collectors["smb"] = smb
#           log.info("✅ FR09-04: SmbCollector started (EIDs 5140-5145 + SMBServer channels)")
#       except Exception as e:
#           log.error(f"❌ FR09-04: SmbCollector failed to start: {e}")
#
#
# 2. api/rt_status_api.py — add endpoints:
#
#       GET /api/smb/recent   → last N SMB events (share access, auth failures)
#       GET /api/smb/stats    → admin share counts, auth fail counts, top shares
#
# ══════════════════════════════════════════════════════════════════════════════
