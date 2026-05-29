"""
core/event_collector/psremoting_collector.py
=============================================
FR09-06: Windows PowerShell Remoting Activity Monitoring

Collects WinRM (Windows Remote Management) and PowerShell remoting session
events from operational log channels, tracking who is connecting remotely,
from which machines, and what commands are being run via PowerShell remoting.

EVENT SOURCES:
  1. Microsoft-Windows-WinRM/Operational
     EID 6    — WSMan session init (incoming connection request)
     EID 8    — WSMan session created
     EID 15   — WSMan session deleted
     EID 16   — WSMan plugin loaded
     EID 91   — Session created
     EID 168  — Authenticating user
     EID 169  — User authenticated
     EID 193  — Authentication failure

  2. Microsoft-Windows-PowerShell/Operational
     EID 4103 — Module pipeline execution
     EID 4104 — Script block logging (remote scripts)
     EID 53504 — PS remoting session started
     EID 40961 — PS console start (may indicate remote init)
     EID 40962 — PS console ready

  3. Security log (already in DB via StreamCollector)
     EID 4624 logon type 3 from WinRM source (network logon for PS remoting)
     EID 4634 — logoff from WinRM session

SECURITY SIGNALS:
  - WinRM connections from external (non-private) IP addresses
  - Authentication failures on WinRM port (brute-force / scanning)
  - Encoded or obfuscated PowerShell script blocks (base64 in 4104)
  - PS remoting outside business hours
  - Connection from unexpected source hosts
  - High-frequency remoting sessions (automation / worm spreading)

All events normalised to:
{
  "timestamp":      "...",
  "date":           "YYYY-MM-DD",
  "level":          "INFO|WARNING|ERROR|CRITICAL",
  "event_id":       169,
  "session_id":     "uuid-...",
  "source_ip":      "192.168.1.10",
  "source_host":    "WORKSTATION-01",
  "username":       "DOMAIN\\user",
  "auth_mechanism": "Kerberos|NTLM|Basic",
  "connection_url": "http://server:5985/wsman",
  "script_block":   "...",         # for EID 4104 only
  "obfuscated":     false,         # base64/encoded script detected
  "suspicious":     false,
  "threat_type":    null,          # "external_ip"|"obfuscated_script"|"auth_fail_burst"|"off_hours"
  "source":         "PSRemoting Monitor",
  "category":       "ps_remoting",
  "raw":            "...",
}

PLACEMENT:
  Place this file at: core/event_collector/psremoting_collector.py
  Then follow the integration steps at the bottom.
"""

import threading
import time
import re
import base64
import socket
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("psremoting_collector")

POLL_INTERVAL = 3
MAX_PER_POLL  = 300

# ── Event ID definitions ───────────────────────────────────────────────────────

WINRM_EIDS = {
    6:   {"level": "INFO",     "name": "WinRM Session Init"},
    8:   {"level": "INFO",     "name": "WinRM Session Created"},
    15:  {"level": "INFO",     "name": "WinRM Session Deleted"},
    16:  {"level": "INFO",     "name": "WinRM Plugin Loaded"},
    91:  {"level": "INFO",     "name": "WinRM Session Established"},
    168: {"level": "INFO",     "name": "WinRM Authenticating User"},
    169: {"level": "INFO",     "name": "WinRM User Authenticated"},
    193: {"level": "WARNING",  "name": "WinRM Authentication Failed"},
}

PS_OPERATIONAL_EIDS = {
    4103:  {"level": "INFO",    "name": "PS Module Execution"},
    4104:  {"level": "WARNING", "name": "PS Script Block"},
    53504: {"level": "INFO",    "name": "PS Remoting Session Start"},
    40961: {"level": "INFO",    "name": "PS Console Start"},
    40962: {"level": "INFO",    "name": "PS Console Ready"},
}

# Security log EIDs already in DB — queried, not re-collected
SECURITY_WINRM_EIDS = {4624, 4634}

# ── Regex helpers ──────────────────────────────────────────────────────────────

_RE_SOURCE_IP      = re.compile(r"(?:ClientIP|Source Address|sourceaddress|connection from)[:\s]+([\d.:a-fA-F]+)", re.IGNORECASE)
_RE_SOURCE_HOST    = re.compile(r"(?:ClientHostname|Source Hostname|WorkstationName|sourcecomputer)[:\s]+([^\s\r\n|,]+)", re.IGNORECASE)
_RE_USERNAME       = re.compile(r"(?:Username|Account Name|userid|user)[:\s]+([^\s\r\n|,\\]+)", re.IGNORECASE)
_RE_AUTH_MECH      = re.compile(r"(?:Authentication Mechanism|AuthenticationMechanism|mechanism)[:\s]+([^\s\r\n|,]+)", re.IGNORECASE)
_RE_SESSION_ID     = re.compile(r"(?:SessionID|Session ID|ActivityId)[:\s]+([\w\-{}]+)", re.IGNORECASE)
_RE_CONN_URL       = re.compile(r"(?:ConnectionURL|Url|url)[:\s]+(https?://[^\s\r\n|,]+)", re.IGNORECASE)
_RE_SCRIPT_BLOCK   = re.compile(r"(?:ScriptBlockText|Script Block Text)[:\s]*\r?\n?([\s\S]{1,4000})", re.IGNORECASE)
_RE_LOGON_TYPE     = re.compile(r"(?:Logon Type)[:\s]+(\d+)", re.IGNORECASE)
_RE_IP_IN_MSG      = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_RE_B64_CHUNK      = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_RE_ENC_FLAG       = re.compile(r"(?:-en(?:c(?:oded)?)?|-ec)\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)

# Hours considered "business hours" — connections outside raise suspicion
_BUSINESS_HOURS_START = 7   # 07:00
_BUSINESS_HOURS_END   = 20  # 20:00


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.", "127.", "::1", "fe80", "0.0.0.0"))


def _is_off_hours(ts: str) -> bool:
    """Return True if timestamp hour is outside business hours."""
    try:
        hour = int(ts[11:13])
        return hour < _BUSINESS_HOURS_START or hour >= _BUSINESS_HOURS_END
    except Exception:
        return False


def _detect_obfuscation(script: str) -> bool:
    """
    Detect base64-encoded commands or -EncodedCommand flags in PS scripts.
    These are used by attackers for fileless attacks and AMSI bypass.
    """
    if not script:
        return False
    if _RE_ENC_FLAG.search(script):
        return True
    # Look for long base64 chunks — a sign of encoded payload
    chunks = _RE_B64_CHUNK.findall(script)
    for chunk in chunks:
        try:
            decoded = base64.b64decode(chunk + "==").decode("utf-16-le", errors="ignore")
            # If decoded text looks like PowerShell keywords, flag it
            if any(kw in decoded.lower() for kw in
                   ("invoke-", "downloadstring", "bypass", "iex ", "net.webclient",
                    "shellcode", "amsi", "mimikatz", "invoke-expression")):
                return True
        except Exception:
            pass
    return False


# ── WinRM auth-failure detector ───────────────────────────────────────────────

class WinRmAuthFailDetector:
    """Flag brute-force/scanning against WinRM port 5985/5986."""
    THRESHOLD   = 8
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


# ── Main collector ─────────────────────────────────────────────────────────────

class PsRemotingCollector:
    """
    FR09-06 — Monitors Windows PowerShell remoting and WinRM sessions.

    Mode 1 (DB query): detects WinRM-related network logons (EID 4624 type 3)
                       already stored by StreamCollector.
    Mode 2 (live):     polls WinRM/Operational and PowerShell/Operational channels
                       for richer session-level and script-level detail.
    """

    WINRM_CHANNEL  = "Microsoft-Windows-WinRM/Operational"
    PS_OP_CHANNEL  = "Microsoft-Windows-PowerShell/Operational"

    def __init__(self):
        self._stop                  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._win32ok               = False
        self._last_winrm_record     = 0
        self._last_ps_record        = 0
        self._last_sec_log_id       = 0
        self._events_found          = 0
        self._auth_fail_detector    = WinRmAuthFailDetector()
        self._winrm_available       = False
        self._ps_op_available       = False

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

    # ── Message parsing ────────────────────────────────────────────────────────

    def _safe_message(self, ev) -> str:
        try:
            msg = self._w32util.SafeFormatMessage(ev, ev.SourceName)
            return msg if msg else ""
        except Exception:
            if ev.StringInserts:
                return " | ".join(str(s) for s in ev.StringInserts)
            return f"Event ID {ev.EventID & 0xFFFF}"

    def _parse_ps_remoting_event(self, eid: int, ts: str, msg: str,
                                  channel: str) -> dict:
        """Build a structured PSRemoting event from raw message text."""

        src_ip_m   = _RE_SOURCE_IP.search(msg)
        src_host_m = _RE_SOURCE_HOST.search(msg)
        user_m     = _RE_USERNAME.search(msg)
        auth_m     = _RE_AUTH_MECH.search(msg)
        sess_m     = _RE_SESSION_ID.search(msg)
        url_m      = _RE_CONN_URL.search(msg)
        sb_m       = _RE_SCRIPT_BLOCK.search(msg)
        lt_m       = _RE_LOGON_TYPE.search(msg)

        source_ip    = (src_ip_m.group(1)  if src_ip_m  else "").strip()
        source_host  = (src_host_m.group(1) if src_host_m else "").strip()
        username     = (user_m.group(1)    if user_m    else "").strip()
        auth_mech    = (auth_m.group(1)    if auth_m    else "").strip()
        session_id   = (sess_m.group(1)    if sess_m    else "").strip()
        conn_url     = (url_m.group(1)     if url_m     else "").strip()
        script_block = (sb_m.group(1)      if sb_m      else "").strip()
        logon_type   = int(lt_m.group(1)   if lt_m      else 0)

        # Fallback: scrape any IP from message
        if not source_ip:
            ips = _RE_IP_IN_MSG.findall(msg)
            source_ip = next((ip for ip in ips if not ip.startswith("127.")), "")

        obfuscated  = _detect_obfuscation(script_block or msg)
        is_external = bool(source_ip and not _is_private_ip(source_ip))
        off_hours   = _is_off_hours(ts)

        suspicious  = False
        threat_type = None
        level       = "INFO"

        # External IP connecting via WinRM
        if is_external and eid in WINRM_EIDS:
            suspicious  = True
            threat_type = "external_ip"
            level       = "WARNING"

        # Auth failure burst
        if eid == 193 and source_ip:  # WinRM auth failed
            if self._auth_fail_detector.record(source_ip, time.time()):
                suspicious  = True
                threat_type = "auth_fail_burst"
                level       = "CRITICAL"
        elif eid == 193:
            level = "WARNING"

        # Obfuscated PS script
        if obfuscated:
            suspicious  = True
            threat_type = threat_type or "obfuscated_script"
            level       = "CRITICAL" if threat_type == "obfuscated_script" else level

        # Off-hours WinRM session from external
        if off_hours and is_external and eid in (8, 91, 169):
            suspicious  = True
            threat_type = threat_type or "off_hours_external"
            level       = "WARNING" if level == "INFO" else level

        all_eids = {**WINRM_EIDS, **PS_OPERATIONAL_EIDS}
        eid_name = all_eids.get(eid, {}).get("name", "PS Remoting Event")
        if level == "INFO" and eid in WINRM_EIDS:
            level = WINRM_EIDS[eid]["level"]
        elif level == "INFO" and eid in PS_OPERATIONAL_EIDS:
            level = PS_OPERATIONAL_EIDS[eid]["level"]

        return {
            "timestamp":      ts,
            "date":           ts[:10],
            "level":          level,
            "event_id":       eid,
            "session_id":     session_id,
            "source_ip":      source_ip,
            "source_host":    source_host,
            "username":       username,
            "auth_mechanism": auth_mech,
            "connection_url": conn_url,
            "logon_type":     logon_type,
            "script_block":   script_block[:1000] if script_block else "",
            "obfuscated":     obfuscated,
            "is_external":    is_external,
            "off_hours":      off_hours,
            "suspicious":     suspicious,
            "threat_type":    threat_type,
            "source":         f"PSRemoting ({channel})",
            "category":       "ps_remoting",
            "message": (
                f"PS Remoting {eid_name}"
                + (f": user={username}"    if username    else "")
                + (f" from={source_ip}"   if source_ip   else "")
                + (f" host={source_host}" if source_host else "")
                + (f" auth={auth_mech}"   if auth_mech   else "")
                + (" [off-hours]"         if off_hours   else "")
                + (f" [⚠ {threat_type}]"  if threat_type else "")
            )[:2000],
            "raw":            msg[:500],
            "hostname":       socket.gethostname(),
            "collected_at":   datetime.now().isoformat(),
        }

    # ── Mode 1: query logs_security for WinRM network logons ─────────────────

    def _poll_security_db(self) -> list[dict]:
        """
        Query logs_security for EID 4624 logon type 3 entries that may indicate
        WinRM/PS-remoting network logons. These are already stored by StreamCollector.
        """
        events = []
        try:
            from database.db import get_conn
            conn = get_conn()
            # logon type 3 = network logon (used by PS remoting via WinRM)
            rows = conn.execute(
                """
                SELECT id, timestamp, date, level, source, message, event_id
                FROM logs_security
                WHERE event_id IN (4624, 4634)
                  AND (message LIKE '%Logon Type:%3%'
                       OR message LIKE '%5985%'
                       OR message LIKE '%5986%'
                       OR message LIKE '%wsman%'
                       OR message LIKE '%winrm%'
                       OR message LIKE '%PowerShell%')
                  AND id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (self._last_sec_log_id, MAX_PER_POLL)
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
                parsed = self._parse_ps_remoting_event(
                    int(eid), ts, msg, "Security"
                )
                events.append(parsed)
        except Exception as e:
            log.warning(f"[PSRemoting] Security DB query error: {e}")
        return events

    # ── Mode 2: poll WinRM/Operational and PS/Operational live ───────────────

    def _poll_channel(self, channel: str, cursor_attr: str,
                      target_eids: dict) -> list[dict]:
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
                    msg = self._safe_message(ev)
                    results.append(
                        self._parse_ps_remoting_event(eid, ts, msg, channel)
                    )
            if highest > getattr(self, cursor_attr):
                setattr(self, cursor_attr, highest)
        except Exception as e:
            err = str(e)
            if "5" not in err and "access" not in err.lower():
                log.error(f"[PSRemoting] {channel} poll error: {e}")
        finally:
            if handle:
                try:
                    self._w32log.CloseEventLog(handle)
                except Exception:
                    pass
        return results

    # ── Store events ──────────────────────────────────────────────────────────

    def _store_events(self, events: list[dict]):
        """Store PS remoting events into logs_security."""
        # Only store events NOT already originating from logs_security DB query
        new_events = [e for e in events
                      if "Security" not in e.get("source", "")]
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
                        ev.get("source", "PSRemoting Monitor"),
                        ev["message"], ev["event_id"], ev.get("raw", ""),
                    )
                )
            conn.commit()
            conn.close()
            self._events_found += len(new_events)
        except Exception as e:
            log.warning(f"[PSRemoting] Store error: {e}")

    # ── Alert push ────────────────────────────────────────────────────────────

    def _push_alerts(self, events: list[dict]):
        suspicious = [e for e in events if e.get("suspicious")]
        if not suspicious:
            return
        try:
            from core.pipeline.alert_bus import get_alert_bus
            bus = get_alert_bus()
            sev_map = {
                "obfuscated_script":    "CRITICAL",
                "auth_fail_burst":      "CRITICAL",
                "external_ip":          "HIGH",
                "off_hours_external":   "HIGH",
            }
            for ev in suspicious:
                threat = ev.get("threat_type", "ps_remoting_suspicious")
                bus.push({
                    "type":        "ps_remoting_alert",
                    "severity":    sev_map.get(threat, "HIGH"),
                    "category":    "network",
                    "title":       f"Suspicious PS Remoting: {threat}",
                    "description": (
                        f"User: {ev.get('username','?')} | "
                        f"From: {ev.get('source_ip','?')} ({ev.get('source_host','?')}) | "
                        f"Auth: {ev.get('auth_mechanism','?')} | "
                        f"Threat: {threat}"
                        + (" | OBFUSCATED SCRIPT DETECTED" if ev.get("obfuscated") else "")
                    ),
                    "event_id":   ev["event_id"],
                    "source":     "PSRemoting Monitor",
                    "risk_score": 15 if threat == "obfuscated_script" else 10,
                    "source_ip":  ev.get("source_ip", ""),
                    "username":   ev.get("username", ""),
                })
            log.warning(f"[PSRemoting] {len(suspicious)} suspicious PS remoting events pushed to AlertBus")
        except Exception as e:
            log.warning(f"[PSRemoting] Alert push failed: {e}")

    # ── Poll cycle ────────────────────────────────────────────────────────────

    def _poll(self):
        events = []

        # Mode 1: check already-collected security log
        db_events = self._poll_security_db()
        events.extend(db_events)

        # Mode 2: live WinRM channel
        if self._winrm_available:
            winrm_events = self._poll_channel(
                self.WINRM_CHANNEL, "_last_winrm_record", WINRM_EIDS
            )
            events.extend(winrm_events)

        # Mode 2: live PowerShell operational channel
        if self._ps_op_available:
            ps_events = self._poll_channel(
                self.PS_OP_CHANNEL, "_last_ps_record", PS_OPERATIONAL_EIDS
            )
            events.extend(ps_events)

        if events:
            self._push_alerts(events)
            self._store_events(events)
            susp = sum(1 for e in events if e.get("suspicious"))
            if susp:
                log.warning(f"[PSRemoting] {len(events)} events, {susp} suspicious")
            else:
                log.debug(f"[PSRemoting] {len(events)} events processed")

    # ── Cursor seeding ────────────────────────────────────────────────────────

    def _seed_cursor(self, channel: str, attr: str):
        try:
            h      = self._w32log.OpenEventLog(None, channel)
            total  = self._w32log.GetNumberOfEventLogRecords(h)
            oldest = self._w32log.GetOldestEventLogRecord(h)
            setattr(self, attr, oldest + total - 1)
            self._w32log.CloseEventLog(h)
        except Exception as e:
            log.warning(f"[PSRemoting] Could not seed cursor for {channel}: {e}")

    def _seed_db_cursor(self):
        try:
            from database.db import get_conn
            conn = get_conn()
            row  = conn.execute(
                "SELECT MAX(id) FROM logs_security WHERE event_id IN (4624, 4634)"
            ).fetchone()
            conn.close()
            self._last_sec_log_id = row[0] or 0
        except Exception:
            self._last_sec_log_id = 0

    # ── Background loop ───────────────────────────────────────────────────────

    def _loop(self):
        log.info("[PSRemoting] PsRemotingCollector started")
        self._seed_db_cursor()
        log.info(f"[PSRemoting] Security DB cursor seeded at id={self._last_sec_log_id}")

        if self._init_win32():
            self._winrm_available  = self._channel_available(self.WINRM_CHANNEL)
            self._ps_op_available  = self._channel_available(self.PS_OP_CHANNEL)

            if self._winrm_available:
                self._seed_cursor(self.WINRM_CHANNEL, "_last_winrm_record")
                log.info("[PSRemoting] WinRM/Operational channel available — live session tracking enabled")
            else:
                log.info("[PSRemoting] WinRM/Operational not available — DB-query mode only")

            if self._ps_op_available:
                self._seed_cursor(self.PS_OP_CHANNEL, "_last_ps_record")
                log.info("[PSRemoting] PowerShell/Operational channel available — script block logging enabled")
            else:
                log.info("[PSRemoting] PowerShell/Operational not available — enable it for script block tracking")
        else:
            log.warning("[PSRemoting] pywin32 not available — running in DB-query mode only")

        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[PSRemoting] Poll loop error: {e}")
            self._stop.wait(POLL_INTERVAL)

        log.info(f"[PSRemoting] Stopped — {self._events_found} total events")

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="psremoting-collector"
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

_instance: Optional[PsRemotingCollector] = None
_lock = threading.Lock()


def get_psremoting_collector() -> PsRemotingCollector:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = PsRemotingCollector()
    return _instance


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION STEPS
# ══════════════════════════════════════════════════════════════════════════════
#
# 1. core/event_collector/rt_pipeline.py — add to RTPipeline.start():
#
#       # ── FR09-06: PS Remoting Collector ───────────────────────────────────
#       try:
#           from core.event_collector.psremoting_collector import get_psremoting_collector
#           psr = get_psremoting_collector()
#           psr.start()
#           self._collectors["ps_remoting"] = psr
#           log.info("✅ FR09-06: PsRemotingCollector started (WinRM/Operational + PS/Operational)")
#       except Exception as e:
#           log.error(f"❌ FR09-06: PsRemotingCollector failed to start: {e}")
#
#
# 2. api/rt_status_api.py — add endpoints:
#
#       GET /api/psremoting/recent  → last N PS remoting events
#       GET /api/psremoting/stats   → session counts, auth fails, obfuscated scripts
#
# ══════════════════════════════════════════════════════════════════════════════
