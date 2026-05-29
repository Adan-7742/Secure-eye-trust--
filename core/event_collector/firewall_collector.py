"""
core/event_collector/firewall_collector.py
===========================================
FR01-05: Firewall and Network Log Collection

TWO collection methods:
  1. pfirewall.log file parser  — Windows Firewall text log
     Path: C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log
     Enable via: Windows Defender Firewall → Advanced Settings → Logging

  2. Windows Event Log — Security / System channels
     EID 5152 — Firewall blocked packet
     EID 5153 — Firewall blocked packet (more restrictive)
     EID 5154 — Firewall allowed listen
     EID 5156 — Firewall allowed connection
     EID 5157 — Firewall blocked connection
     EID 4946 — Firewall rule added
     EID 4947 — Firewall rule modified
     EID 4950 — Firewall policy changed

SUSPICIOUS IP DETECTION:
  - Port scan detection (same IP → many ports in short time)
  - Known bad port targeting (22, 23, 3389, 445, 1433)
  - Private IP scanning from external IPs
  - High connection rate from single source

All events normalize to:
{
  "timestamp":    "...",
  "direction":    "INBOUND|OUTBOUND",
  "action":       "ALLOW|DROP|BLOCK",
  "protocol":     "TCP|UDP|ICMP",
  "src_ip":       "...",
  "src_port":     443,
  "dst_ip":       "...",
  "dst_port":     80,
  "suspicious":   true|false,
  "threat_type":  "port_scan|known_bad_port|null",
  "event_id":     5157,
  "source":       "pfirewall|event_log",
}
"""

import threading
import time
import os
import re
import sqlite3
from datetime import datetime
from collections import defaultdict, deque
from typing import Optional
from utils.logger import get_logger

log = get_logger("firewall_collector")

POLL_INTERVAL = 3   # seconds

# Windows Firewall log default path
FIREWALL_LOG_PATH = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
FALLBACK_LOG_PATH = r"C:\Windows\Temp\pfirewall.log"

# Firewall Event IDs from Windows Security + System log
FIREWALL_EIDS = {
    5152: {"action": "BLOCK",  "direction": "INBOUND",  "level": "WARNING"},
    5153: {"action": "BLOCK",  "direction": "INBOUND",  "level": "HIGH"},
    5154: {"action": "ALLOW",  "direction": "INBOUND",  "level": "INFO"},
    5155: {"action": "BLOCK",  "direction": "INBOUND",  "level": "WARNING"},
    5156: {"action": "ALLOW",  "direction": "OUTBOUND", "level": "INFO"},
    5157: {"action": "BLOCK",  "direction": "OUTBOUND", "level": "WARNING"},
    5158: {"action": "ALLOW",  "direction": "INBOUND",  "level": "INFO"},
    4946: {"action": "RULE",   "direction": "BOTH",     "level": "HIGH"},
    4947: {"action": "RULE",   "direction": "BOTH",     "level": "HIGH"},
    4950: {"action": "POLICY", "direction": "BOTH",     "level": "CRITICAL"},
}

# Ports known to be targeted in attacks
SUSPICIOUS_PORTS = {
    22:    "SSH brute force",
    23:    "Telnet attack",
    3389:  "RDP attack",
    445:   "SMB/EternalBlue exploit",
    1433:  "SQL Server attack",
    1434:  "SQL Browser attack",
    5985:  "WinRM attack",
    4444:  "Metasploit reverse shell",
    8080:  "HTTP proxy attack",
    6379:  "Redis attack",
    27017: "MongoDB attack",
}

# Private IP ranges (RFC 1918)
_PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
]


def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip or "") for p in _PRIVATE_RANGES)


# ── pfirewall.log line parser ─────────────────────────────────────────────────
# Format: date time action protocol src-ip src-port dst-ip dst-port ...
_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})\s+"          # date
    r"(\d{2}:\d{2}:\d{2})\s+"           # time
    r"(\w+)\s+"                          # action (ALLOW/DROP)
    r"(\w+)\s+"                          # protocol
    r"([\d.]+)\s+"                       # src-ip
    r"(\d+|-)\s+"                        # src-port
    r"([\d.]+)\s+"                       # dst-ip
    r"(\d+|-)\s+"                        # dst-port
    r"([\d-]+)\s+"                       # size
    r"([\d-]+)\s+"                       # tcpflags
    r"([\d-]+)\s+"                       # tcpsyn
    r"([\d-]+)\s+"                       # tcpack
    r"([\d-]+)\s+"                       # tcpwin
    r"([\d-]+)\s+"                       # icmptype
    r"([\d-]+)\s+"                       # icmpcode
    r"([\d-]+)\s+"                       # info
    r"(\S+)"                             # direction (SEND/RECEIVE)
)

def _parse_firewall_line(line: str) -> Optional[dict]:
    """Parse one pfirewall.log line into a structured dict."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _LOG_RE.match(line)
    if not m:
        return None

    date, tme, action, proto, src_ip, src_port, dst_ip, dst_port = m.groups()[:8]
    direction_raw = m.group(17)

    direction = "INBOUND" if direction_raw.upper() == "RECEIVE" else "OUTBOUND"
    dst_port_int = int(dst_port) if dst_port.isdigit() else 0
    src_port_int = int(src_port) if src_port.isdigit() else 0

    threat_type = None
    suspicious  = False
    if dst_port_int in SUSPICIOUS_PORTS:
        threat_type = SUSPICIOUS_PORTS[dst_port_int]
        suspicious  = True

    return {
        "timestamp":  f"{date}T{tme}",
        "date":       date,
        "action":     action.upper(),
        "protocol":   proto.upper(),
        "direction":  direction,
        "src_ip":     src_ip,
        "src_port":   src_port_int,
        "dst_ip":     dst_ip,
        "dst_port":   dst_port_int,
        "suspicious": suspicious,
        "threat_type": threat_type,
        "src_private": _is_private_ip(src_ip),
        "dst_private": _is_private_ip(dst_ip),
        "source":     "pfirewall",
        "level":      "WARNING" if action.upper() == "DROP" else "INFO",
        "event_id":   5157 if action.upper() == "DROP" else 5156,
        "raw":        line[:500],
        "collected_at": datetime.now().isoformat(),
    }


# ── Port scan detector ────────────────────────────────────────────────────────

class PortScanDetector:
    """
    Sliding window detector.
    If same source IP hits > THRESHOLD distinct destination ports
    within TIME_WINDOW seconds → port scan alert.
    """
    THRESHOLD   = 15   # distinct dst_ports from same src_ip
    TIME_WINDOW = 60   # seconds

    def __init__(self):
        # src_ip → deque of (timestamp, dst_port)
        self._seen: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._alerted: set[str] = set()   # IPs we already alerted on

    def check(self, src_ip: str, dst_port: int, ts: float) -> Optional[dict]:
        """
        Record this connection attempt.
        Returns a scan detection dict if a scan is confirmed, else None.
        """
        if not src_ip or src_ip in ("0.0.0.0", "-", "::"):
            return None

        dq = self._seen[src_ip]
        dq.append((ts, dst_port))

        # Remove entries outside time window
        cutoff = ts - self.TIME_WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        distinct_ports = len(set(p for _, p in dq))
        if distinct_ports >= self.THRESHOLD and src_ip not in self._alerted:
            self._alerted.add(src_ip)
            return {
                "threat_type":    "port_scan",
                "src_ip":         src_ip,
                "distinct_ports": distinct_ports,
                "window_seconds": self.TIME_WINDOW,
                "severity":       "HIGH",
                "description": (
                    f"Port scan detected from {src_ip}: "
                    f"{distinct_ports} distinct ports in {self.TIME_WINDOW}s."
                ),
            }
        return None

    def reset_alert(self, src_ip: str):
        """Call after alert has been actioned to allow future alerts for same IP."""
        self._alerted.discard(src_ip)


class FirewallCollector:
    """
    FR01-05 — Collects and analyses firewall events from both
    pfirewall.log and Windows Event Log.
    """

    def __init__(self):
        self._stop        = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scan_detect = PortScanDetector()
        self._file_pos    = 0            # byte position in pfirewall.log
        self._log_path    = self._find_log_path()
        self._last_eid_record = 0       # cursor for event log EID-based read
        self._events_found   = 0
        self._win32ok        = False
        self._priv_warned    = False     # Suppress repeated privilege errors

    def _find_log_path(self) -> Optional[str]:
        """Find the pfirewall.log file, or return None if not found."""
        for path in [FIREWALL_LOG_PATH, FALLBACK_LOG_PATH]:
            if os.path.exists(path):
                log.info(f"Firewall log found: {path}")
                return path
        log.warning(
            "pfirewall.log not found. Enable it: Windows Defender Firewall → "
            "Advanced Settings → Properties → Logging → Log dropped/successful packets"
        )
        return None

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

    # ── pfirewall.log tailing ─────────────────────────────────────────────────

    def _read_log_file(self) -> list[dict]:
        """Read new lines appended to pfirewall.log since last read."""
        if not self._log_path:
            return []
        results = []
        try:
            with open(self._log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._file_pos)
                for line in f:
                    parsed = _parse_firewall_line(line)
                    if parsed:
                        # Port scan check
                        scan = self._scan_detect.check(
                            parsed["src_ip"],
                            parsed["dst_port"],
                            time.time()
                        )
                        if scan:
                            parsed["suspicious"]  = True
                            parsed["threat_type"] = "port_scan"
                            parsed["scan_details"] = scan
                        results.append(parsed)
                self._file_pos = f.tell()
        except PermissionError:
            log.warning("pfirewall.log: permission denied — run as Administrator")
        except Exception as e:
            log.error(f"pfirewall.log read error: {e}")
        return results

    # ── Event Log firewall events ─────────────────────────────────────────────

    def _read_firewall_events(self) -> list[dict]:
        """Read firewall EIDs (5152-5157, 4946, 4947, 4950) from Security log."""
        if not self._init_win32():
            return []

        import socket, re
        results = []
        highest = self._last_eid_record
        IP_RE   = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        PORT_RE = re.compile(r"(?:Source Port|Destination Port):\s*(\d+)", re.IGNORECASE)

        try:
            handle = self._win32evtlog.OpenEventLog(None, "Security")
            flags  = (self._win32evtlog.EVENTLOG_BACKWARDS_READ |
                      self._win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            done   = False

            while not done:
                batch = self._win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for ev in batch:
                    if ev.RecordNumber <= self._last_eid_record:
                        done = True
                        break
                    if ev.RecordNumber > highest:
                        highest = ev.RecordNumber

                    eid = ev.EventID & 0xFFFF
                    if eid not in FIREWALL_EIDS:
                        continue

                    meta = FIREWALL_EIDS[eid]
                    try:
                        ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                    except Exception:
                        ts = datetime.now().isoformat()

                    try:
                        msg = self._win32evtlogutil.SafeFormatMessage(ev, ev.SourceName) or ""
                    except Exception:
                        inserts = ev.StringInserts
                        msg = " | ".join(str(s) for s in inserts) if inserts else ""

                    # Extract IPs and ports from message
                    ips   = IP_RE.findall(msg)
                    ports = PORT_RE.findall(msg)
                    src_ip  = ips[0] if len(ips) > 0 else None
                    dst_ip  = ips[1] if len(ips) > 1 else None
                    dst_prt = int(ports[1]) if len(ports) > 1 else 0

                    suspicious = dst_prt in SUSPICIOUS_PORTS
                    threat     = SUSPICIOUS_PORTS.get(dst_prt)

                    # Port scan check on EID 5152/5157
                    if eid in (5152, 5157) and src_ip:
                        scan = self._scan_detect.check(src_ip, dst_prt, time.time())
                        if scan:
                            suspicious = True
                            threat     = "port_scan"

                    results.append({
                        "timestamp":   ts,
                        "date":        ts[:10],
                        "level":       meta["level"],
                        "action":      meta["action"],
                        "direction":   meta["direction"],
                        "src_ip":      src_ip,
                        "dst_ip":      dst_ip,
                        "dst_port":    dst_prt,
                        "src_private": _is_private_ip(src_ip),
                        "dst_private": _is_private_ip(dst_ip),
                        "suspicious":  suspicious,
                        "threat_type": threat,
                        "event_id":    eid,
                        "source":      "Firewall Event Log",
                        "message":     msg[:2000],
                        "raw":         msg[:500],
                        "hostname":    socket.gethostname(),
                        "collected_at": datetime.now().isoformat(),
                    })

            self._win32evtlog.CloseEventLog(handle)
            if highest > self._last_eid_record:
                self._last_eid_record = highest

        except Exception as e:
            err = str(e)
            if "1314" in err or "access" in err.lower() or "privilege" in err.lower() or "5" == err.strip():
                if not self._priv_warned:
                    log.warning("Firewall log access requires Administrator — run as admin to enable. (This message will not repeat.)")
                    self._priv_warned = True
            else:
                log.error(f"Firewall event log read error: {e}")

        return results

    # ── Alert push ────────────────────────────────────────────────────────────

    def _push_suspicious_alerts(self, events: list[dict]):
        """Push suspicious firewall events to AlertBus."""
        try:
            from core.pipeline.alert_bus import get_alert_bus
            bus = get_alert_bus()

            for ev in events:
                if not ev.get("suspicious"):
                    continue
                threat   = ev.get("threat_type") or "suspicious_traffic"
                src_ip   = ev.get("src_ip") or "unknown"
                dst_port = ev.get("dst_port") or 0

                bus.push({
                    "type":        "firewall_alert",
                    "severity":    "HIGH",
                    "category":    "network",
                    "title":       f"Suspicious firewall activity: {threat}",
                    "description": (
                        f"Source IP: {src_ip}, "
                        f"Destination Port: {dst_port}, "
                        f"Type: {threat}."
                    ),
                    "event_id":    ev.get("event_id"),
                    "source":      "Firewall Monitor",
                    "risk_score":  12,
                    "src_ip":      src_ip,
                })
        except Exception as e:
            log.warning(f"Firewall alert push failed: {e}")

    def _store_events(self, events: list[dict]):
        """Write firewall events to logs_security table."""
        if not events:
            return
        try:
            from database.db import get_conn
            attempt = 0
            while attempt < 3:
                conn = get_conn()
                try:
                    for ev in events:
                        conn.execute("""
                            INSERT INTO logs_security
                                (timestamp, date, level, source, message, event_id, raw)
                            VALUES (?,?,?,?,?,?,?)
                        """, (
                            ev.get("timestamp"), ev.get("date"),
                            ev.get("level", "INFO"),
                            ev.get("source", "Windows Firewall"),
                            ev.get("message") or ev.get("raw") or "",
                            ev.get("event_id"), ev.get("raw", ""),
                        ))
                    conn.commit()
                    self._events_found += len(events)
                    break
                except sqlite3.OperationalError as e:
                    conn.close()
                    if attempt < 2 and "database is locked" in str(e).lower():
                        time.sleep(0.1 * (attempt + 1))
                        attempt += 1
                        continue
                    raise
                finally:
                    if conn:
                        conn.close()
        except Exception as e:
            log.warning(f"Firewall store failed: {e}")

    def _poll(self):
        # Read from pfirewall.log file
        file_events = self._read_log_file()

        # Read from Windows Event Log
        evtlog_events = self._read_firewall_events()

        all_events = file_events + evtlog_events
        if not all_events:
            return

        # Push suspicious ones to alert bus immediately
        suspicious = [e for e in all_events if e.get("suspicious")]
        if suspicious:
            self._push_suspicious_alerts(suspicious)
            log.warning(f"[Firewall] {len(suspicious)} suspicious events detected")

        # Store everything
        self._store_events(all_events)

        if all_events:
            log.debug(f"[Firewall] {len(all_events)} events processed "
                      f"({len(suspicious)} suspicious)")

    def _seed_cursor(self):
        """Seed event log cursor and skip to end of existing log file."""
        # Seed log file position to end
        if self._log_path and os.path.exists(self._log_path):
            try:
                self._file_pos = os.path.getsize(self._log_path)
                log.info(f"Firewall log: starting at byte {self._file_pos}")
            except Exception:
                pass

        # Seed event log cursor
        if self._init_win32():
            try:
                h      = self._win32evtlog.OpenEventLog(None, "Security")
                total  = self._win32evtlog.GetNumberOfEventLogRecords(h)
                oldest = self._win32evtlog.GetOldestEventLogRecord(h)
                self._last_eid_record = oldest + total - 1
                self._win32evtlog.CloseEventLog(h)
            except Exception:
                pass

    def _loop(self):
        log.info("FirewallCollector started")
        self._seed_cursor()

        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"FirewallCollector poll error: {e}")
            self._stop.wait(POLL_INTERVAL)

        log.info(f"FirewallCollector stopped — {self._events_found} total events")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="firewall-collector"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[FirewallCollector] = None
_lock = threading.Lock()


def get_firewall_collector() -> FirewallCollector:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = FirewallCollector()
    return _instance
