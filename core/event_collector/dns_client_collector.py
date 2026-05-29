"""
core/event_collector/dns_client_collector.py
=============================================
FR09-03: Windows DNS Client Activity Monitoring

Collects DNS client queries and failures from the Windows DNS Client
operational event log channel, bridging the gap between the existing
on-demand /dns-lookup tool and real passive monitoring of what the
system is actually resolving behind the scenes.

EVENT LOG CHANNEL:
  Microsoft-Windows-DNS-Client/Operational
  (must be enabled — see _enable_dns_log() below)

DNS CLIENT EVENT IDs MAPPED:
  3006  — DNS query initiated             (INFO)
  3008  — DNS query response received     (INFO)
  3010  — DNS cache entry added           (INFO)
  3018  — DNS cache flushed               (WARNING)
  3020  — DNS name resolution failed      (WARNING)  ← key security signal
  3060  — DNS suffix search               (INFO)
  1014  — DNS name resolution timeout     (WARNING)  ← in System log

SECURITY SIGNALS DETECTED:
  - High-entropy domain names (possible DGA/malware C2)
  - Resolution of known suspicious TLDs (.ru, .cn, .to, .tk, .pw, etc.)
  - Excessive NXDOMAIN failures (possible C2 beacon or DNS enumeration)
  - DNS resolution of IP literals (unusual, potential proxy bypass)
  - Burst queries to the same domain (beaconing pattern)

All events normalised to:
{
  "timestamp":    "...",
  "date":         "YYYY-MM-DD",
  "level":        "INFO|WARNING|ERROR",
  "event_id":     3006,
  "query_name":   "example.com",
  "query_type":   "A",
  "result":       "SUCCESS|NXDOMAIN|TIMEOUT|REFUSED",
  "response_ip":  "1.2.3.4",       # for successful resolutions
  "process_id":   1234,
  "suspicious":   false,
  "threat_type":  null,             # "dga"|"suspicious_tld"|"nxdomain_burst"|"beaconing"
  "entropy":      3.2,              # Shannon entropy of domain label
  "source":       "DNS-Client/Operational",
  "category":     "dns_client",
  "raw":          "...",
}

PLACEMENT:
  Place this file at: core/event_collector/dns_client_collector.py
  Then follow the three integration steps at the bottom of this file.
"""

import threading
import time
import re
import math
import socket
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("dns_client_collector")

POLL_INTERVAL = 3       # seconds — matches other collectors
MAX_PER_POLL  = 300     # max events per cycle

# ── DNS Client Event ID definitions ───────────────────────────────────────────

DNS_CLIENT_EIDS = {
    3006: {"level": "INFO",    "result": "QUERY_SENT",    "name": "DNS Query Initiated"},
    3008: {"level": "INFO",    "result": "SUCCESS",       "name": "DNS Query Response"},
    3010: {"level": "INFO",    "result": "CACHE_ADD",     "name": "DNS Cache Entry Added"},
    3018: {"level": "WARNING", "result": "CACHE_FLUSH",   "name": "DNS Cache Flushed"},
    3020: {"level": "WARNING", "result": "NXDOMAIN",      "name": "DNS Resolution Failed"},
    3060: {"level": "INFO",    "result": "SUFFIX_SEARCH", "name": "DNS Suffix Search"},
    1014: {"level": "WARNING", "result": "TIMEOUT",       "name": "DNS Resolution Timeout"},
}

# System log EID 1014 is in the System channel, not DNS-Client/Operational
SYSTEM_DNS_EIDS = {1014}

# ── Suspicious TLD list ────────────────────────────────────────────────────────

_SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".tk", ".pw", ".cc", ".to", ".biz",
    ".xyz", ".top", ".club", ".work", ".loan", ".review",
    ".stream", ".download", ".gq", ".ml", ".ga", ".cf",
}

# ── Regex helpers ──────────────────────────────────────────────────────────────

_RE_QUERY_NAME = re.compile(
    r"(?:QueryName|Name|DNS Name|query name)[:\s]+([^\s\r\n|,]+)",
    re.IGNORECASE
)
_RE_QUERY_TYPE = re.compile(
    r"(?:QueryType|Type|Record Type)[:\s]+([^\s\r\n|,]+)",
    re.IGNORECASE
)
_RE_RESULT = re.compile(
    r"(?:QueryResult|QueryStatus|Result|Status)[:\s]+([^\s\r\n|,]+)",
    re.IGNORECASE
)
_RE_RESPONSE_IP = re.compile(
    r"(?:ResponseAddress|Address|IP Address)[:\s]+([\d.:a-fA-F]+)"
)
_RE_PID = re.compile(r"(?:ProcessId|PID)[:\s]+(\d+)", re.IGNORECASE)


# ── Shannon entropy for DGA detection ─────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. High values → possible DGA."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return round(-sum((v / n) * math.log2(v / n) for v in freq.values()), 2)


def _extract_label(domain: str) -> str:
    """Return the leftmost label of a domain for entropy analysis."""
    parts = domain.strip(".").split(".")
    return parts[0] if parts else domain


# ── Beaconing / burst detector ─────────────────────────────────────────────────

class DnsBeaconDetector:
    """
    Sliding-window detector for DNS beaconing patterns.
    If the same domain is queried > THRESHOLD times in TIME_WINDOW seconds,
    it is flagged as a possible C2 beacon.
    """
    THRESHOLD   = 20   # queries to same domain
    TIME_WINDOW = 60   # seconds

    def __init__(self):
        # domain → deque of timestamps
        self._seen: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._alerted: set[str] = set()

    def check(self, domain: str, ts: float) -> bool:
        """
        Record a query. Return True if beaconing is detected (and not yet alerted).
        Clears old alert flag after TIME_WINDOW passes with no queries.
        """
        if not domain:
            return False
        dq = self._seen[domain]
        dq.append(ts)
        cutoff = ts - self.TIME_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)
        if count >= self.THRESHOLD and domain not in self._alerted:
            self._alerted.add(domain)
            return True
        if count < self.THRESHOLD // 2 and domain in self._alerted:
            self._alerted.discard(domain)
        return False


# ── NXDomain burst detector ────────────────────────────────────────────────────

class NxdomainBurstDetector:
    """
    Flags when many distinct domains fail to resolve in a short window.
    Indicates DNS enumeration or a misconfigured C2 beaconing to random domains.
    """
    THRESHOLD   = 15   # distinct NXDOMAIN failures
    TIME_WINDOW = 60   # seconds

    def __init__(self):
        self._failures: deque = deque(maxlen=500)
        self._alerted  = False

    def record(self, ts: float) -> bool:
        self._failures.append(ts)
        cutoff = ts - self.TIME_WINDOW
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()
        count = len(self._failures)
        if count >= self.THRESHOLD and not self._alerted:
            self._alerted = True
            return True
        if count < self.THRESHOLD // 2:
            self._alerted = False
        return False


# ── Main collector class ───────────────────────────────────────────────────────

class DnsClientCollector:
    """
    FR09-03 — Monitors Windows DNS Client Operational event log and System log
    for all DNS queries, responses, failures, and cache operations.

    Runs as a background daemon thread polling every POLL_INTERVAL seconds.
    Suspicious activity is pushed to AlertBus immediately.
    All events are stored in the logs_security table (reuses the existing
    infrastructure — no schema change required).
    """

    DNS_CHANNEL    = "Microsoft-Windows-DNS-Client/Operational"
    SYSTEM_CHANNEL = "System"

    def __init__(self):
        self._stop               = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._win32ok            = False
        self._last_dns_record    = 0
        self._last_sys_record    = 0
        self._events_found       = 0
        self._beacon_detector    = DnsBeaconDetector()
        self._nxdomain_detector  = NxdomainBurstDetector()
        self._dns_enabled        = False   # whether the log channel is enabled

    # ── win32 initialisation ─────────────────────────────────────────────────

    def _init_win32(self) -> bool:
        if self._win32ok:
            return True
        try:
            import win32evtlog, win32evtlogutil, win32con, win32api, pywintypes
            self._w32log  = win32evtlog
            self._w32util = win32evtlogutil
            self._w32con  = win32con
            self._w32api  = win32api
            self._pywt    = pywintypes
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

    # ── Enable DNS Client operational log ─────────────────────────────────────

    def _enable_dns_log(self):
        """
        Attempt to enable Microsoft-Windows-DNS-Client/Operational via wevtutil.
        This is a one-time operation — requires Administrator privileges.
        Silently skips on failure (non-admin or already enabled).
        """
        try:
            import subprocess
            result = subprocess.run(
                ["wevtutil", "sl", "Microsoft-Windows-DNS-Client/Operational",
                 "/e:true", "/q:true"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                log.info("[DNS] DNS Client operational log enabled")
                self._dns_enabled = True
            else:
                # May already be enabled, or insufficient privileges
                err = result.stderr.decode(errors="replace").strip()
                if "already" in err.lower() or result.returncode == 0:
                    self._dns_enabled = True
                else:
                    log.warning(
                        f"[DNS] Could not enable DNS-Client/Operational log: {err}. "
                        "Run as Administrator to enable it."
                    )
        except Exception as e:
            log.warning(f"[DNS] wevtutil call failed: {e}")

    def _check_dns_channel_available(self) -> bool:
        """Test whether the DNS-Client/Operational channel can be opened."""
        if not self._win32ok:
            return False
        try:
            h = self._w32log.OpenEventLog(None, self.DNS_CHANNEL)
            self._w32log.CloseEventLog(h)
            return True
        except Exception:
            return False

    # ── Cursor seeding ────────────────────────────────────────────────────────

    def _seed_cursor(self, channel: str, attr: str):
        """Seed event log cursor to current end — only capture future events."""
        try:
            h      = self._w32log.OpenEventLog(None, channel)
            total  = self._w32log.GetNumberOfEventLogRecords(h)
            oldest = self._w32log.GetOldestEventLogRecord(h)
            setattr(self, attr, oldest + total - 1)
            self._w32log.CloseEventLog(h)
            log.info(f"[DNS] {channel} cursor seeded at record #{getattr(self, attr)}")
        except Exception as e:
            log.warning(f"[DNS] Could not seed cursor for {channel}: {e}")

    # ── Message parsing ────────────────────────────────────────────────────────

    def _safe_message(self, ev) -> str:
        try:
            msg = self._w32util.SafeFormatMessage(ev, ev.SourceName)
            return msg if msg else ""
        except Exception:
            if ev.StringInserts:
                return " | ".join(str(s) for s in ev.StringInserts)
            return f"Event ID {ev.EventID & 0xFFFF}"

    def _parse_dns_event(self, ev, channel: str) -> dict:
        """Parse a win32evtlog event into a structured DNS client event dict."""
        try:
            ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
        except Exception:
            ts = datetime.now().isoformat()

        eid = ev.EventID & 0xFFFF
        msg = self._safe_message(ev)
        meta = DNS_CLIENT_EIDS.get(eid, {"level": "INFO", "result": "UNKNOWN", "name": "DNS Event"})

        # Extract structured fields from message text
        qname_m  = _RE_QUERY_NAME.search(msg)
        qtype_m  = _RE_QUERY_TYPE.search(msg)
        result_m = _RE_RESULT.search(msg)
        resp_m   = _RE_RESPONSE_IP.search(msg)
        pid_m    = _RE_PID.search(msg)

        query_name  = (qname_m.group(1) if qname_m else "").strip().rstrip(".")
        query_type  = (qtype_m.group(1) if qtype_m else "").strip()
        result_str  = (result_m.group(1) if result_m else meta["result"]).strip()
        response_ip = (resp_m.group(1) if resp_m else "").strip()
        process_id  = int(pid_m.group(1)) if pid_m else 0

        # Normalise result from numeric codes
        if result_str.isdigit():
            code = int(result_str)
            result_str = {
                0: "SUCCESS", 9003: "NXDOMAIN", 9701: "NXDOMAIN",
                9002: "SERVFAIL", 9501: "TIMEOUT", 5: "REFUSED",
            }.get(code, f"CODE_{result_str}")

        # Entropy and suspicious-domain analysis
        label   = _extract_label(query_name) if query_name else ""
        entropy = _shannon_entropy(label) if len(label) > 4 else 0.0

        suspicious  = False
        threat_type = None

        if query_name:
            # DGA heuristic: high entropy label > 12 chars
            if entropy > 3.8 and len(label) > 12:
                suspicious  = True
                threat_type = "dga"

            # Known suspicious TLD
            domain_lower = query_name.lower()
            if any(domain_lower.endswith(tld) for tld in _SUSPICIOUS_TLDS):
                suspicious  = True
                threat_type = threat_type or "suspicious_tld"

            # Beaconing detection
            if self._beacon_detector.check(query_name, time.time()):
                suspicious  = True
                threat_type = "beaconing"

        # NXDOMAIN burst
        if eid in (3020, 1014) or "NXDOMAIN" in result_str.upper() or "TIMEOUT" in result_str.upper():
            if self._nxdomain_detector.record(time.time()):
                suspicious  = True
                threat_type = threat_type or "nxdomain_burst"

        level = meta["level"]
        if suspicious and level == "INFO":
            level = "WARNING"

        return {
            "timestamp":   ts,
            "date":        ts[:10],
            "level":       level,
            "source":      f"DNS-Client ({channel})",
            "event_id":    eid,
            "query_name":  query_name,
            "query_type":  query_type,
            "result":      result_str,
            "response_ip": response_ip,
            "process_id":  process_id,
            "suspicious":  suspicious,
            "threat_type": threat_type,
            "entropy":     entropy,
            "message":     (
                f"DNS {meta['name']}: {query_name or 'unknown'}"
                + (f" → {response_ip}" if response_ip else "")
                + (f" [{result_str}]" if result_str else "")
                + (f" [⚠ {threat_type}]" if threat_type else "")
            )[:2000],
            "raw":         msg[:500],
            "category":    "dns_client",
            "hostname":    socket.gethostname(),
            "collected_at": datetime.now().isoformat(),
        }

    # ── Poll one channel ──────────────────────────────────────────────────────

    def _poll_channel(self, channel: str, cursor_attr: str,
                      target_eids: set) -> list[dict]:
        """Read new events from `channel` since last cursor. Returns parsed list."""
        if not self._win32ok:
            return []

        results   = []
        highest   = getattr(self, cursor_attr)
        handle    = None

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
                    results.append(self._parse_dns_event(ev, channel))

            if highest > getattr(self, cursor_attr):
                setattr(self, cursor_attr, highest)

        except Exception as e:
            err = str(e)
            if "5" not in err and "access" not in err.lower():
                log.error(f"[DNS] {channel} poll error: {e}")
        finally:
            if handle:
                try:
                    self._w32log.CloseEventLog(handle)
                except Exception:
                    pass

        return results

    # ── Store events ──────────────────────────────────────────────────────────

    def _store_events(self, events: list[dict]):
        """
        Persist DNS events into logs_security.
        Stores query_name in the 'source' column for easy searchability,
        full structured message in 'message', and threat info in 'raw'.
        No schema change required.
        """
        if not events:
            return
        try:
            from database.db import get_conn
            import sqlite3
            conn   = get_conn()
            insert = 0
            for ev in events:
                try:
                    conn.execute(
                        """
                        INSERT INTO logs_security
                            (timestamp, date, level, source, message, event_id, raw)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            ev["timestamp"], ev["date"], ev["level"],
                            ev.get("source", "DNS-Client"),
                            ev["message"], ev["event_id"],
                            ev.get("raw", ""),
                        )
                    )
                    insert += 1
                except sqlite3.IntegrityError:
                    pass
            conn.commit()
            conn.close()
            self._events_found += insert
        except Exception as e:
            log.warning(f"[DNS] Store error: {e}")

    # ── Alert push ────────────────────────────────────────────────────────────

    def _push_alerts(self, events: list[dict]):
        """Push suspicious DNS events to AlertBus."""
        suspicious = [e for e in events if e.get("suspicious")]
        if not suspicious:
            return
        try:
            from core.pipeline.alert_bus import get_alert_bus
            bus = get_alert_bus()
            for ev in suspicious:
                threat = ev.get("threat_type", "suspicious_dns")
                qname  = ev.get("query_name", "unknown")
                bus.push({
                    "type":        "dns_alert",
                    "severity":    "HIGH" if threat in ("dga", "beaconing") else "MEDIUM",
                    "category":    "network",
                    "title":       f"Suspicious DNS activity: {threat}",
                    "description": (
                        f"Query: {qname} | "
                        f"Result: {ev.get('result','')} | "
                        f"Type: {threat} | "
                        f"Entropy: {ev.get('entropy',0)}"
                    ),
                    "event_id":    ev["event_id"],
                    "source":      "DNS Client Monitor",
                    "risk_score":  10 if threat == "dga" else 7,
                    "query_name":  qname,
                })
            log.warning(f"[DNS] {len(suspicious)} suspicious DNS events pushed to AlertBus")
        except Exception as e:
            log.warning(f"[DNS] Alert push failed: {e}")

    # ── Main poll cycle ───────────────────────────────────────────────────────

    def _poll(self):
        events = []

        # Poll DNS-Client/Operational (primary source)
        if self._dns_enabled or self._check_dns_channel_available():
            self._dns_enabled = True
            dns_events = self._poll_channel(
                self.DNS_CHANNEL,
                "_last_dns_record",
                set(DNS_CLIENT_EIDS.keys()) - SYSTEM_DNS_EIDS
            )
            events.extend(dns_events)

        # Always poll System log for EID 1014 (DNS timeout, available without extra permissions)
        sys_events = self._poll_channel(
            self.SYSTEM_CHANNEL,
            "_last_sys_record",
            SYSTEM_DNS_EIDS
        )
        events.extend(sys_events)

        if events:
            self._push_alerts(events)
            self._store_events(events)
            log.debug(
                f"[DNS] {len(events)} events processed "
                f"({sum(1 for e in events if e.get('suspicious'))} suspicious)"
            )

    # ── Background loop ───────────────────────────────────────────────────────

    def _loop(self):
        log.info("[DNS] DnsClientCollector started")
        if not self._init_win32():
            log.warning("[DNS] pywin32 not available — DNS client monitoring disabled")
            return

        # Attempt to enable the DNS-Client/Operational log
        self._enable_dns_log()

        # Seed both cursors to current log end
        if self._dns_enabled or self._check_dns_channel_available():
            self._seed_cursor(self.DNS_CHANNEL, "_last_dns_record")
        self._seed_cursor(self.SYSTEM_CHANNEL, "_last_sys_record")

        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[DNS] Poll loop error: {e}")
            self._stop.wait(POLL_INTERVAL)

        log.info(f"[DNS] DnsClientCollector stopped — {self._events_found} total events")

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="dns-client-collector"
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

_instance: Optional[DnsClientCollector] = None
_lock = threading.Lock()


def get_dns_client_collector() -> DnsClientCollector:
    """Return the global DnsClientCollector singleton. Thread-safe."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = DnsClientCollector()
    return _instance


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION STEPS (3 files to update)
# ══════════════════════════════════════════════════════════════════════════════
#
# 1. core/event_collector/rt_pipeline.py  — add to RTPipeline.start():
#
#       # ── FR09-03: DNS Client Collector ─────────────────────────────────────
#       try:
#           from core.event_collector.dns_client_collector import get_dns_client_collector
#           dns = get_dns_client_collector()
#           dns.start()
#           self._collectors["dns_client"] = dns
#           log.info("✅ FR09-03: DnsClientCollector started (DNS-Client/Operational)")
#       except Exception as e:
#           log.error(f"❌ FR09-03: DnsClientCollector failed to start: {e}")
#
#
# 2. api/rt_status_api.py  — add endpoint (see rt_status_api.py output file):
#
#       GET /api/dns/recent   → last N DNS client events from logs_security
#       GET /api/dns/stats    → query counts, NXDOMAIN rate, top queried domains
#
#
# 3. app.py  — add startup log line:
#
#       print(f"🌐  DNS     : monitoring DNS-Client/Operational (FR09-03)")
#
# ══════════════════════════════════════════════════════════════════════════════
