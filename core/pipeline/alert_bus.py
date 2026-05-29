"""
core/pipeline/alert_bus.py
===========================
Real-time alert bus — thread-safe queue connecting the pipeline
to the SSE stream and the dashboard.

ARCHITECTURE:
  Pipeline (any thread)
      │  push(alert)
      ▼
  AlertBus (thread-safe queue, max 500 alerts)
      │  subscribe() → generator
      ▼
  SSE endpoint (/api/alerts/stream)
      │  text/event-stream
      ▼
  Browser JS (alert panel, toast notifications, sound)

Also writes every alert to the `security_alerts` DB table for
persistence, history, and the alerts history page.

ALERT SEVERITY LEVELS:
  CRITICAL  — immediate action required (risk ≥ 15, attack chain confirmed)
  HIGH      — investigate within 2h   (risk ≥ 8, or correlation hit)
  MEDIUM    — review within 24h       (risk ≥ 4, or anomaly detected)
  LOW       — informational            (risk < 4)
"""

import json
import queue
import threading
import time
from datetime import datetime
from typing import Generator, Optional

from utils.logger import get_logger

log = get_logger("pipeline.alert_bus")


class AlertBus:
    """
    Thread-safe multi-subscriber alert bus.

    Multiple SSE clients can subscribe simultaneously.
    Alerts are broadcast to all active subscribers.
    Also persists alerts to the database.
    """

    def __init__(self, maxsize: int = 500):
        self._lock        = threading.Lock()
        self._subscribers: list[queue.Queue] = []
        self._history:     list[dict]        = []   # last 200 alerts in memory
        self._history_max  = 200
        self._total_pushed = 0

        # ── Noise-suppression state ───────────────────────────────────────
        # Track recent alert fingerprints so we don't fire 50 alerts for the
        # same routine event repeating across a single noisy session.
        #   key (type, fp)  →  {first_ts, last_ts, count}
        self._recent: dict = {}
        self._dedup_window_sec  = 300   # 5 min — within this, same FP coalesces
        self._suppressed_total  = 0


    # Events that are technically "high risk" by raw score but are produced
    # constantly by routine Windows operation. They alert ONLY when something
    # else corroborates (correlator chain, threshold burst, etc.) — not as
    # a single isolated event.
    _ROUTINE_EVENT_IDS = {
        # Authentication noise
        4624, 4634, 4647, 4648, 4672, 4673, 4798, 4799,
        # Process creation noise
        4688,
        # Service/task lifecycle (Windows itself generates these constantly)
        7036, 7040, 7045, 4698, 4699, 4700, 4701, 4702,
        # Registry value-set spam
        4657,
        # Sysmon noise
        1, 3, 11, 13,
        # Power / kernel
        41, 6005, 6006, 6008,
    }

    # Service / account names that produce huge amounts of routine activity
    _SYSTEM_ACCOUNTS = {
        "SYSTEM", "NT AUTHORITY\\SYSTEM",
        "LOCAL SERVICE", "NT AUTHORITY\\LOCAL SERVICE",
        "NETWORK SERVICE", "NT AUTHORITY\\NETWORK SERVICE",
        "DWM-1", "DWM-2", "UMFD-0", "UMFD-1", "UMFD-2",
        "ANONYMOUS LOGON",
    }


    def _alert_fingerprint(self, alert: dict) -> str:
        """Build a coarse fingerprint identifying 'the same alert'.

        Two alerts share a fingerprint when they refer to the same underlying
        condition — same type, same event id, same user, same source. Within
        the dedup window such alerts are coalesced into one burst alert with
        an incrementing count instead of firing dozens of times.
        """
        parts = [
            str(alert.get("type", "")),
            str(alert.get("event_id", "")),
            str(alert.get("user", "")),
            str(alert.get("source", "")),
            str(alert.get("yara_rule", "")),  # for yara alerts
            str(alert.get("name", "")),       # for threat_detection alerts
        ]
        return "|".join(parts)


    def _should_suppress(self, alert: dict) -> tuple[bool, str]:
        """Decide whether an alert should be silently dropped.

        Returns (True, reason) when the alert is noise, (False, "") otherwise.

        The rules below are conservative — we *never* drop a CRITICAL alert,
        we *never* drop alerts carrying a confirmed-malware indicator, and we
        *never* drop correlator-confirmed attack chains. Everything else
        passes through a routine-noise filter.
        """
        sev = (alert.get("severity") or "MEDIUM").upper()

        # ── Always let CRITICAL through ───────────────────────────────────
        if sev == "CRITICAL":
            return False, ""

        # ── Always let confirmed attack chains through ────────────────────
        if alert.get("type") in ("correlation_alert", "attack_chain", "yara_match"):
            # YARA / correlator alerts already passed our scoring gates
            # in their respective modules — don't double-filter them.
            return False, ""

        # ── Drop routine event IDs from system accounts ───────────────────
        eid  = alert.get("event_id")
        user = (alert.get("user") or "").upper()
        if eid in self._ROUTINE_EVENT_IDS and user in self._SYSTEM_ACCOUNTS:
            return True, f"routine EID {eid} from system account {user}"

        # ── Drop isolated routine events with no corroborating signal ─────
        # If the only reason we're alerting is "score >= 8 on a routine
        # event", and there's no rule_alert riding along, suppress it.
        if eid in self._ROUTINE_EVENT_IDS and sev in ("LOW", "MEDIUM"):
            risk = int(alert.get("risk_score", 0) or 0)
            if risk < 15:  # only suppress when the event isn't already exceptional
                return True, f"isolated routine EID {eid} below corroboration threshold"

        return False, ""


    def push(self, alert: dict):
        """
        Push an alert to all subscribers and persist it.
        Thread-safe. Never raises.

        v2: applies routine-noise suppression and per-fingerprint coalescing
        so the dashboard doesn't drown in routine-event alerts. The original
        events are still recorded in the logs tables; only the *alerting* is
        dampened — analyses run after the fact see everything.
        """
        try:
            # Stamp it
            alert = dict(alert)
            alert.setdefault("id",        int(time.time() * 1000))
            alert.setdefault("timestamp", datetime.now().isoformat())
            alert.setdefault("severity",  "MEDIUM")
            alert.setdefault("type",      "generic")
            alert.setdefault("read",      False)

            # ── Noise-floor filter ────────────────────────────────────────
            suppress, why = self._should_suppress(alert)
            if suppress:
                with self._lock:
                    self._suppressed_total += 1
                log.debug(f"AlertBus suppressed: {why}")
                return

            # ── Dedup / coalesce within the rolling window ────────────────
            fp     = self._alert_fingerprint(alert)
            now    = time.time()
            window = self._dedup_window_sec
            with self._lock:
                entry = self._recent.get(fp)
                if entry and (now - entry["last_ts"]) < window:
                    # Bump the existing entry's count instead of firing a new alert
                    entry["count"]   += 1
                    entry["last_ts"]  = now
                    self._suppressed_total += 1
                    # Update the in-history alert with the new count so the UI
                    # can show "× N" without re-emitting through SSE.
                    for h in reversed(self._history):
                        if h.get("_fp") == fp:
                            h["count"] = entry["count"]
                            h["last_ts"] = alert["timestamp"]
                            break
                    return
                # Brand-new fingerprint — record it and fire normally
                self._recent[fp] = {"first_ts": now, "last_ts": now, "count": 1}
                # Garbage-collect old entries
                if len(self._recent) > 1000:
                    cutoff = now - window
                    self._recent = {
                        k: v for k, v in self._recent.items()
                        if v["last_ts"] > cutoff
                    }
                alert["_fp"]   = fp
                alert["count"] = 1

            # In-memory history
            with self._lock:
                self._history.append(alert)
                if len(self._history) > self._history_max:
                    self._history.pop(0)
                self._total_pushed += 1

                # Broadcast to all SSE subscribers
                dead = []
                for q in self._subscribers:
                    try:
                        q.put_nowait(alert)
                    except queue.Full:
                        dead.append(q)
                for q in dead:
                    self._subscribers.remove(q)

            # Persist to DB (non-blocking — fire and forget)
            threading.Thread(
                target=self._persist, args=(alert,), daemon=True
            ).start()

        except Exception as e:
            log.error(f"AlertBus.push failed: {e}")

    def subscribe(self) -> tuple[queue.Queue, callable]:
        """
        Register a new SSE subscriber.
        Returns (queue, unsubscribe_fn).

        The caller should call unsubscribe_fn() when the client disconnects.
        """
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        log.debug(f"New alert subscriber. Total: {len(self._subscribers)}")

        def unsubscribe():
            with self._lock:
                if q in self._subscribers:
                    self._subscribers.remove(q)
            log.debug(f"Alert subscriber removed. Total: {len(self._subscribers)}")

        return q, unsubscribe

    def get_history(self, limit: int = 50, min_severity: str = None) -> list:
        """Return recent alerts from memory + DB."""
        SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        min_rank  = SEV_ORDER.get(min_severity, 99) if min_severity else 99

        with self._lock:
            history = list(self._history)

        if min_severity:
            history = [a for a in history if SEV_ORDER.get(a.get("severity", "LOW"), 99) <= min_rank]

        return sorted(history, key=lambda a: a.get("timestamp", ""), reverse=True)[:limit]

    def get_unread_count(self) -> int:
        with self._lock:
            return sum(1 for a in self._history if not a.get("read"))

    def mark_read(self, alert_id: int):
        with self._lock:
            for a in self._history:
                if a.get("id") == alert_id:
                    a["read"] = True
                    break

    def mark_all_read(self):
        with self._lock:
            for a in self._history:
                a["read"] = True

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_pushed":  self._total_pushed,
                "in_memory":     len(self._history),
                "subscribers":   len(self._subscribers),
                "unread":        sum(1 for a in self._history if not a.get("read")),
            }

    def _persist(self, alert: dict):
        """Write alert to DB — called in a background thread."""
        conn = None
        try:
            from database.db import get_conn
            attempt = 0
            while attempt < 3:
                conn = get_conn()
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO security_alerts
                            (alert_id, timestamp, severity, alert_type, category,
                             event_id, source, user_name, ip_address, risk_score,
                             title, description, raw_json, read)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0)
                    """, (
                        str(alert.get("id")),
                        alert.get("timestamp"),
                        alert.get("severity", "MEDIUM"),
                        alert.get("type", "generic"),
                        alert.get("category", ""),
                        alert.get("event_id"),
                        alert.get("source", ""),
                        alert.get("user"),
                        alert.get("ip"),
                        alert.get("risk_score", 0),
                        alert.get("label") or alert.get("name", ""),
                        alert.get("message") or alert.get("description", ""),
                        json.dumps(alert),
                    ))
                    conn.commit()
                    return
                except Exception as e:
                    if conn:
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
            log.warning(f"Alert persist failed: {e}")


# ── SSE generator helper ──────────────────────────────────────────────────────

def alert_sse_generator(bus: "AlertBus") -> Generator[str, None, None]:
    """
    Generator for SSE streaming.
    Yields SSE-formatted strings: "data: {...}\n\n"
    Includes a heartbeat every 30s to keep the connection alive.
    """
    q, unsubscribe = bus.subscribe()

    # Send recent alerts immediately on connect
    for alert in bus.get_history(limit=10):
        yield f"data: {json.dumps(alert)}\n\n"

    try:
        while True:
            try:
                alert = q.get(timeout=30)
                yield f"data: {json.dumps(alert)}\n\n"
            except queue.Empty:
                # Heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat', 'ts': time.strftime('%H:%M:%S')})}\n\n"
    except GeneratorExit:
        unsubscribe()


# ── Singleton ─────────────────────────────────────────────────────────────────

_bus_instance: Optional[AlertBus] = None
_bus_lock = threading.Lock()


def get_alert_bus() -> AlertBus:
    global _bus_instance
    if _bus_instance is None:
        with _bus_lock:
            if _bus_instance is None:
                _bus_instance = AlertBus()
                log.info("AlertBus singleton created")
    return _bus_instance
