"""
core/event_collector/service_monitor.py
=========================================
FR04-05: Windows Services Status and Dependency Monitoring

WHAT THIS DOES:
  Two complementary layers — reactive event detection + active polling.

  Layer 1 — Event-log watcher (System log):
    Polls for all service lifecycle events:
      EID 7000 — Service failed to start
      EID 7001 — Service dependency failure
      EID 7009 — Service start timeout
      EID 7022 — Service hung on start
      EID 7023 — Service terminated with error
      EID 7031 — Service terminated unexpectedly
      EID 7034 — Service crashed / exited unexpectedly
      EID 7035 — Service control (start/stop) request
      EID 7036 — Service entered running/stopped state
      EID 7040 — Service start type changed   (may be attacker disabling security)
      EID 7045 — New service installed         (persistence/malware indicator)

  Layer 2 — Active service status polling (win32service):
    Every SERVICE_POLL_INTERVAL seconds, enumerates ALL installed Windows
    services via win32service.EnumServicesStatus() and:
      - Stores a full snapshot in `service_inventory` SQLite table
      - Diffs against previous snapshot:
          * Service stopped unexpectedly → CRITICAL alert
          * New service appeared → HIGH alert (redundant with EID 7045 but
            catches services that bypass the event log)
          * Service start type changed → MEDIUM alert
      - Tracks dependency health: if a RUNNING service depends on a
        STOPPED service, that mismatch is flagged as a dependency warning.

ALERT SEVERITY MAP:
  CRITICAL — unexpected stop of a previously running service
  CRITICAL — new service with suspicious path (Temp/AppData/cmd/powershell)
  HIGH     — new service installed (clean path)
  HIGH     — service start type changed from Automatic to Disabled
  MEDIUM   — service crash / dependency failure / timeout
  LOW      — expected state changes (service started, stopped on demand)

REQUIREMENTS:
  pip install pywin32

INTEGRATION (app.py):
  from core.event_collector.service_monitor import get_service_monitor
  get_service_monitor().start()
"""

import threading
import time
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("service_monitor")

# How often to poll the System event log for service events (seconds)
EVENT_POLL_INTERVAL = 5

# How often to enumerate all services for live status (seconds)
SERVICE_POLL_INTERVAL = 30

# Service Event IDs to watch in the System log
SERVICE_EVENT_IDS = {7000, 7001, 7009, 7022, 7023, 7031, 7034, 7035, 7036, 7040, 7045}

SERVICE_EVENT_META = {
    7000: {"label": "Service Failed to Start",        "severity": "HIGH",     "risk_score": 10},
    7001: {"label": "Service Dependency Failure",      "severity": "HIGH",     "risk_score": 10},
    7009: {"label": "Service Start Timeout",           "severity": "MEDIUM",   "risk_score": 6},
    7022: {"label": "Service Hung on Start",           "severity": "MEDIUM",   "risk_score": 6},
    7023: {"label": "Service Terminated with Error",   "severity": "HIGH",     "risk_score": 10},
    7031: {"label": "Service Terminated Unexpectedly", "severity": "HIGH",     "risk_score": 12},
    7034: {"label": "Service Crashed",                 "severity": "HIGH",     "risk_score": 12},
    7035: {"label": "Service Control Request",         "severity": "LOW",      "risk_score": 1},
    7036: {"label": "Service State Change",            "severity": "LOW",      "risk_score": 1},
    7040: {"label": "Service Start Type Changed",      "severity": "HIGH",     "risk_score": 14},
    7045: {"label": "New Service Installed",           "severity": "CRITICAL", "risk_score": 18},
}

# High-value services whose unexpected stop should always alert at CRITICAL
CRITICAL_SERVICES = {
    "windefend", "mpssvc", "eventlog", "seclogon", "samss",
    "lsass", "cryptsvc", "wuauserv", "bits", "rpcss",
    "lanmanworkstation", "lanmanserver", "dnscache",
}

# Suspicious paths in service binaries
SUSPICIOUS_SVC_PATHS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\",
    "\\users\\public\\", "%temp%", "%appdata%",
    "powershell", "cmd.exe", "wscript", "cscript", "mshta",
)

# win32service state constants (imported lazily)
_SVC_STATES = {
    1: "STOPPED",
    2: "START_PENDING",
    3: "STOP_PENDING",
    4: "RUNNING",
    5: "CONTINUE_PENDING",
    6: "PAUSE_PENDING",
    7: "PAUSED",
}

_SVC_START_TYPES = {
    0: "BOOT",
    1: "SYSTEM",
    2: "AUTOMATIC",
    3: "MANUAL",
    4: "DISABLED",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_suspicious_service(svc_name: str, binary_path: str) -> bool:
    combined = (svc_name + " " + binary_path).lower()
    return any(frag in combined for frag in SUSPICIOUS_SVC_PATHS)


def _is_critical_service(svc_name: str) -> bool:
    return svc_name.lower() in CRITICAL_SERVICES


def _parse_service_event(ev) -> dict:
    """
    Extract service name and detail from System log event StringInserts.
    EID 7045 layout: [0] ServiceName [1] ServiceFileName [2] ServiceType
                     [3] ServiceStartType [4] ServiceAccount
    EID 7000/7001:   [0] ServiceName [1] detail...
    EID 7040:        [0] ServiceName [1] OldStartType [2] NewStartType [3] Account
    """
    result = {"service_name": "—", "detail": ""}
    try:
        inserts = ev.StringInserts or []
        if inserts:
            result["service_name"] = str(inserts[0]).strip() or "—"
        if len(inserts) > 1:
            result["detail"] = " | ".join(str(s) for s in inserts[1:])[:500]
    except Exception as e:
        log.debug(f"Service event parse error: {e}")
    return result


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_tables():
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS service_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT,
                event_id     INTEGER,
                event_label  TEXT,
                service_name TEXT,
                severity     TEXT,
                suspicious   INTEGER DEFAULT 0,
                detail       TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS service_inventory (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_ts  TEXT,
                service_name TEXT,
                display_name TEXT,
                state        TEXT,
                start_type   TEXT,
                binary_path  TEXT,
                description  TEXT,
                pid          INTEGER
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Service table creation failed: {e}")


def _save_service_event(ts, eid, svc_name, suspicious, detail):
    meta = SERVICE_EVENT_META.get(eid, {"label": "Service Event", "severity": "MEDIUM"})
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            INSERT INTO service_events
                (ts, event_id, event_label, service_name, severity, suspicious, detail)
            VALUES (?,?,?,?,?,?,?)
        """, (ts, eid, meta["label"], svc_name, meta["severity"], int(suspicious), detail))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"service_events insert failed: {e}")


def _push_alert(eid: int, svc_name: str, suspicious: bool,
                override_sev: str = None, extra: str = ""):
    meta = SERVICE_EVENT_META.get(eid, {"label": "Service Event", "severity": "MEDIUM", "risk_score": 5})
    severity   = override_sev or ("CRITICAL" if suspicious else meta["severity"])
    risk_score = 20 if suspicious else meta["risk_score"]
    label      = meta["label"]

    title = (f"Suspicious service activity: {svc_name}"
             if suspicious else f"{label}: {svc_name}")
    desc  = (f"Service '{svc_name}': {label}. "
             f"{'Binary path matches attacker technique. ' if suspicious else ''}{extra}").strip()

    try:
        from core.pipeline.alert_bus import get_alert_bus
        get_alert_bus().push({
            "id":          int(time.time() * 1000),
            "type":        f"service_{eid}",
            "severity":    severity,
            "category":    "system",
            "title":       title,
            "description": desc,
            "source":      "Service Monitor",
            "risk_score":  risk_score,
        })
    except Exception as e:
        log.warning(f"Alert push failed: {e}")


# ── Layer 1: System Event Log watcher ─────────────────────────────────────────

class ServiceEventWatcher:
    """
    Polls the System event log for service-related Event IDs
    and fires alerts + DB inserts for each match.
    """

    def __init__(self):
        self._stop        = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_record = 0

    def _seed(self):
        try:
            import win32evtlog
            h = win32evtlog.OpenEventLog(None, "System")
            n = win32evtlog.GetNumberOfEventLogRecords(h)
            o = win32evtlog.GetOldestEventLogRecord(h)
            self._last_record = o + n - 1
            win32evtlog.CloseEventLog(h)
            log.info(f"[ServiceEventWatcher] seeded at System record #{self._last_record}")
        except Exception as e:
            log.warning(f"[ServiceEventWatcher] seed failed: {e}")

    def _poll(self):
        try:
            import win32evtlog
        except ImportError:
            return

        handle = None
        try:
            handle   = win32evtlog.OpenEventLog(None, "System")
            flags    = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                        win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            new_evts = []
            highest  = self._last_record

            while True:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for ev in batch:
                    rec = ev.RecordNumber
                    if rec <= self._last_record:
                        break
                    if rec > highest:
                        highest = rec
                    eid = ev.EventID & 0xFFFF
                    if eid in SERVICE_EVENT_IDS:
                        new_evts.append(ev)
                else:
                    continue
                break

            if highest > self._last_record:
                self._last_record = highest

            for ev in new_evts:
                self._handle(ev)

        except Exception as e:
            err = str(e)
            if "5" not in err and "access" not in err.lower():
                log.error(f"[ServiceEventWatcher] poll error: {e}")
        finally:
            if handle:
                try:
                    import win32evtlog
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass

    def _handle(self, ev):
        eid      = ev.EventID & 0xFFFF
        ts_obj   = ev.TimeGenerated
        ts_str   = ts_obj.strftime("%Y-%m-%d %H:%M:%S") if ts_obj else datetime.now().isoformat()
        parsed   = _parse_service_event(ev)
        svc_name = parsed["service_name"]
        detail   = parsed["detail"]

        # Elevate severity for critical security services stopping unexpectedly
        override_sev = None
        if eid in {7031, 7034, 7023} and _is_critical_service(svc_name):
            override_sev = "CRITICAL"

        suspicious = (eid == 7045 and _is_suspicious_service(svc_name, detail))

        log.info(f"[ServiceEventWatcher] EID {eid} — {svc_name}"
                 f"{' [SUSPICIOUS]' if suspicious else ''}")

        # Only alert for meaningful events (skip noisy 7035/7036)
        if eid not in {7035, 7036}:
            _push_alert(eid, svc_name, suspicious, override_sev, detail)

        _save_service_event(ts_str, eid, svc_name, suspicious, detail)

        # Mirror important events to logs_system for unified log viewer
        if eid not in {7035, 7036}:
            try:
                from database.db import get_conn
                meta  = SERVICE_EVENT_META.get(eid, {})
                conn  = get_conn()
                conn.execute("""
                    INSERT INTO logs_system
                        (timestamp, date, level, source, message, event_id, raw)
                    VALUES (?,?,?,?,?,?,?)
                """, (
                    ts_str, ts_str[:10],
                    "CRITICAL" if override_sev == "CRITICAL" or suspicious else "WARNING",
                    "Service Control Manager",
                    f"[FR04-05] {meta.get('label', 'Service event')}: "
                    f"service='{svc_name}'"
                    f"{' [SUSPICIOUS BINARY]' if suspicious else ''}"
                    f" | {detail[:200]}",
                    eid,
                    detail[:200],
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                log.warning(f"System log insert failed: {e}")

    def _loop(self):
        log.info("[ServiceEventWatcher] started — monitoring service EIDs")
        try:
            import win32evtlog
        except ImportError:
            log.warning("[ServiceEventWatcher] pywin32 not installed — layer 1 inactive")
            return

        self._seed()
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[ServiceEventWatcher] loop error: {e}")
            self._stop.wait(EVENT_POLL_INTERVAL)
        log.info("[ServiceEventWatcher] stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="service-event-watcher"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()


# ── Layer 2: Active service status polling ────────────────────────────────────

class ServiceStatusPoller:
    """
    Enumerates all Windows services every SERVICE_POLL_INTERVAL seconds
    via win32service.EnumServicesStatus(Ex).
    Diffs against the previous snapshot to detect:
      - Unexpected service stops
      - New services
      - Start-type changes (e.g. Automatic → Disabled)
      - Dependency mismatches (running service whose dependency is stopped)
    """

    def __init__(self):
        self._stop      = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev_snap: dict[str, dict] = {}

    # ── Enumeration ───────────────────────────────────────────────────────────

    def _enum_services(self) -> list[dict]:
        results = []
        try:
            import win32service, win32con

            # Use ServicesActive (None = local machine) with explicit str args
            scm = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
            )
            try:
                # EnumServicesStatusEx returns a list of dicts on pywin32
                # Some pywin32 builds require the resumeHandle arg explicitly
                try:
                    svc_list = win32service.EnumServicesStatusEx(
                        scm,
                        win32service.SC_ENUM_PROCESS_INFO,
                        win32service.SERVICE_WIN32,
                        win32service.SERVICE_STATE_ALL,
                        None,   # groupName — None = all groups (avoids int→Unicode bug)
                    )
                except TypeError:
                    # Older pywin32 build — try without groupName arg
                    svc_list = win32service.EnumServicesStatusEx(
                        scm,
                        win32service.SC_ENUM_PROCESS_INFO,
                        win32service.SERVICE_WIN32,
                        win32service.SERVICE_STATE_ALL,
                    )
                for svc in svc_list:
                    name    = svc["ServiceName"]
                    display = svc["DisplayName"]
                    status  = svc["CurrentState"]
                    pid     = svc.get("ProcessId", 0)

                    # Get config (binary path, start type, description)
                    binary_path = "—"
                    start_type  = "—"
                    description = "—"
                    deps        = []
                    try:
                        handle = win32service.OpenService(
                            scm, name, win32service.SERVICE_QUERY_CONFIG
                        )
                        config = win32service.QueryServiceConfig(handle)
                        binary_path = config[3] or "—"
                        start_type  = _SVC_START_TYPES.get(config[1], str(config[1]))
                        # Dependencies list
                        raw_deps = config[6] or []
                        deps = [d for d in raw_deps if d]
                        try:
                            desc_buf = win32service.QueryServiceConfig2(
                                handle, win32service.SERVICE_CONFIG_DESCRIPTION
                            )
                            description = desc_buf or "—"
                        except Exception:
                            pass
                        win32service.CloseServiceHandle(handle)
                    except Exception:
                        pass

                    results.append({
                        "service_name": name,
                        "display_name": display,
                        "state":        _SVC_STATES.get(status, str(status)),
                        "state_code":   status,
                        "start_type":   start_type,
                        "binary_path":  binary_path[:400],
                        "description":  str(description)[:300],
                        "pid":          pid,
                        "dependencies": deps,
                        "suspicious":   _is_suspicious_service(name, binary_path),
                        "is_critical":  _is_critical_service(name),
                    })
            finally:
                win32service.CloseServiceHandle(scm)

        except ImportError:
            log.warning("[ServicePoller] win32service not available — falling back to sc query")
            results = self._sc_query_fallback()
        except Exception as e:
            # Only log once to avoid terminal spam
            if not getattr(self, "_enum_err_logged", False):
                log.warning(f"[ServicePoller] Service enumeration unavailable: {e} — falling back to sc query")
                self._enum_err_logged = True
            results = self._sc_query_fallback()

        return results

    def _sc_query_fallback(self) -> list[dict]:
        """Parse `sc query type= all state= all` as a last resort."""
        import subprocess, re
        results = []
        try:
            proc = subprocess.run(
                ["sc", "query", "type=", "all", "state=", "all"],
                capture_output=True, text=True, timeout=30,
                creationflags=0x08000000
            )
            blocks = proc.stdout.split("\n\n")
            for block in blocks:
                name_m  = re.search(r"SERVICE_NAME:\s+(.+)", block)
                state_m = re.search(r"STATE\s*:\s+\d+\s+(\w+)", block)
                if name_m:
                    results.append({
                        "service_name": name_m.group(1).strip(),
                        "display_name": name_m.group(1).strip(),
                        "state":        state_m.group(1).strip() if state_m else "UNKNOWN",
                        "state_code":   0,
                        "start_type":   "—",
                        "binary_path":  "—",
                        "description":  "—",
                        "pid":          0,
                        "dependencies": [],
                        "suspicious":   False,
                        "is_critical":  _is_critical_service(name_m.group(1).strip()),
                    })
        except Exception as e:
            log.warning(f"[ServicePoller] sc query fallback failed: {e}")
        return results

    # ── Snapshot persistence ──────────────────────────────────────────────────

    def _save_snapshot(self, services: list[dict]):
        ts = datetime.now().isoformat()
        try:
            from database.db import get_conn
            conn = get_conn()
            conn.execute("""
                DELETE FROM service_inventory WHERE id NOT IN (
                    SELECT id FROM service_inventory ORDER BY id DESC LIMIT 1000
                )
            """)
            for s in services:
                conn.execute("""
                    INSERT INTO service_inventory
                        (snapshot_ts, service_name, display_name, state,
                         start_type, binary_path, description, pid)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (
                    ts, s["service_name"], s["display_name"], s["state"],
                    s["start_type"], s["binary_path"], s["description"], s["pid"],
                ))
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning(f"[ServicePoller] snapshot save failed: {e}")

    # ── Diff & dependency check ───────────────────────────────────────────────

    def _diff(self, current: list[dict]):
        curr_map = {s["service_name"]: s for s in current}

        # Check for unexpected stops and start-type changes
        for name, svc in curr_map.items():
            prev = self._prev_snap.get(name)

            if prev is None:
                # Brand-new service — also covered by EID 7045 but catch here too
                if svc["suspicious"]:
                    _push_alert(7045, name, True,
                                extra="(detected via active service poll)")
                else:
                    log.info(f"[ServicePoller] new service detected: {name}")
                    _push_alert(7045, name, False,
                                extra="(detected via active service poll)")
                continue

            # Running → Stopped (unexpected for critical services)
            if (prev["state"] == "RUNNING" and svc["state"] == "STOPPED"):
                override = "CRITICAL" if svc["is_critical"] else None
                log.warning(f"[ServicePoller] service stopped unexpectedly: {name}")
                _push_alert(7031, name, svc["suspicious"], override,
                            f"Service transitioned RUNNING → STOPPED. "
                            f"{'CRITICAL system service affected.' if svc['is_critical'] else ''}")

            # Start-type change (e.g. Automatic → Disabled)
            if prev["start_type"] != svc["start_type"] and svc["start_type"] not in ("—", ""):
                log.warning(f"[ServicePoller] start type changed: {name} "
                            f"{prev['start_type']} → {svc['start_type']}")
                override = "CRITICAL" if svc["is_critical"] else None
                _push_alert(7040, name, svc["suspicious"], override,
                            f"Start type changed from {prev['start_type']} "
                            f"to {svc['start_type']}.")

        self._prev_snap = curr_map

    def _check_dependency_health(self, services: list[dict]):
        """
        Flag running services whose declared dependencies are stopped.
        This surfaces broken dependency chains proactively.
        """
        svc_map = {s["service_name"].lower(): s for s in services}
        for svc in services:
            if svc["state"] != "RUNNING":
                continue
            for dep in svc.get("dependencies", []):
                dep_lower = dep.lower()
                dep_svc   = svc_map.get(dep_lower)
                if dep_svc and dep_svc["state"] == "STOPPED":
                    log.warning(
                        f"[ServicePoller] dependency mismatch: "
                        f"{svc['service_name']} is RUNNING but depends on "
                        f"{dep} which is STOPPED"
                    )
                    try:
                        from core.pipeline.alert_bus import get_alert_bus
                        get_alert_bus().push({
                            "id":          int(time.time() * 1000),
                            "type":        "service_dep_broken",
                            "severity":    "HIGH",
                            "category":    "system",
                            "title":       f"Broken service dependency: {svc['service_name']}",
                            "description": (
                                f"Service '{svc['service_name']}' is RUNNING but its dependency "
                                f"'{dep}' is STOPPED. This may cause instability or silent failures."
                            ),
                            "source":      "Service Monitor",
                            "risk_score":  10,
                        })
                    except Exception as e:
                        log.warning(f"Dependency alert push failed: {e}")

    def _loop(self):
        log.info(f"[ServicePoller] started — polling every {SERVICE_POLL_INTERVAL}s")
        while not self._stop.is_set():
            try:
                services = self._enum_services()
                log.info(f"[ServicePoller] enumerated {len(services)} services")
                if self._prev_snap:
                    self._diff(services)
                    self._check_dependency_health(services)
                else:
                    # First run — seed baseline, no diff yet
                    self._prev_snap = {s["service_name"]: s for s in services}
                    log.info(f"[ServicePoller] baseline seeded with {len(services)} services")
                self._save_snapshot(services)
            except Exception as e:
                log.error(f"[ServicePoller] poll loop error: {e}")
            self._stop.wait(SERVICE_POLL_INTERVAL)
        log.info("[ServicePoller] stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="service-status-poller"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def get_snapshot(self) -> list[dict]:
        return list(self._prev_snap.values())


# ── Unified monitor ───────────────────────────────────────────────────────────

class ServiceMonitor:
    """
    FR04-05 — Master controller.
    Starts both the event-log watcher (Layer 1) and the active
    service status poller (Layer 2).

    Usage (app.py):
        from core.event_collector.service_monitor import get_service_monitor
        get_service_monitor().start()
    """

    def __init__(self):
        _ensure_tables()
        self._event_watcher = ServiceEventWatcher()
        self._poller        = ServiceStatusPoller()

    def start(self):
        self._event_watcher.start()
        self._poller.start()
        log.info("[ServiceMonitor] both layers started (FR04-05)")

    def stop(self):
        self._event_watcher.stop()
        self._poller.stop()

    def get_snapshot(self) -> list[dict]:
        """Return latest in-memory service inventory for API use."""
        return self._poller.get_snapshot()


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[ServiceMonitor] = None
_lock = threading.Lock()


def get_service_monitor() -> ServiceMonitor:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = ServiceMonitor()
    return _instance
