"""
core/event_collector/task_scheduler_monitor.py
================================================
FR04-03: Windows Task Scheduler and Automated Task Monitoring

WHAT THIS DOES:
  Two complementary layers:

  Layer 1 — Event-log watcher (Security log):
    Polls for ALL five task lifecycle Event IDs:
      EID 4698 — Scheduled task created   (HIGH — persistence)
      EID 4699 — Scheduled task deleted
      EID 4700 — Scheduled task enabled
      EID 4701 — Scheduled task disabled
      EID 4702 — Scheduled task updated   (MEDIUM — could hide payload change)

  Layer 2 — Active task inventory (win32com / schtasks):
    Every INVENTORY_INTERVAL seconds, enumerates ALL tasks in
    Task Scheduler via the COM interface (ITaskService) and stores
    a snapshot in the `task_inventory` SQLite table.
    On each cycle it diffs against the previous snapshot so that
    tasks that appeared/disappeared without generating a Security
    event (e.g. created under a different user context) are also caught.

ALERT LOGIC:
  - New task created (EID 4698 OR inventory diff) → CRITICAL alert
  - Task updated    (EID 4702 OR action/trigger hash change) → HIGH alert
  - Task enabled    (EID 4700) → MEDIUM alert
  - Task deleted    (EID 4699) or inventory disappear → MEDIUM alert
  - Task disabled   (EID 4701) → LOW alert (may be defensive action)
  - Task with suspicious path (Temp/AppData/ProgramData + cmd/powershell) → CRITICAL

REQUIREMENTS:
  pip install pywin32   (win32evtlog + win32com)

INTEGRATION (app.py):
  from core.event_collector.task_scheduler_monitor import get_task_monitor
  get_task_monitor().start()
"""

import threading
import time
import hashlib
import json
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("task_scheduler_monitor")

# How often to poll the Security event log for task events (seconds)
EVENT_POLL_INTERVAL = 5

# How often to enumerate the full task inventory (seconds)
INVENTORY_INTERVAL = 60

# Paths that suggest attacker-planted tasks
SUSPICIOUS_PATH_FRAGMENTS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\",
    "\\users\\public\\", "%temp%", "%appdata%", "%public%",
)

# Executables that are suspicious inside task actions
SUSPICIOUS_EXECUTABLES = (
    "powershell", "cmd.exe", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32", "certutil", "bitsadmin", "wmic",
)

# Task lifecycle event IDs
TASK_EVENT_IDS = {4698, 4699, 4700, 4701, 4702}

TASK_EVENT_META = {
    4698: {"label": "Task Created", "severity": "CRITICAL", "risk_score": 18},
    4699: {"label": "Task Deleted", "severity": "MEDIUM",   "risk_score": 6},
    4700: {"label": "Task Enabled",  "severity": "MEDIUM",   "risk_score": 5},
    4701: {"label": "Task Disabled", "severity": "LOW",      "risk_score": 2},
    4702: {"label": "Task Updated",  "severity": "HIGH",     "risk_score": 12},
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_suspicious_task(task_name: str, task_action: str) -> bool:
    """Return True if task name or action path looks attacker-planted."""
    combined = (task_name + " " + task_action).lower()
    if any(frag in combined for frag in SUSPICIOUS_PATH_FRAGMENTS):
        return True
    if any(exe in combined for exe in SUSPICIOUS_EXECUTABLES):
        return True
    return False


def _action_hash(action_str: str) -> str:
    return hashlib.sha256(action_str.encode("utf-8", errors="replace")).hexdigest()[:16]


def _parse_task_event(ev) -> dict:
    """
    Extract task name, author, and action from Security log event StringInserts.
    EID 4698/4702 layout:
      [0] SubjectUserSid, [1] SubjectUserName, [2] SubjectDomainName,
      [3] SubjectLogonId, [4] TaskName, [5] TaskContent (XML)
    EID 4699/4700/4701 layout: same first 5 fields; [5] may be empty.
    """
    result = {
        "task_name":   "—",
        "subject_user": "—",
        "task_content": "",
    }
    try:
        inserts = ev.StringInserts or []
        if len(inserts) > 4:
            result["task_name"] = str(inserts[4]).strip() or "—"
        if len(inserts) > 1:
            user = str(inserts[1]).strip()
            domain = str(inserts[2]).strip() if len(inserts) > 2 else ""
            result["subject_user"] = f"{domain}\\{user}" if domain else user
        if len(inserts) > 5:
            result["task_content"] = str(inserts[5])[:1000]
    except Exception as e:
        log.warning(f"Task event parse error: {e}")
    return result


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_tables():
    """Create task_events and task_inventory tables if they don't exist."""
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS task_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT,
                event_id     INTEGER,
                event_label  TEXT,
                task_name    TEXT,
                subject_user TEXT,
                severity     TEXT,
                suspicious   INTEGER DEFAULT 0,
                task_content TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS task_inventory (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_ts  TEXT,
                task_path    TEXT,
                task_name    TEXT,
                state        TEXT,
                last_run     TEXT,
                next_run     TEXT,
                author       TEXT,
                action_hash  TEXT,
                action_desc  TEXT,
                enabled      INTEGER
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Table creation failed: {e}")


def _save_task_event(ts: str, eid: int, task_name: str, subject_user: str,
                     suspicious: bool, content: str):
    meta = TASK_EVENT_META.get(eid, {"label": "Task Event", "severity": "MEDIUM", "risk_score": 5})
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            INSERT INTO task_events
                (ts, event_id, event_label, task_name, subject_user, severity, suspicious, task_content)
            VALUES (?,?,?,?,?,?,?,?)
        """, (ts, eid, meta["label"], task_name, subject_user,
              meta["severity"], int(suspicious), content))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"task_events insert failed: {e}")


def _push_alert(eid: int, task_name: str, subject_user: str, suspicious: bool, extra: str = ""):
    meta = TASK_EVENT_META.get(eid, {"label": "Task Event", "severity": "MEDIUM", "risk_score": 5})
    if suspicious:
        severity   = "CRITICAL"
        risk_score = 20
        title      = f"Suspicious scheduled task: {task_name}"
        desc       = (f"Task '{task_name}' {meta['label'].lower()} by {subject_user}. "
                      f"Action path or name matches known attacker techniques. {extra}")
    else:
        severity   = meta["severity"]
        risk_score = meta["risk_score"]
        title      = f"{meta['label']}: {task_name}"
        desc       = f"Scheduled task '{task_name}' was {meta['label'].lower()} by {subject_user}. {extra}"

    try:
        from core.pipeline.alert_bus import get_alert_bus
        get_alert_bus().push({
            "id":          int(time.time() * 1000),
            "type":        f"task_{eid}",
            "severity":    severity,
            "category":    "persistence",
            "title":       title,
            "description": desc,
            "source":      "Task Scheduler Monitor",
            "risk_score":  risk_score,
        })
    except Exception as e:
        log.warning(f"Alert push failed: {e}")


# ── Layer 1: Security Event Log watcher ──────────────────────────────────────

class TaskEventWatcher:
    """
    Polls the Windows Security event log for task lifecycle events
    (EIDs 4698–4702) and fires alerts + DB inserts on each match.
    """

    def __init__(self):
        self._stop       = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_record = 0
        self._priv_warned = False   # Suppress repeated privilege warnings

    def _seed(self):
        try:
            import win32evtlog
            h = win32evtlog.OpenEventLog(None, "Security")
            n = win32evtlog.GetNumberOfEventLogRecords(h)
            o = win32evtlog.GetOldestEventLogRecord(h)
            self._last_record = o + n - 1
            win32evtlog.CloseEventLog(h)
            log.info(f"[TaskEventWatcher] seeded at Security record #{self._last_record}")
        except Exception as e:
            err = str(e)
            if "1314" in err or "access" in err.lower() or "not held" in err.lower():
                if not self._priv_warned:
                    log.warning("[TaskEventWatcher] Security log needs Administrator — task event monitoring limited. (This message will not repeat.)")
                    self._priv_warned = True
            else:
                log.warning(f"[TaskEventWatcher] seed failed: {e}")

    def _poll(self):
        try:
            import win32evtlog
        except ImportError:
            return

        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                      win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            new_events  = []
            highest     = self._last_record

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
                    if eid in TASK_EVENT_IDS:
                        new_events.append(ev)
                else:
                    continue
                break

            if highest > self._last_record:
                self._last_record = highest

            for ev in new_events:
                self._handle(ev)

        except Exception as e:
            err = str(e)
            if ("5" in err or "access" in err.lower() or
                    "1314" in err or "not held" in err.lower()):
                if not self._priv_warned:
                    log.warning("[TaskEventWatcher] Security log requires Administrator — task scheduling events will not be monitored. (This message will not repeat.)")
                    self._priv_warned = True
            else:
                log.error(f"[TaskEventWatcher] poll error: {e}")
        finally:
            if handle:
                try:
                    import win32evtlog
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass

    def _handle(self, ev):
        eid     = ev.EventID & 0xFFFF
        ts_obj  = ev.TimeGenerated
        ts_str  = ts_obj.strftime("%Y-%m-%d %H:%M:%S") if ts_obj else datetime.now().isoformat()
        parsed  = _parse_task_event(ev)

        task_name    = parsed["task_name"]
        subject_user = parsed["subject_user"]
        content      = parsed["task_content"]
        suspicious   = _is_suspicious_task(task_name, content)

        log.info(f"[TaskEventWatcher] EID {eid} — {task_name} by {subject_user}"
                 f"{' [SUSPICIOUS]' if suspicious else ''}")

        _save_task_event(ts_str, eid, task_name, subject_user, suspicious, content)
        _push_alert(eid, task_name, subject_user, suspicious)

        # Also write to logs_security so it appears in the main log viewer
        try:
            from database.db import get_conn
            conn = get_conn()
            conn.execute("""
                INSERT INTO logs_security
                    (timestamp, date, level, source, message, event_id, raw)
                VALUES (?,?,?,?,?,?,?)
            """, (
                ts_str, ts_str[:10],
                "WARNING" if not suspicious else "CRITICAL",
                "Microsoft-Windows-Security-Auditing",
                f"[FR04-03] {TASK_EVENT_META.get(eid, {}).get('label', 'Task Event')}: "
                f"task='{task_name}' user='{subject_user}'"
                f"{' [SUSPICIOUS PATH/EXEC]' if suspicious else ''}",
                eid,
                content[:200],
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning(f"Security log insert failed: {e}")

    def _loop(self):
        log.info("[TaskEventWatcher] started — monitoring EIDs 4698-4702")
        try:
            import win32evtlog
        except ImportError:
            log.warning("[TaskEventWatcher] pywin32 not installed — layer 1 inactive")
            return

        self._seed()
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[TaskEventWatcher] loop error: {e}")
            self._stop.wait(EVENT_POLL_INTERVAL)
        log.info("[TaskEventWatcher] stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="task-event-watcher"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()


# ── Layer 2: Active task inventory via COM ────────────────────────────────────

class TaskInventoryScanner:
    """
    Enumerates all Task Scheduler tasks every INVENTORY_INTERVAL seconds
    using the ITaskService COM interface (win32com).  Diffs against the
    previous snapshot to detect additions/removals/changes that may not
    have generated a Security event.
    """

    def __init__(self):
        self._stop      = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev_snap: dict[str, dict] = {}   # task_path → snapshot row

    # ── COM enumeration ───────────────────────────────────────────────────────

    def _enum_tasks(self) -> list[dict]:
        """Return list of task dicts from Task Scheduler COM interface."""
        results = []
        try:
            import win32com.client
            ts = win32com.client.Dispatch("Schedule.Service")
            ts.Connect()
            root = ts.GetFolder("\\")
            self._walk_folder(root, results)
        except ImportError:
            log.warning("[TaskInventory] win32com not available — trying schtasks fallback")
            results = self._schtasks_fallback()
        except Exception as e:
            log.error(f"[TaskInventory] COM enumeration failed: {e}")
            results = self._schtasks_fallback()
        return results

    def _walk_folder(self, folder, results: list, depth: int = 0):
        """Recursively walk Task Scheduler folders."""
        if depth > 8:   # guard against infinite loops
            return
        try:
            tasks = folder.GetTasks(0)
            for i in range(tasks.Count):
                task = tasks.Item(i + 1)
                self._extract_task(task, folder.Path, results)
        except Exception:
            pass
        try:
            subfolders = folder.GetFolders(0)
            for i in range(subfolders.Count):
                self._walk_folder(subfolders.Item(i + 1), results, depth + 1)
        except Exception:
            pass

    def _extract_task(self, task, folder_path: str, results: list):
        """Pull fields from IRegisteredTask COM object."""
        try:
            TASK_STATE = {0: "Unknown", 1: "Disabled", 2: "Queued",
                          3: "Ready",   4: "Running"}

            name    = task.Name
            path    = task.Path
            state   = TASK_STATE.get(task.State, str(task.State))
            enabled = task.Enabled

            try:
                last_run = str(task.LastRunTime)
            except Exception:
                last_run = "—"
            try:
                next_run = str(task.NextRunTime)
            except Exception:
                next_run = "—"

            # Pull action description from task definition
            action_parts = []
            try:
                defn    = task.Definition
                author  = defn.RegistrationInfo.Author or "—"
                actions = defn.Actions
                for j in range(actions.Count):
                    act = actions.Item(j + 1)
                    try:
                        action_parts.append(f"{act.Path} {act.Arguments}".strip())
                    except Exception:
                        action_parts.append("(unknown action)")
            except Exception:
                author = "—"

            action_desc = " | ".join(action_parts) if action_parts else "—"
            a_hash      = _action_hash(action_desc)
            suspicious  = _is_suspicious_task(name, action_desc)

            results.append({
                "task_path":   path,
                "task_name":   name,
                "state":       state,
                "last_run":    last_run,
                "next_run":    next_run,
                "author":      author,
                "action_hash": a_hash,
                "action_desc": action_desc[:500],
                "enabled":     int(enabled),
                "suspicious":  suspicious,
            })
        except Exception as e:
            log.debug(f"[TaskInventory] extract_task error: {e}")

    def _schtasks_fallback(self) -> list[dict]:
        """
        Fallback: parse `schtasks /query /fo CSV /v` when win32com is unavailable.
        Returns minimal dicts.
        """
        import subprocess, csv, io
        results = []
        try:
            proc = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=30,
                creationflags=0x08000000   # CREATE_NO_WINDOW
            )
            reader = csv.DictReader(io.StringIO(proc.stdout))
            for row in reader:
                name   = row.get("TaskName", "").strip()
                status = row.get("Status", "").strip()
                action = row.get("Task To Run", "").strip()
                author = row.get("Author", "—").strip()
                if not name or name == "TaskName":
                    continue
                results.append({
                    "task_path":   name,
                    "task_name":   name.rsplit("\\", 1)[-1],
                    "state":       status,
                    "last_run":    row.get("Last Run Time", "—"),
                    "next_run":    row.get("Next Run Time", "—"),
                    "author":      author,
                    "action_hash": _action_hash(action),
                    "action_desc": action[:500],
                    "enabled":     int(status.lower() not in ("disabled", "")),
                    "suspicious":  _is_suspicious_task(name, action),
                })
        except Exception as e:
            log.warning(f"[TaskInventory] schtasks fallback failed: {e}")
        return results

    # ── Snapshot diff & persistence ───────────────────────────────────────────

    def _save_snapshot(self, tasks: list[dict]):
        """Write full snapshot to task_inventory table."""
        ts = datetime.now().isoformat()
        try:
            from database.db import get_conn
            conn = get_conn()
            # Keep only the last 5 full snapshots (5 × ~100 tasks typical)
            conn.execute("""
                DELETE FROM task_inventory WHERE id NOT IN (
                    SELECT id FROM task_inventory ORDER BY id DESC LIMIT 500
                )
            """)
            for t in tasks:
                conn.execute("""
                    INSERT INTO task_inventory
                        (snapshot_ts, task_path, task_name, state, last_run,
                         next_run, author, action_hash, action_desc, enabled)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (
                    ts, t["task_path"], t["task_name"], t["state"],
                    t["last_run"], t["next_run"], t["author"],
                    t["action_hash"], t["action_desc"], t["enabled"],
                ))
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning(f"[TaskInventory] snapshot save failed: {e}")

    def _diff(self, current: list[dict]):
        """Compare current snapshot with previous; fire alerts on changes."""
        curr_map = {t["task_path"]: t for t in current}

        # New tasks (added since last scan)
        for path, task in curr_map.items():
            if path not in self._prev_snap:
                log.info(f"[TaskInventory] NEW TASK detected (inventory diff): {path}")
                _push_alert(4698, task["task_name"], task["author"],
                            task["suspicious"], "(detected via inventory scan)")
                _save_task_event(
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    4698, task["task_name"], task["author"],
                    task["suspicious"], task["action_desc"]
                )

        # Removed tasks
        for path, task in self._prev_snap.items():
            if path not in curr_map:
                log.info(f"[TaskInventory] TASK REMOVED (inventory diff): {path}")
                _push_alert(4699, task["task_name"], task.get("author", "—"),
                            False, "(detected via inventory scan)")

        # Updated tasks (action hash changed)
        for path, task in curr_map.items():
            prev = self._prev_snap.get(path)
            if prev and prev["action_hash"] != task["action_hash"]:
                log.info(f"[TaskInventory] TASK MODIFIED (action changed): {path}")
                _push_alert(4702, task["task_name"], task["author"],
                            task["suspicious"], "(action/trigger modified — detected via inventory scan)")
                _save_task_event(
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    4702, task["task_name"], task["author"],
                    task["suspicious"], task["action_desc"]
                )

        self._prev_snap = curr_map

    def _scan(self):
        tasks = self._enum_tasks()
        log.info(f"[TaskInventory] scanned {len(tasks)} tasks")
        if self._prev_snap:      # skip diff on first run (just seed baseline)
            self._diff(tasks)
        else:
            self._prev_snap = {t["task_path"]: t for t in tasks}
            log.info(f"[TaskInventory] baseline seeded with {len(tasks)} tasks")
        self._save_snapshot(tasks)
        return tasks

    def _loop(self):
        log.info("[TaskInventory] started — enumerating tasks every "
                 f"{INVENTORY_INTERVAL}s")
        while not self._stop.is_set():
            try:
                self._scan()
            except Exception as e:
                log.error(f"[TaskInventory] scan error: {e}")
            self._stop.wait(INVENTORY_INTERVAL)
        log.info("[TaskInventory] stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="task-inventory-scanner"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def get_inventory(self) -> list[dict]:
        """Return the latest in-memory task snapshot (for API use)."""
        return list(self._prev_snap.values())


# ── Unified monitor ───────────────────────────────────────────────────────────

class TaskSchedulerMonitor:
    """
    FR04-03 — Master controller.
    Starts both the event-log watcher (Layer 1) and the
    active inventory scanner (Layer 2).

    Usage (app.py):
        from core.event_collector.task_scheduler_monitor import get_task_monitor
        get_task_monitor().start()
    """

    def __init__(self):
        _ensure_tables()
        self._event_watcher  = TaskEventWatcher()
        self._inventory      = TaskInventoryScanner()

    def start(self):
        self._event_watcher.start()
        self._inventory.start()
        log.info("[TaskSchedulerMonitor] both layers started (FR04-03)")

    def stop(self):
        self._event_watcher.stop()
        self._inventory.stop()

    def get_inventory(self) -> list[dict]:
        return self._inventory.get_inventory()


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[TaskSchedulerMonitor] = None
_lock = threading.Lock()


def get_task_monitor() -> TaskSchedulerMonitor:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = TaskSchedulerMonitor()
    return _instance
