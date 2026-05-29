"""
core/event_collector/powershell_collector.py
=============================================
FR03-06: Windows PowerShell and Command Line Activity Monitoring

WHAT THIS MONITORS:
  1. PowerShell Script Block Logging  — EID 4103, 4104
     Channel: Microsoft-Windows-PowerShell/Operational
     Captures every script block executed, including encoded/obfuscated commands.
     REQUIRES: Enable-PSScriptBlockLogging via Group Policy or registry.

  2. PowerShell Module Logging        — EID 4103
     Captures module-level pipeline execution detail.

  3. Process Creation with Command Line — EID 4688
     Channel: Security log
     Captures every new process start with full command-line arguments.
     REQUIRES: Audit Process Creation policy + command-line logging enabled.

  4. Suspicious Pattern Detection (inline, real-time):
     - Encoded commands (-EncodedCommand / -enc / -e)
     - Execution policy bypass (-ExecutionPolicy Bypass / -ep bypass)
     - Download cradles (IEX, Invoke-Expression, DownloadString, WebClient)
     - AMSI bypass keywords (amsi, AmsiUtils, AmsiScanBuffer)
     - LOLBin process launches (mshta, regsvr32, certutil, rundll32, wscript, cscript)
     - Base64-like long strings (>100 chars, high entropy)
     - Fileless execution patterns (from memory, reflection, Add-Type)

HOW TO ENABLE (Windows prerequisites):
  PowerShell Script Block Logging:
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
         /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

  Command-line auditing (required for EID 4688 to include cmdline):
    secpol.msc → Advanced Audit Policy → Detailed Tracking
               → Audit Process Creation → Success
    + reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
           /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

ARCHITECTURE:
  PowerShellCollector runs TWO background threads:
    Thread 1 — PS channel poller   (EID 4103/4104, 2s interval)
    Thread 2 — EID 4688 poller     (Security log process creation, 2s interval)

  All events → pipeline_queue → Orchestrator → DB + AlertBus

INTEGRATION:
  from core.event_collector.powershell_collector import get_ps_collector
  get_ps_collector().start()
"""

import re
import threading
import queue
import time
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("powershell_collector")

# ── Poll interval (≤3s latency budget, matches other collectors) ──────────────
POLL_INTERVAL = 2     # seconds

# ── PowerShell event log channels ────────────────────────────────────────────
PS_CHANNEL       = "Microsoft-Windows-PowerShell/Operational"
PS_ADMIN_CHANNEL = "Microsoft-Windows-PowerShell/Admin"

# ── Event IDs ─────────────────────────────────────────────────────────────────
EID_PS_PIPELINE    = 4103   # Module/pipeline execution
EID_PS_SCRIPTBLOCK = 4104   # Script block execution (most important)
EID_PS_START       = 4105   # Script started
EID_PS_STOP        = 4106   # Script stopped
EID_PROCESS_CREATE = 4688   # New process (Security log)
EID_PROCESS_EXIT   = 4689   # Process terminated

# ── Suspicious pattern signatures (FR03-06) ────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    # Encoded / obfuscated commands
    (r"-[Ee]nc(?:odedCommand)?\s+[A-Za-z0-9+/]{20,}", "ENCODED_COMMAND",     "CRITICAL"),
    (r"-[Ee]nc\s",                                      "ENCODED_FLAG",        "HIGH"),

    # Execution policy bypass
    (r"-[Ee]xecution[Pp]olicy\s+[Bb]ypass",            "EXEC_POLICY_BYPASS",  "HIGH"),
    (r"-[Ee][Pp]\s+[Bb]ypass",                         "EXEC_POLICY_BYPASS",  "HIGH"),
    (r"-[Ee]xecution[Pp]olicy\s+[Uu]nrestricted",      "EXEC_POLICY_BYPASS",  "HIGH"),

    # Download cradles
    (r"[Ii]nvoke-[Ee]xpression|IEX\s*\(",              "DOWNLOAD_CRADLE",     "CRITICAL"),
    (r"[Dd]ownload[Ss]tring|[Dd]ownload[Ff]ile",       "DOWNLOAD_CRADLE",     "CRITICAL"),
    (r"[Nn]et\.Web[Cc]lient|[Hh]ttp[Ww]eb[Rr]equest",  "DOWNLOAD_CRADLE",    "HIGH"),
    (r"[Ii]nvoke-[Ww]eb[Rr]equest|[Ii][Ww][Rr]\s",    "DOWNLOAD_CRADLE",     "HIGH"),
    (r"[Ss]tart-[Bb]its[Tt]ransfer",                   "DOWNLOAD_CRADLE",     "HIGH"),

    # AMSI bypass
    (r"[Aa]msi[Uu]tils|[Aa]msi[Ss]can[Bb]uffer",      "AMSI_BYPASS",         "CRITICAL"),
    (r"\[Rr]ef\].*[Aa]msi|amsi\.dll",                  "AMSI_BYPASS",         "CRITICAL"),
    (r"[Ss]et-[Mm]p[Pp]reference.*-[Dd]isable",        "AV_TAMPER",           "CRITICAL"),

    # Fileless / reflective execution
    (r"[Rr]eflection\.|Add-[Tt]ype\s.*-[Aa]ssembly",  "REFLECTIVE_LOAD",     "HIGH"),
    (r"\[System\.Runtime\.InteropServices",             "REFLECTIVE_LOAD",     "HIGH"),
    (r"[Mm]emory[Ss]tream|[Ff]rom[Bb]ase64",           "FILELESS_EXEC",       "HIGH"),

    # Credential theft
    (r"[Mm]imikatz|sekurlsa|lsadump|[Dd]ump[Cc]reds",  "CREDENTIAL_THEFT",    "CRITICAL"),
    (r"Invoke-[Mm]imikatz|Get-[Pp]assword[Hh]ash",     "CREDENTIAL_THEFT",    "CRITICAL"),

    # Common LOLBin patterns inside PowerShell
    (r"mshta\.exe|regsvr32\.exe|certutil\.exe",         "LOLBIN_EXEC",         "HIGH"),
    (r"wscript\.exe|cscript\.exe|rundll32\.exe",        "LOLBIN_EXEC",         "HIGH"),

    # Reverse shell indicators
    (r"[Nn]et\.[Ss]ockets|[Tt]cp[Cc]lient|[Tt]cp[Ll]istener",  "REVERSE_SHELL", "CRITICAL"),
    (r"[Cc]md\.exe.*[Cc] echo.*[Bb]ase64",              "REVERSE_SHELL",       "CRITICAL"),
]

# ── LOLBins — process names that are suspicious as parent/child (EID 4688) ────
LOLBINS = {
    "mshta.exe", "regsvr32.exe", "certutil.exe", "wscript.exe",
    "cscript.exe", "rundll32.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe",
    "xwizard.exe", "pcalua.exe", "syncappvpublishingserver.exe",
}

# ── Process names that are high-risk spawning PowerShell ──────────────────────
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "cmd.exe",
    "regsvr32.exe", "rundll32.exe", "explorer.exe",
}


def _detect_patterns(text: str) -> list:
    """
    Scan command text against all suspicious patterns.
    Returns list of (pattern_id, severity) tuples.
    """
    if not text:
        return []
    findings = []
    for pattern, pid, severity in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({"pattern": pid, "severity": severity})
    return findings


def _has_long_base64(text: str) -> bool:
    """Detect suspiciously long base64-like strings (common in encoded payloads)."""
    return bool(re.search(r"[A-Za-z0-9+/]{100,}={0,2}", text or ""))


def _classify_severity(findings: list) -> str:
    """Return highest severity from a list of pattern findings."""
    if any(f["severity"] == "CRITICAL" for f in findings):
        return "CRITICAL"
    if any(f["severity"] == "HIGH" for f in findings):
        return "HIGH"
    if findings:
        return "MEDIUM"
    return "INFO"


class PSChannelPoller:
    """
    FR03-06 — Polls Microsoft-Windows-PowerShell/Operational for
    Script Block Logging events (EID 4103/4104).

    These capture every script block executed, including:
      - Encoded commands (after decode — you see the decoded payload)
      - IEX / Invoke-Expression content
      - Module pipelines
    """

    def __init__(self, pipeline_queue: queue.Queue):
        self._queue      = pipeline_queue
        self._last_rec   = 0
        self._stop       = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._win32ok    = False
        self._events_found = 0

    def _init_win32(self) -> bool:
        if self._win32ok:
            return True
        try:
            import win32evtlog, win32evtlogutil, win32con
            self._w32   = win32evtlog
            self._w32u  = win32evtlogutil
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

    def _seed_cursor(self):
        try:
            h = self._w32.OpenEventLog(None, PS_CHANNEL)
            total  = self._w32.GetNumberOfEventLogRecords(h)
            oldest = self._w32.GetOldestEventLogRecord(h)
            self._last_rec = oldest + total - 1
            self._w32.CloseEventLog(h)
        except Exception:
            pass   # channel may not exist if PS logging disabled

    def _safe_msg(self, ev) -> str:
        try:
            msg = self._w32u.SafeFormatMessage(ev, ev.SourceName)
            return msg or ""
        except Exception:
            if ev.StringInserts:
                return " | ".join(str(s) for s in ev.StringInserts)
            return ""

    def _poll(self):
        if not self._init_win32():
            return

        try:
            handle = self._w32.OpenEventLog(None, PS_CHANNEL)
        except Exception:
            return   # channel doesn't exist → PS logging not enabled

        flags    = (self._w32.EVENTLOG_BACKWARDS_READ |
                    self._w32.EVENTLOG_SEQUENTIAL_READ)
        highest  = self._last_rec
        new_evts = []

        try:
            while True:
                batch = self._w32.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                done = False
                for ev in batch:
                    if ev.RecordNumber <= self._last_rec:
                        done = True
                        break
                    eid = ev.EventID & 0xFFFF
                    if eid not in (EID_PS_PIPELINE, EID_PS_SCRIPTBLOCK,
                                   EID_PS_START, EID_PS_STOP):
                        continue
                    if ev.RecordNumber > highest:
                        highest = ev.RecordNumber
                    msg = self._safe_msg(ev)
                    ts  = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")

                    findings = _detect_patterns(msg)
                    if _has_long_base64(msg):
                        findings.append({"pattern": "LONG_BASE64", "severity": "HIGH"})

                    evt_dict = {
                        "timestamp":  ts,
                        "date":       ts[:10],
                        "level":      "CRITICAL" if findings else self._TYPE_MAP.get(ev.EventType, "INFO"),
                        "source":     "PowerShell",
                        "message":    msg[:3000],
                        "event_id":   eid,
                        "record_number": ev.RecordNumber,
                        "category":   "powershell",
                        "channel":    PS_CHANNEL,
                        "collected_at": datetime.now().isoformat(),
                        "ps_findings":  findings,
                        "ps_severity":  _classify_severity(findings),
                        "suspicious":   len(findings) > 0,
                        "raw":          msg[:500],
                    }
                    new_evts.append(evt_dict)
                if done:
                    break
        except Exception as e:
            log.debug(f"PSChannelPoller poll error: {e}")
        finally:
            try:
                self._w32.CloseEventLog(handle)
            except Exception:
                pass

        if highest > self._last_rec:
            self._last_rec = highest

        for evt in new_evts:
            try:
                self._queue.put_nowait({"event": evt, "category": "powershell"})
                self._events_found += 1
            except queue.Full:
                log.warning("PSChannelPoller: pipeline queue full — dropped 1 event")

        if new_evts:
            suspicious_count = sum(1 for e in new_evts if e["suspicious"])
            log.info(f"[PS] {len(new_evts)} script-block events → queue "
                     f"({suspicious_count} suspicious)")

    def _loop(self):
        log.info("[PS] PowerShell script-block poller started")
        if self._init_win32():
            self._seed_cursor()
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[PS] loop error: {e}")
            self._stop.wait(POLL_INTERVAL)
        log.info("[PS] PowerShell script-block poller stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ps-scriptblock-poller")
        self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


class ProcessCreationPoller:
    """
    FR03-06 — Polls Security log for EID 4688 (process creation).

    When command-line auditing is enabled this captures the full
    command line of every new process — including:
      - powershell.exe -enc ... -ep bypass ...
      - cmd.exe /c ...
      - LOLBin executions
      - Suspicious child processes spawned by Office apps
    """

    def __init__(self, pipeline_queue: queue.Queue):
        self._queue      = pipeline_queue
        self._last_rec   = 0
        self._stop       = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._win32ok    = False
        self._events_found = 0

    def _init_win32(self) -> bool:
        if self._win32ok:
            return True
        try:
            import win32evtlog, win32evtlogutil, win32con
            self._w32  = win32evtlog
            self._w32u = win32evtlogutil
            self._win32ok = True
            return True
        except ImportError:
            return False

    def _seed_cursor(self):
        try:
            h = self._w32.OpenEventLog(None, "Security")
            total  = self._w32.GetNumberOfEventLogRecords(h)
            oldest = self._w32.GetOldestEventLogRecord(h)
            self._last_rec = oldest + total - 1
            self._w32.CloseEventLog(h)
        except Exception:
            pass

    def _safe_msg(self, ev) -> str:
        try:
            msg = self._w32u.SafeFormatMessage(ev, ev.SourceName)
            return msg or ""
        except Exception:
            if ev.StringInserts:
                return " | ".join(str(s) for s in ev.StringInserts)
            return ""

    def _parse_4688(self, msg: str) -> dict:
        """Extract structured fields from EID 4688 message text."""
        fields = {}
        # New Process Name
        m = re.search(r"New Process Name:\s+(.+)", msg, re.IGNORECASE)
        if m:
            fields["process_name"] = m.group(1).strip()
        # Creator Process Name (parent)
        m = re.search(r"Creator Process Name:\s+(.+)", msg, re.IGNORECASE)
        if m:
            fields["parent_process"] = m.group(1).strip()
        # Process Command Line
        m = re.search(r"Process Command Line:\s+(.+)", msg, re.IGNORECASE)
        if m:
            fields["command_line"] = m.group(1).strip()
        # Subject User Name
        m = re.search(r"Subject:\s+.*?Account Name:\s+(\S+)", msg, re.IGNORECASE | re.DOTALL)
        if m:
            fields["username"] = m.group(1).strip()
        return fields

    def _assess_4688(self, fields: dict) -> tuple:
        """
        Return (findings, severity, suspicious) for a process creation event.
        Checks command line patterns AND LOLBin/parent relationships.
        """
        findings = []
        proc     = (fields.get("process_name") or "").lower()
        parent   = (fields.get("parent_process") or "").lower()
        cmdline  = fields.get("command_line") or ""

        # Check command line against patterns
        findings.extend(_detect_patterns(cmdline))
        if _has_long_base64(cmdline):
            findings.append({"pattern": "LONG_BASE64", "severity": "HIGH"})

        # LOLBin process launch
        proc_base = proc.split("\\")[-1]
        if proc_base in LOLBINS:
            findings.append({"pattern": "LOLBIN_PROCESS", "severity": "HIGH",
                              "detail": f"LOLBin: {proc_base}"})

        # Suspicious parent spawning PowerShell or cmd
        parent_base = parent.split("\\")[-1]
        if parent_base in SUSPICIOUS_PARENTS and any(
            x in proc_base for x in ("powershell", "cmd.exe", "wscript", "mshta")
        ):
            findings.append({"pattern": "SUSPICIOUS_PARENT_CHILD",
                              "severity": "CRITICAL",
                              "detail": f"{parent_base} → {proc_base}"})

        severity = _classify_severity(findings)
        return findings, severity, len(findings) > 0

    def _poll(self):
        if not self._init_win32():
            return

        try:
            handle = self._w32.OpenEventLog(None, "Security")
        except Exception:
            return

        flags    = (self._w32.EVENTLOG_BACKWARDS_READ |
                    self._w32.EVENTLOG_SEQUENTIAL_READ)
        highest  = self._last_rec
        new_evts = []

        try:
            while True:
                batch = self._w32.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                done = False
                for ev in batch:
                    if ev.RecordNumber <= self._last_rec:
                        done = True
                        break
                    eid = ev.EventID & 0xFFFF
                    if eid != EID_PROCESS_CREATE:
                        continue
                    if ev.RecordNumber > highest:
                        highest = ev.RecordNumber

                    try:
                        ts  = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                    except Exception:
                        ts  = datetime.now().isoformat()
                    msg = self._safe_msg(ev)
                    fields = self._parse_4688(msg)
                    findings, severity, suspicious = self._assess_4688(fields)

                    # Only push to queue if suspicious OR if it's PowerShell/cmd
                    proc_base = (fields.get("process_name") or "").lower().split("\\")[-1]
                    is_ps_related = any(x in proc_base for x in
                                        ("powershell", "pwsh", "cmd.exe", "wscript",
                                         "cscript", "mshta", "rundll32"))
                    if not suspicious and not is_ps_related:
                        continue   # skip boring process creation noise

                    evt_dict = {
                        "timestamp":    ts,
                        "date":         ts[:10],
                        "level":        severity if suspicious else "INFO",
                        "source":       "Microsoft-Windows-Security-Auditing",
                        "message":      msg[:3000],
                        "event_id":     EID_PROCESS_CREATE,
                        "record_number": ev.RecordNumber,
                        "category":     "powershell",
                        "channel":      "Security",
                        "collected_at": datetime.now().isoformat(),
                        "process_name":   fields.get("process_name", ""),
                        "parent_process": fields.get("parent_process", ""),
                        "command_line":   fields.get("command_line", ""),
                        "ps_username":    fields.get("username", ""),
                        "ps_findings":    findings,
                        "ps_severity":    severity,
                        "suspicious":     suspicious,
                        "raw":            msg[:500],
                    }
                    new_evts.append(evt_dict)
                if done:
                    break
        except Exception as e:
            log.debug(f"ProcessCreationPoller poll error: {e}")
        finally:
            try:
                self._w32.CloseEventLog(handle)
            except Exception:
                pass

        if highest > self._last_rec:
            self._last_rec = highest

        for evt in new_evts:
            try:
                self._queue.put_nowait({"event": evt, "category": "powershell"})
                self._events_found += 1
            except queue.Full:
                log.warning("ProcessCreationPoller: pipeline queue full — dropped 1 event")

        if new_evts:
            suspicious_count = sum(1 for e in new_evts if e["suspicious"])
            log.info(f"[PS:4688] {len(new_evts)} process events → queue "
                     f"({suspicious_count} suspicious)")

    def _loop(self):
        log.info("[PS:4688] Process creation poller started (FR03-06)")
        if self._init_win32():
            self._seed_cursor()
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"[PS:4688] loop error: {e}")
            self._stop.wait(POLL_INTERVAL)
        log.info("[PS:4688] Process creation poller stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ps-process-creation-poller")
        self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


class PowerShellCollector:
    """
    FR03-06 — Master controller for PowerShell and command-line monitoring.

    Manages two pollers:
      1. PSChannelPoller       — Script Block Logging (EID 4103/4104)
      2. ProcessCreationPoller — Process creation with command line (EID 4688)

    Both share the same pipeline queue and feed the Orchestrator.

    Usage:
        from core.event_collector.powershell_collector import get_ps_collector
        get_ps_collector().start()
    """

    def __init__(self):
        self._queue   = queue.Queue(maxsize=2000)
        self._ps      = PSChannelPoller(self._queue)
        self._proc    = ProcessCreationPoller(self._queue)
        self._workers: list[threading.Thread] = []
        self._running = False
        self._lock    = threading.Lock()
        self._total_processed = 0

    def start(self, num_workers: int = 2):
        with self._lock:
            if self._running:
                return
            self._running = True

        self._ps.start()
        self._proc.start()
        log.info("✅ FR03-06: PowerShellCollector started (ScriptBlock + ProcessCreation pollers)")

        for i in range(num_workers):
            t = threading.Thread(target=self._pipeline_worker,
                                 args=(i,), daemon=True,
                                 name=f"ps-worker-{i}")
            t.start()
            self._workers.append(t)

    def stop(self):
        with self._lock:
            self._running = False
        self._ps.stop()
        self._proc.stop()

    @property
    def alive(self) -> bool:
        return self._ps.alive or self._proc.alive

    def _pipeline_worker(self, worker_id: int):
        """Drain queue → Orchestrator pipeline."""
        try:
            from core.pipeline.orchestrator import get_pipeline
            pipeline = get_pipeline()
        except Exception as e:
            log.error(f"PS worker {worker_id}: pipeline init failed: {e}")
            return

        while self._running:
            try:
                item = self._queue.get(timeout=3)
                if item is None:
                    break
                event    = item["event"]
                category = item.get("category", "powershell")
                try:
                    pipeline.process(event, category)
                    self._total_processed += 1
                except Exception as e:
                    _direct_insert_ps(event)
                    log.warning(f"PS worker {worker_id}: pipeline error, direct insert: {e}")
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                log.error(f"PS worker {worker_id} error: {e}")

    def stats(self) -> dict:
        return {
            "running":           self._running,
            "queue_size":        self._queue.qsize(),
            "total_processed":   self._total_processed,
            "ps_events_found":   self._ps._events_found,
            "proc_events_found": self._proc._events_found,
            "ps_poller_alive":   self._ps.alive,
            "proc_poller_alive": self._proc.alive,
        }


def _direct_insert_ps(event: dict):
    """Emergency fallback — insert directly to logs_powershell table."""
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            INSERT OR IGNORE INTO logs_powershell
                (timestamp, date, level, source, message, event_id, raw)
            VALUES (?,?,?,?,?,?,?)
        """, (
            event.get("timestamp"), event.get("date"), event.get("level"),
            event.get("source"), event.get("message"),
            event.get("event_id"), event.get("raw"),
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── Singleton ─────────────────────────────────────────────────────────────────
_instance: Optional[PowerShellCollector] = None
_init_lock = threading.Lock()


def get_ps_collector() -> PowerShellCollector:
    """Return the global PowerShellCollector singleton. Thread-safe."""
    global _instance
    if _instance is None:
        with _init_lock:
            if _instance is None:
                _instance = PowerShellCollector()
    return _instance
