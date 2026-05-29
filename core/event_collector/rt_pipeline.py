"""
core/event_collector/rt_pipeline.py
======================================
FR01-06: Real-Time Processing ≤3 Second Latency

Master coordinator that starts and monitors all collectors:
  FR01-01/02: StreamCollector     — Application/System/Security/WinUpdate
  FR01-03:    PerfMonitor         — CPU/RAM/Disk/Network (every 3s)
  FR01-04:    DefenderCollector   — Malware/AV events (≤3s)
  FR01-05:    FirewallCollector   — pfirewall.log + firewall EIDs (≤3s)
  FR09-03:    DnsClientCollector  — DNS-Client/Operational + System EID 1014
  FR09-04:    SmbCollector        — SMB EIDs 5140-5145 + SMBServer channels
  FR09-06:    PsRemotingCollector — WinRM/Operational + PS/Operational
"""

import threading
import time
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("rt_pipeline")


class RTPipeline:
    """
    Master real-time pipeline controller.
    Starts and monitors all collectors. Restarts any that crash.
    """

    def __init__(self):
        self._running    = False
        self._lock       = threading.Lock()
        self._watchdog: Optional[threading.Thread] = None
        self._stop       = threading.Event()
        self._start_time: Optional[float] = None
        self._collectors = {}

    def start(self):
        with self._lock:
            if self._running:
                log.warning("RT pipeline already running")
                return
            self._running    = True
            self._start_time = time.time()

        log.info("=" * 60)
        log.info("Starting Real-Time Pipeline (FR01-01 through FR09-06)")
        log.info("=" * 60)

        # ── FR01-01/02: Stream Collector ──────────────────────────────────────
        try:
            from core.event_collector.stream_collector import get_stream_collector
            sc = get_stream_collector()
            sc.start(num_workers=3)
            self._collectors["stream"] = sc
            log.info("✅ FR01-01/02: StreamCollector started (3 channels, 3 workers)")
        except Exception as e:
            log.error(f"❌ FR01-01/02: StreamCollector failed to start: {e}")

        # ── FR01-03: Performance Monitor ──────────────────────────────────────
        try:
            from core.event_collector.perf_monitor import get_perf_monitor
            pm = get_perf_monitor()
            pm.start()
            self._collectors["perf"] = pm
            log.info("✅ FR01-03: PerfMonitor started (CPU/RAM/Disk/Network)")
        except Exception as e:
            log.error(f"❌ FR01-03: PerfMonitor failed to start: {e}")

        # ── FR01-04: Defender Collector ───────────────────────────────────────
        try:
            from core.event_collector.defender_collector import get_defender_collector
            dc = get_defender_collector()
            dc.start()
            self._collectors["defender"] = dc
            log.info("✅ FR01-04: DefenderCollector started (malware/AV events)")
        except Exception as e:
            log.error(f"❌ FR01-04: DefenderCollector failed to start: {e}")

        # ── FR01-05: Firewall Collector ───────────────────────────────────────
        try:
            from core.event_collector.firewall_collector import get_firewall_collector
            fc = get_firewall_collector()
            fc.start()
            self._collectors["firewall"] = fc
            log.info("✅ FR01-05: FirewallCollector started (pfirewall.log + event log)")
        except Exception as e:
            log.error(f"❌ FR01-05: FirewallCollector failed to start: {e}")

        # ── FR09-03: DNS Client Collector ─────────────────────────────────────
        try:
            from core.event_collector.dns_client_collector import get_dns_client_collector
            dns = get_dns_client_collector()
            dns.start()
            self._collectors["dns_client"] = dns
            log.info("✅ FR09-03: DnsClientCollector started (DNS-Client/Operational + EID 1014)")
        except Exception as e:
            log.error(f"❌ FR09-03: DnsClientCollector failed to start: {e}")

        # ── FR09-04: SMB Collector ────────────────────────────────────────────
        try:
            from core.event_collector.smb_collector import get_smb_collector
            smb = get_smb_collector()
            smb.start()
            self._collectors["smb"] = smb
            log.info("✅ FR09-04: SmbCollector started (EIDs 5140-5145 + SMBServer channels)")
        except Exception as e:
            log.error(f"❌ FR09-04: SmbCollector failed to start: {e}")

        # ── FR09-06: PowerShell Remoting Collector ────────────────────────────
        try:
            from core.event_collector.psremoting_collector import get_psremoting_collector
            psr = get_psremoting_collector()
            psr.start()
            self._collectors["ps_remoting"] = psr
            log.info("✅ FR09-06: PsRemotingCollector started (WinRM/Operational + PS/Operational)")
        except Exception as e:
            log.error(f"❌ FR09-06: PsRemotingCollector failed to start: {e}")

        # ── Sysmon Collector ─────────────────────────────────────────────────────
        try:
            from core.event_collector.sysmon_collector import get_sysmon_collector
            sc_sys = get_sysmon_collector()
            sc_sys.start()
            self._collectors["sysmon"] = sc_sys
            log.info("✅ Sysmon: SysmonCollector started (EIDs 1/3/11/13)")
        except Exception as e:
            log.error(f"❌ Sysmon: SysmonCollector failed: {e}")

        # ── File Scanner (YARA) ───────────────────────────────────────────────
        try:
            from core.event_collector.file_scanner import get_file_scanner
            fs = get_file_scanner()
            fs.start()
            self._collectors["file_scanner"] = fs
            log.info("✅ FileScanner: started (Downloads/Desktop/Temp/AppData + YARA)")
        except Exception as e:
            log.error(f"❌ FileScanner: failed: {e}")

        # ── Watchdog ──────────────────────────────────────────────────────────
        self._watchdog = threading.Thread(
            target=self._watchdog_loop, daemon=True, name="rt-watchdog"
        )
        self._watchdog.start()
        log.info("✅ FR01-06: Watchdog started (auto-restart on crash)")

        active = sum(
            1 for c in self._collectors.values()
            if (hasattr(c, "alive") and c.alive)
            or (hasattr(c, "_thread") and c._thread and c._thread.is_alive())
            or hasattr(c, "last_sample")
        )
        log.info(f"RT Pipeline ready — {active}/{len(self._collectors)} collectors active")
        log.info("Latency target: ≤3 seconds end-to-end")
        log.info("=" * 60)

    def stop(self):
        self._stop.set()
        with self._lock:
            self._running = False
        for name, collector in self._collectors.items():
            try:
                collector.stop()
                log.info(f"Stopped: {name}")
            except Exception as e:
                log.warning(f"Stop error for {name}: {e}")

    def _watchdog_loop(self):
        log.debug("Watchdog thread started")
        while not self._stop.wait(60):
            for name, collector in list(self._collectors.items()):
                try:
                    is_alive = False
                    if hasattr(collector, "alive"):
                        is_alive = bool(collector.alive)
                    elif hasattr(collector, "_thread"):
                        is_alive = bool(collector._thread and collector._thread.is_alive())
                    elif hasattr(collector, "_running"):
                        is_alive = bool(collector._running)
                    elif hasattr(collector, "last_sample"):
                        is_alive = True
                    if not is_alive and self._running:
                        log.warning(f"[Watchdog] {name} collector is down — restarting")
                        collector.start()
                except Exception as e:
                    log.error(f"[Watchdog] Error checking {name}: {e}")

    def status(self) -> dict:
        uptime = round(time.time() - self._start_time, 0) if self._start_time else 0
        collectors_status = {}
        for name, collector in self._collectors.items():
            try:
                alive = False
                if hasattr(collector, "alive"):
                    alive = collector.alive
                elif hasattr(collector, "_thread"):
                    alive = bool(collector._thread and collector._thread.is_alive())
                elif hasattr(collector, "last_sample"):
                    alive = collector.last_sample is not None
                extra = {}
                if hasattr(collector, "stats"):
                    extra = collector.stats() or {}
                elif hasattr(collector, "events_found"):
                    extra = {"events_found": collector.events_found}
                elif hasattr(collector, "_events_found"):
                    extra = {"events_found": collector._events_found}
                collectors_status[name] = {
                    "alive": alive, "status": "running" if alive else "stopped", **extra
                }
            except Exception:
                collectors_status[name] = {"alive": False, "status": "error"}
        return {
            "running":           self._running,
            "uptime_sec":        uptime,
            "latency_target_ms": 3000,
            "collectors":        collectors_status,
            "timestamp":         datetime.now().isoformat(),
        }

    def get_perf_sample(self) -> Optional[dict]:
        pm = self._collectors.get("perf")
        if pm and hasattr(pm, "get_current"):
            return pm.get_current()
        return None


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[RTPipeline] = None
_lock = threading.Lock()


def get_rt_pipeline() -> RTPipeline:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = RTPipeline()
    return _instance
