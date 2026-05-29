"""
core/event_collector/perf_monitor.py
======================================
FR01-03: Real-time System Performance Monitoring

Collects every POLL_INTERVAL seconds:
  - CPU:     total %, per-core %, frequency, top processes
  - Memory:  total/used/available/percent, swap
  - Disk:    read/write bytes/sec, IOPS, usage per partition
  - Network: bytes_sent/recv per second, packets, errors, connections

Data flows two ways:
  1. Stored in `perf_samples` SQLite table (for trend analysis)
  2. Pushed to AlertBus when thresholds are breached
  3. Exposed via /api/perf/current for dashboard real-time display

INTEGRATION:
  Called from app.py startup:
      from core.event_collector.perf_monitor import get_perf_monitor
      get_perf_monitor().start()
"""

import threading
import time
import os
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("perf_monitor")

# ── Thresholds for alert bus ──────────────────────────────────────────────────
THRESHOLDS = {
    "cpu_critical":    90.0,   # % total CPU
    "cpu_warning":     75.0,
    "ram_critical":    90.0,   # % RAM used (excl. own process)
    "ram_warning":     80.0,
    "disk_critical":   90.0,   # % disk used
    "disk_warning":    80.0,
    "net_high_mbps":   800.0,  # MB/s combined
    "disk_iops_high":  1000,   # IOPS threshold
}

POLL_INTERVAL = 3   # seconds — matches FR01-06 ≤3s requirement

# Processes to exclude from "high CPU process" alerts (monitoring app itself)
OWN_PROCESS_NAMES = {
    "python.exe", "python3.exe", "python", "pythonw.exe", "py.exe",
    "System Idle Process", "System", "", "Registry", "Memory Compression",
}


class PerfSample:
    """One snapshot of all performance metrics — structured JSON output."""

    __slots__ = ("ts", "cpu", "memory", "disk", "network", "processes", "raw")

    def __init__(self, ts, cpu, memory, disk, network, processes):
        self.ts        = ts
        self.cpu       = cpu
        self.memory    = memory
        self.disk      = disk
        self.network   = network
        self.processes = processes

    def to_dict(self) -> dict:
        return {
            "timestamp": self.ts,
            "cpu":       self.cpu,
            "memory":    self.memory,
            "disk":      self.disk,
            "network":   self.network,
            "top_processes": self.processes,
        }


class PerfMonitor:
    """
    FR01-03 — Continuous system performance monitor.

    Runs a single background thread.
    Exposes last_sample for the dashboard and writes to perf_samples table.
    """

    def __init__(self):
        self._stop       = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock       = threading.Lock()
        self.last_sample: Optional[dict] = None
        self._own_pid    = os.getpid()
        self._psutil_ok  = False
        self._prev_disk_io  = None
        self._prev_net_io   = None
        self._prev_io_time  = None
        self._last_alert_state = {
            "cpu":    "NORMAL",
            "memory": "NORMAL",
        }
        self._active_perf_alerts: dict[str, int] = {}
        self._disk_alerted = set()

    def _init_psutil(self) -> bool:
        if self._psutil_ok:
            return True
        try:
            import psutil
            self._psutil = psutil
            self._psutil_ok = True
            # Warm up CPU percent measurement (first call always returns 0)
            psutil.cpu_percent(interval=None)
            for p in psutil.process_iter(["cpu_percent"]):
                try: p.cpu_percent(interval=None)
                except: pass
            return True
        except ImportError:
            log.warning("psutil not installed — run: pip install psutil")
            return False

    def _is_alert_resolved(self, alert_id: int) -> bool:
        """Return True if this alert was marked resolved in the resolved_alerts table."""
        try:
            from database.db import get_conn
            conn = get_conn()
            c = conn.cursor()
            c.execute("SELECT 1 FROM resolved_alerts WHERE alert_id = ? LIMIT 1", (str(alert_id),))
            row = c.fetchone()
            conn.close()
            return row is not None
        except Exception:
            return False

    def _should_fire_alert(self, metric: str, current_status: str, alert_id: int) -> bool:
        """Fire a new alert only when there is no unresolved active alert for the metric."""
        active_id = self._active_perf_alerts.get(metric)

        if current_status == "NORMAL":
            return False

        if active_id is not None:
            if self._is_alert_resolved(active_id):
                self._active_perf_alerts.pop(metric, None)
            else:
                return False

        self._last_alert_state[metric] = current_status
        self._active_perf_alerts[metric] = alert_id
        return True

    # ── Collectors ────────────────────────────────────────────────────────────

    def _collect_cpu(self) -> dict:
        ps = self._psutil
        cpu_total    = ps.cpu_percent(interval=None)
        cpu_per_core = ps.cpu_percent(interval=None, percpu=True)
        freq         = ps.cpu_freq()
        return {
            "total_percent":    round(cpu_total, 1),
            "per_core_percent": [round(c, 1) for c in (cpu_per_core or [])],
            "core_count":       ps.cpu_count(logical=True),
            "physical_cores":   ps.cpu_count(logical=False),
            "frequency_mhz":    round(freq.current, 0) if freq else None,
            "status": (
                "CRITICAL" if cpu_total >= THRESHOLDS["cpu_critical"] else
                "HIGH"     if cpu_total >= THRESHOLDS["cpu_warning"]  else
                "NORMAL"
            ),
        }

    def _collect_memory(self) -> dict:
        ps  = self._psutil
        vm  = ps.virtual_memory()
        sw  = ps.swap_memory()

        # Subtract own process memory to avoid self-alerts
        own_mb = 0.0
        try:
            own_proc = ps.Process(self._own_pid)
            own_mb   = own_proc.memory_info().rss / (1024 * 1024)
            for child in own_proc.children(recursive=True):
                try: own_mb += child.memory_info().rss / (1024 * 1024)
                except: pass
        except Exception:
            pass

        total_mb    = vm.total  / (1024 * 1024)
        used_mb     = vm.used   / (1024 * 1024)
        avail_mb    = vm.available / (1024 * 1024)
        excl_mb     = max(0.0, used_mb - own_mb)
        excl_pct    = round((excl_mb / total_mb) * 100, 1) if total_mb else 0.0

        return {
            "total_mb":          round(total_mb, 0),
            "used_mb":           round(used_mb, 0),
            "available_mb":      round(avail_mb, 0),
            "percent":           round(vm.percent, 1),
            "percent_excl_self": excl_pct,
            "swap_used_mb":      round(sw.used / (1024 * 1024), 0),
            "swap_percent":      round(sw.percent, 1),
            "status": (
                "CRITICAL" if excl_pct >= THRESHOLDS["ram_critical"] else
                "HIGH"     if excl_pct >= THRESHOLDS["ram_warning"]  else
                "NORMAL"
            ),
        }

    def _collect_disk(self) -> dict:
        ps   = self._psutil
        now  = time.time()
        io   = ps.disk_io_counters()

        # Calculate IOPS and throughput
        read_bps  = write_bps  = 0.0
        read_iops = write_iops = 0.0

        if self._prev_disk_io and self._prev_io_time:
            dt = now - self._prev_io_time
            if dt > 0:
                read_bps   = (io.read_bytes  - self._prev_disk_io.read_bytes)  / dt
                write_bps  = (io.write_bytes - self._prev_disk_io.write_bytes) / dt
                read_iops  = (io.read_count  - self._prev_disk_io.read_count)  / dt
                write_iops = (io.write_count - self._prev_disk_io.write_count) / dt

        self._prev_disk_io  = io
        self._prev_io_time  = now

        # Partition usage
        partitions = []
        for part in ps.disk_partitions(all=False):
            try:
                usage = ps.disk_usage(part.mountpoint)
                partitions.append({
                    "device":      part.device,
                    "mountpoint":  part.mountpoint,
                    "total_gb":    round(usage.total  / 1e9, 1),
                    "used_gb":     round(usage.used   / 1e9, 1),
                    "free_gb":     round(usage.free   / 1e9, 1),
                    "percent":     round(usage.percent, 1),
                    "status": (
                        "CRITICAL" if usage.percent >= THRESHOLDS["disk_critical"] else
                        "HIGH"     if usage.percent >= THRESHOLDS["disk_warning"]  else
                        "NORMAL"
                    ),
                })
            except Exception:
                continue

        total_iops = read_iops + write_iops
        return {
            "read_mb_per_sec":  round(read_bps  / (1024 * 1024), 2),
            "write_mb_per_sec": round(write_bps / (1024 * 1024), 2),
            "read_iops":        round(read_iops,  0),
            "write_iops":       round(write_iops, 0),
            "total_iops":       round(total_iops, 0),
            "partitions":       partitions,
            "status": (
                "HIGH" if total_iops >= THRESHOLDS["disk_iops_high"] else "NORMAL"
            ),
        }

    def _collect_network(self) -> dict:
        ps  = self._psutil
        now = time.time()
        nio = ps.net_io_counters()

        sent_bps = recv_bps = 0.0
        if self._prev_net_io and self._prev_io_time:
            # Use same dt as disk (both updated in same cycle)
            dt = now - (self._prev_io_time or now)
            if dt > 0:
                sent_bps = (nio.bytes_sent - self._prev_net_io.bytes_sent) / dt
                recv_bps = (nio.bytes_recv - self._prev_net_io.bytes_recv) / dt

        self._prev_net_io = nio

        # Active connections summary
        try:
            conns = ps.net_connections(kind="inet")
            conn_count    = len(conns)
            established   = sum(1 for c in conns if c.status == "ESTABLISHED")
            listening     = sum(1 for c in conns if c.status == "LISTEN")
        except Exception:
            conn_count = established = listening = 0

        total_mbps = (sent_bps + recv_bps) / (1024 * 1024)
        return {
            "bytes_sent_total":  nio.bytes_sent,
            "bytes_recv_total":  nio.bytes_recv,
            "sent_mb_per_sec":   round(sent_bps / (1024 * 1024), 3),
            "recv_mb_per_sec":   round(recv_bps / (1024 * 1024), 3),
            "packets_sent":      nio.packets_sent,
            "packets_recv":      nio.packets_recv,
            "errors_in":         nio.errin,
            "errors_out":        nio.errout,
            "active_connections": conn_count,
            "established":       established,
            "listening":         listening,
            "status": (
                "HIGH" if total_mbps >= THRESHOLDS["net_high_mbps"] else "NORMAL"
            ),
        }

    def _collect_top_processes(self) -> list:
        """Top 10 CPU-consuming processes — excluding own app."""
        ps = self._psutil
        procs = []
        own_pid = self._own_pid

        for p in ps.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
            try:
                pname = p.info["name"] or ""
                if p.info["pid"] == own_pid:        continue
                if pname in OWN_PROCESS_NAMES:      continue
                if pname.lower().startswith("python"): continue
                procs.append({
                    "pid":      p.info["pid"],
                    "name":     pname,
                    "cpu_pct":  round(p.info["cpu_percent"] or 0, 1),
                    "ram_pct":  round(p.info["memory_percent"] or 0, 1),
                })
            except Exception:
                continue

        return sorted(procs, key=lambda x: x["cpu_pct"], reverse=True)[:10]

    # ── Alert check ───────────────────────────────────────────────────────────

    def _check_alerts(self, sample: dict):
        """Push to AlertBus if any metric exceeds threshold."""
        try:
            from core.pipeline.alert_bus import get_alert_bus
            bus = get_alert_bus()

            cpu = sample["cpu"]
            mem = sample["memory"]

            if cpu["status"] == "CRITICAL":
                alert_id = int(time.time() * 1000)
                if self._should_fire_alert("cpu", "CRITICAL", alert_id):
                    bus.push({
                        "id":       alert_id,
                        "type":     "cpu_critical", "severity": "CRITICAL",
                        "category": "system",
                        "title":    f"CPU critically high: {cpu['total_percent']}%",
                        "description": f"System CPU at {cpu['total_percent']}% — may become unresponsive.",
                        "source":   "Performance Monitor", "risk_score": 15,
                    })
            elif cpu["status"] == "HIGH":
                alert_id = int(time.time() * 1000)
                if self._should_fire_alert("cpu", "HIGH", alert_id):
                    bus.push({
                        "id":       alert_id,
                        "type":     "cpu_high", "severity": "MEDIUM",
                        "category": "system",
                        "title":    f"CPU usage elevated: {cpu['total_percent']}%",
                        "description": f"CPU load is high — check top processes.",
                        "source":   "Performance Monitor", "risk_score": 7,
                    })
            else:
                self._should_fire_alert("cpu", "NORMAL", 0)

            if mem["status"] == "CRITICAL":
                alert_id = int(time.time() * 1000)
                if self._should_fire_alert("memory", "CRITICAL", alert_id):
                    bus.push({
                        "id":       alert_id,
                        "type":     "ram_critical", "severity": "CRITICAL",
                        "category": "system",
                        "title":    f"Memory critically low: {mem['percent_excl_self']}% used",
                        "description": f"Only {mem['available_mb']} MB free.",
                        "source":   "Performance Monitor", "risk_score": 15,
                    })
            elif mem["status"] == "HIGH":
                alert_id = int(time.time() * 1000)
                if self._should_fire_alert("memory", "HIGH", alert_id):
                    bus.push({
                        "id":       alert_id,
                        "type":     "ram_high", "severity": "MEDIUM",
                        "category": "system",
                        "title":    f"Memory usage high: {mem['percent_excl_self']}%",
                        "description": f"Available RAM: {mem['available_mb']} MB.",
                        "source":   "Performance Monitor", "risk_score": 7,
                    })
            else:
                self._should_fire_alert("memory", "NORMAL", 0)

            for part in sample["disk"].get("partitions", []):
                mountpoint = part["mountpoint"]
                if part["status"] == "CRITICAL":
                    if mountpoint not in self._disk_alerted:
                        bus.push({
                            "type": "disk_full", "severity": "CRITICAL",
                            "category": "system",
                            "title": f"Disk nearly full: {mountpoint} at {part['percent']}%",
                            "description": f"Only {part['free_gb']} GB free on {part['device']}.",
                            "source": "Disk Monitor", "risk_score": 12,
                        })
                        self._disk_alerted.add(mountpoint)
                else:
                    self._disk_alerted.discard(mountpoint)

        except Exception as e:
            log.warning(f"Alert check failed: {e}")

    # ── Persist ───────────────────────────────────────────────────────────────

    def _persist(self, sample: dict):
        """Write sample to perf_samples table."""
        conn = None
        try:
            import json
            from database.db import get_conn
            attempt = 0
            while attempt < 3:
                conn = get_conn()
                try:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS perf_samples (
                            id        INTEGER PRIMARY KEY AUTOINCREMENT,
                            ts        TEXT,
                            cpu_pct   REAL,
                            ram_pct   REAL,
                            disk_iops REAL,
                            net_mbps  REAL,
                            raw_json  TEXT
                        )
                    """)
                    conn.execute("""
                        INSERT INTO perf_samples (ts, cpu_pct, ram_pct, disk_iops, net_mbps, raw_json)
                        VALUES (?,?,?,?,?,?)
                    """, (
                        sample["timestamp"],
                        sample["cpu"]["total_percent"],
                        sample["memory"]["percent_excl_self"],
                        sample["disk"]["total_iops"],
                        sample["network"]["sent_mb_per_sec"] + sample["network"]["recv_mb_per_sec"],
                        json.dumps(sample),
                    ))
                    # Keep only last 2880 samples (2880 × 3s = 8 hours)
                    conn.execute("""
                        DELETE FROM perf_samples WHERE id NOT IN (
                            SELECT id FROM perf_samples ORDER BY id DESC LIMIT 2880
                        )
                    """)
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
            log.warning(f"Perf persist failed: {e}")

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _collect_once(self) -> Optional[dict]:
        if not self._init_psutil():
            return None
        ts = datetime.now().isoformat()
        try:
            sample = {
                "timestamp": ts,
                "cpu":       self._collect_cpu(),
                "memory":    self._collect_memory(),
                "disk":      self._collect_disk(),
                "network":   self._collect_network(),
                "top_processes": self._collect_top_processes(),
            }
            return sample
        except Exception as e:
            log.error(f"Collection failed: {e}")
            return None

    def _loop(self):
        log.info(f"PerfMonitor started — polling every {POLL_INTERVAL}s")
        # First poll: seed baseline IO counters
        if self._init_psutil():
            try:
                self._prev_disk_io  = self._psutil.disk_io_counters()
                self._prev_net_io   = self._psutil.net_io_counters()
                self._prev_io_time  = time.time()
            except Exception:
                pass

        while not self._stop.is_set():
            sample = self._collect_once()
            if sample:
                with self._lock:
                    self.last_sample = sample
                self._check_alerts(sample)
                self._persist(sample)
            self._stop.wait(POLL_INTERVAL)

        log.info("PerfMonitor stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="perf-monitor"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def get_current(self) -> Optional[dict]:
        """Thread-safe accessor for latest sample — used by API."""
        with self._lock:
            return dict(self.last_sample) if self.last_sample else None


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[PerfMonitor] = None
_lock = threading.Lock()


def get_perf_monitor() -> PerfMonitor:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = PerfMonitor()
    return _instance
