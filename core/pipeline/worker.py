"""
core/pipeline/worker.py
========================
Background worker queue — replaces Celery/Redis for heavy processing.
Uses Python's threading.Queue (can be swapped for Celery with no API changes).

JOBS HANDLED:
  - full_intelligence_scan  : run threat detection + correlation + anomaly detection
  - batch_pipeline          : process a batch of raw events through the pipeline
  - persist_alert           : save alert to DB
  - scheduled_analysis      : 12-hour auto-analysis

API:
    from core.pipeline.worker import get_worker
    worker = get_worker()
    worker.enqueue("full_intelligence_scan", {})
    worker.enqueue("batch_pipeline", {"events": [...], "category": "security"})
"""

import queue
import threading
import time
from typing import Any, Callable, Optional
from utils.logger import get_logger

log = get_logger("pipeline.worker")


class WorkerQueue:
    """
    Thread-pool based job queue.
    Spins up N worker threads that drain the queue continuously.
    """

    def __init__(self, num_workers: int = 3, maxsize: int = 1000):
        self._queue    = queue.Queue(maxsize=maxsize)
        self._workers  = []
        self._running  = False
        self._stats    = {"enqueued": 0, "completed": 0, "failed": 0}
        self._lock     = threading.Lock()
        self._handlers: dict[str, Callable] = {}
        self._num_workers = num_workers

    def register(self, job_type: str, handler: Callable):
        """Register a handler function for a job type."""
        self._handlers[job_type] = handler
        log.debug(f"Registered handler for job type: {job_type}")

    def start(self):
        """Start worker threads."""
        if self._running:
            return
        self._running = True
        for i in range(self._num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                daemon=True,
                name=f"pipeline-worker-{i}",
            )
            t.start()
            self._workers.append(t)
        log.info(f"WorkerQueue started — {self._num_workers} worker threads")

    def stop(self):
        """Signal workers to stop. Non-blocking."""
        self._running = False
        # Poison pills
        for _ in self._workers:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass

    def enqueue(self, job_type: str, payload: dict = None, priority: int = 0) -> bool:
        """
        Enqueue a job. Returns True if accepted, False if queue full.
        priority is currently unused (reserved for future PriorityQueue upgrade).
        """
        try:
            self._queue.put_nowait({"type": job_type, "payload": payload or {}, "ts": time.time()})
            with self._lock:
                self._stats["enqueued"] += 1
            return True
        except queue.Full:
            log.warning(f"Worker queue full — dropped job: {job_type}")
            return False

    def enqueue_batch(self, jobs: list) -> int:
        """Enqueue multiple jobs. Returns number accepted."""
        accepted = 0
        for job in jobs:
            if self.enqueue(job.get("type", "unknown"), job.get("payload", {})):
                accepted += 1
        return accepted

    def stats(self) -> dict:
        with self._lock:
            return {**self._stats, "queue_size": self._queue.qsize(), "workers": len(self._workers)}

    def _worker_loop(self, worker_id: int):
        """Main loop for each worker thread."""
        log.debug(f"Worker {worker_id} started")
        while self._running:
            try:
                job = self._queue.get(timeout=5)
                if job is None:  # poison pill
                    break
                self._handle_job(job, worker_id)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                log.error(f"Worker {worker_id} unexpected error: {e}")
        log.debug(f"Worker {worker_id} stopped")

    def _handle_job(self, job: dict, worker_id: int):
        """Dispatch a job to its registered handler."""
        job_type = job.get("type", "unknown")
        payload  = job.get("payload", {})

        handler = self._handlers.get(job_type)
        if not handler:
            log.warning(f"No handler for job type: {job_type}")
            return

        try:
            t0 = time.time()
            handler(payload)
            elapsed = round(time.time() - t0, 3)
            with self._lock:
                self._stats["completed"] += 1
            log.debug(f"Worker {worker_id}: {job_type} completed in {elapsed}s")
        except Exception as e:
            log.error(f"Worker {worker_id}: {job_type} failed: {e}")
            with self._lock:
                self._stats["failed"] += 1


# ── Job handlers ──────────────────────────────────────────────────────────────

def _handle_full_intelligence_scan(payload: dict):
    """Run the full intelligence engine and push results to alert bus."""
    try:
        from core.analysis_engine import run_intelligence_engine
        from core.pipeline.alert_bus import get_alert_bus

        result = run_intelligence_engine()
        bus    = get_alert_bus()

        # Push critical threats as alerts
        for threat in result.get("threats", []):
            if threat.get("severity") in ("CRITICAL", "HIGH"):
                bus.push({
                    "type":        "threat_detection",
                    "name":        threat.get("name"),
                    "severity":    threat.get("severity"),
                    "category":    threat.get("category"),
                    "description": threat.get("description"),
                    "count":       threat.get("count"),
                    "risk_score":  result.get("risk_score", 0),
                })

        # Push critical correlations
        for corr in result.get("correlations", []):
            if corr.get("severity") == "CRITICAL":
                bus.push({
                    "type":        "correlation_alert",
                    "name":        corr.get("name"),
                    "severity":    "CRITICAL",
                    "category":    "attack_chain",
                    "description": corr.get("description"),
                    "evidence":    corr.get("evidence", []),
                })

        log.info(f"Intelligence scan complete — risk: {result.get('risk_level')} ({result.get('risk_score')}/100)")
    except Exception as e:
        log.error(f"Intelligence scan job failed: {e}")


def _handle_batch_pipeline(payload: dict):
    """Process a batch of raw events through the pipeline."""
    try:
        from core.pipeline.orchestrator import get_pipeline
        events   = payload.get("events", [])
        category = payload.get("category", "system")
        if not events:
            return
        pipeline = get_pipeline()
        results  = pipeline.process_batch(events, category)
        log.info(f"Batch pipeline complete: {results}")
    except Exception as e:
        log.error(f"Batch pipeline job failed: {e}")


def _handle_scheduled_analysis(payload: dict):
    """Triggered every 12 hours — runs full analysis and saves report."""
    try:
        from api.perform_analysis_api import _run_analysis, _save_report
        report = _run_analysis(trigger="auto_worker")
        _save_report(report, trigger="auto_worker")
        log.info(f"Scheduled analysis saved — risk: {report.get('risk_summary', {}).get('label')}")
    except Exception as e:
        log.error(f"Scheduled analysis job failed: {e}")


# ── Singleton + startup ───────────────────────────────────────────────────────

_worker_instance: Optional[WorkerQueue] = None
_worker_lock = threading.Lock()


def get_worker() -> WorkerQueue:
    """Return the global singleton worker queue. Thread-safe."""
    global _worker_instance
    if _worker_instance is None:
        with _worker_lock:
            if _worker_instance is None:
                wq = WorkerQueue(num_workers=3)
                wq.register("full_intelligence_scan", _handle_full_intelligence_scan)
                wq.register("batch_pipeline",         _handle_batch_pipeline)
                wq.register("scheduled_analysis",     _handle_scheduled_analysis)
                wq.start()
                _worker_instance = wq
                log.info("WorkerQueue singleton created and started")
    return _worker_instance
