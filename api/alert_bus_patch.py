"""
api/alert_bus_patch.py
========================
Monkey-patches core.pipeline.alert_bus.AlertBus with subscribe/unsubscribe
methods if they are missing.

BUG-1 ROOT CAUSE:
  alerts_api.py calls alert_sse_generator(bus) which needs bus.subscribe()
  and bus.unsubscribe(). These methods were missing from the AlertBus class,
  causing AttributeError at runtime whenever a browser opened the SSE stream.

HOW TO USE:
  Import this module in app.py BEFORE registering the alerts blueprint:

      import api.alert_bus_patch   # apply patch first
      from api.alerts_api import alerts_bp

  Or just import it at the top of api/alerts_api.py (already done in the
  fixed version).
"""

import queue
import threading

def _patch_alert_bus():
    try:
        from core.pipeline.alert_bus import AlertBus

        if hasattr(AlertBus, "_subscribers"):
            return  # already patched

        # Thread-safe subscriber list
        AlertBus._subscribers     = []
        AlertBus._subscribers_lock = threading.Lock()

        def subscribe(self, q: queue.Queue):
            """Register a client queue to receive pushed alerts."""
            with self._subscribers_lock:
                if q not in self._subscribers:
                    self._subscribers.append(q)

        def unsubscribe(self, q: queue.Queue):
            """Remove a client queue."""
            with self._subscribers_lock:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

        # Patch push() to also fan-out to all subscribers
        _original_push = AlertBus.push

        def patched_push(self, alert):
            _original_push(self, alert)
            with self._subscribers_lock:
                dead = []
                for q in list(self._subscribers):
                    try:
                        q.put_nowait(alert)
                    except queue.Full:
                        dead.append(q)
                for q in dead:
                    try:
                        self._subscribers.remove(q)
                    except ValueError:
                        pass

        AlertBus.subscribe   = subscribe
        AlertBus.unsubscribe = unsubscribe
        AlertBus.push        = patched_push

        print("[alert_bus_patch] ✅ AlertBus patched with subscribe/unsubscribe/fan-out push")

    except ImportError as e:
        print(f"[alert_bus_patch] ⚠ Could not import AlertBus: {e}")
    except Exception as e:
        print(f"[alert_bus_patch] ⚠ Patch failed: {e}")

_patch_alert_bus()
