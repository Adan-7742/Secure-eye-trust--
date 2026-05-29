"""
core/event_collector/rt_pipeline_sysmon_patch.py
==================================================
Patch instructions and code for adding SysmonCollector to rt_pipeline.py.

INTEGRATION INSTRUCTIONS
--------------------------
Open  core/event_collector/rt_pipeline.py

Find the Watchdog block (the last collector block before _watchdog):

        # ── Watchdog ──────────────────────────────────────────────────────────
        self._watchdog = threading.Thread(
            target=self._watchdog_loop, daemon=True, name="rt-watchdog"
        )

PASTE the block below IMMEDIATELY BEFORE the Watchdog block:

        # ── Sysmon Collector ───────────────────────────────────────────────────
        try:
            from core.event_collector.sysmon_collector import get_sysmon_collector
            sc_sysmon = get_sysmon_collector()
            sc_sysmon.start()
            self._collectors["sysmon"] = sc_sysmon
            log.info("✅ Sysmon: SysmonCollector started (EIDs 1,3,11,13,22 — Process/Net/File/Registry/DNS)")
        except Exception as e:
            log.error(f"❌ Sysmon: SysmonCollector failed to start: {e}")

That is the ONLY change needed to rt_pipeline.py.
The watchdog loop already handles restart for any collector that goes down.

NO other changes to rt_pipeline.py are required — the watchdog's
generic alive-check works for SysmonCollector because it exposes the
`alive` property (same pattern as DefenderCollector).
"""

# ── Standalone verification helper ────────────────────────────────────────────

def verify_sysmon_in_pipeline() -> dict:
    """
    Call from a REPL or test to verify the sysmon collector is wired into
    the rt_pipeline and reporting as alive.

    Usage:
        from core.event_collector.rt_pipeline_sysmon_patch import verify_sysmon_in_pipeline
        print(verify_sysmon_in_pipeline())
    """
    result = {"wired": False, "alive": False, "stats": {}, "error": None}
    try:
        from core.event_collector.rt_pipeline import get_rt_pipeline
        pipeline = get_rt_pipeline()
        status   = pipeline.status()
        collectors = status.get("collectors", {})
        if "sysmon" in collectors:
            result["wired"]  = True
            result["alive"]  = collectors["sysmon"].get("alive", False)
            result["stats"]  = collectors["sysmon"]
        else:
            result["error"] = (
                "SysmonCollector not found in rt_pipeline._collectors. "
                "Apply the rt_pipeline patch and restart the app."
            )
    except Exception as e:
        result["error"] = str(e)
    return result
