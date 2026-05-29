"""
core/analysis_engine/risk_scorer_sysmon_patch.py
==================================================
Add Sysmon Event ID weights to risk_scorer.py

INTEGRATION INSTRUCTIONS
--------------------------
Open  core/analysis_engine/risk_scorer.py

Find the EVENT_RISK dict (starts at line ~29).
At the END of that dict, before the closing  }  brace,
add the entries below.

Example — the current file ends with something like:
    1000: {"score": 2, "label": "Application Crash", "category": "stability"},
}

Change to:
    1000: {"score": 2, "label": "Application Crash", "category": "stability"},

    # ── Sysmon Event IDs ───────────────────────────────────────────────
    1:   {"score": 12, "label": "Process Create",      "category": "process_creation"},
    3:   {"score": 10, "label": "Network Connection",  "category": "network"},
    11:  {"score": 10, "label": "File Create",         "category": "file_activity"},
    13:  {"score": 14, "label": "Registry Value Set",  "category": "persistence"},
    22:  {"score": 8,  "label": "DNS Query",           "category": "network"},
}

NOTE: EIDs 1, 3, 11, 13, 22 are low-volume Sysmon EIDs — every occurrence
is stored because Sysmon already filters them by its own rule config.
Higher base scores reflect that these are targeted detections, not noisy
generic Windows events.
"""

# ── Sysmon EID entries to add to EVENT_RISK ───────────────────────────────────

SYSMON_EVENT_RISK = {
    # Process Create — scored per occurrence; context (parent, commandline)
    # raises this further in the correlator and threat_detector.
    1:  {"score": 12, "label": "Process Create",     "category": "process_creation"},

    # Network Connection — outbound connection logged by Sysmon;
    # external destination + suspicious process raises this in correlator.
    3:  {"score": 10, "label": "Network Connection", "category": "network"},

    # File Create — file written to disk; suspicious path/extension
    # triggers file_monitor and correlator Chain 10.
    11: {"score": 10, "label": "File Create",        "category": "file_activity"},

    # Registry Value Set — any write to the registry logged;
    # persistence key matches raise this significantly.
    13: {"score": 14, "label": "Registry Value Set", "category": "persistence"},

    # DNS Query — domain lookup; unusual TLDs and DGA-like names
    # raise suspicion in threat_detector.
    22: {"score": 8,  "label": "DNS Query",          "category": "network"},
}
