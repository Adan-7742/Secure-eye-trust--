"""
core/pipeline/orchestrator.py
==============================
THE CENTRAL ORCHESTRATOR — production EDR-style event processing pipeline.

UPGRADED: Integrates FR02-01, FR02-03, FR02-04, FR02-05 via HE engine.

Every log event collected from Windows MUST pass through this pipeline.
No event is written to the database without going through every stage.

PIPELINE STAGES:
  1. Validate      — reject malformed/empty events
  2. Normalize     — extract user, IP, logon_type, process from raw message
  2.5 HE-Encrypt   — FR02-01/03: encrypt sensitive fields BEFORE DB write
  3. Deduplicate   — compute content hash, reject duplicates
  4. Risk Score    — assign per-event risk score and category
  5. Enrich        — attach metadata (hostname, session context)
  6. Store         — write to SQLite with all enriched fields (inc. encrypted cols)
  7. Detect        — run lightweight per-event rule checks
  8. Alert         — push high-risk events to the alert bus

FR02-01: Stage 2.5 encrypts sensitive fields BEFORE any DB write.
FR02-03: Only username, ip_address, machine_name are encrypted — all other
         fields stay plaintext so regex threat rules work unchanged.
FR02-04: HE engine loads FEK and seed from KeyManager (PBKDF2 + AES-GCM).
FR02-05: KeyManager resolves master passphrase via Windows DPAPI / Credential Manager.

The pipeline returns a PipelineResult for every event, so callers
know exactly what happened at each stage.

USAGE:
    from core.pipeline.orchestrator import get_pipeline
    pipeline = get_pipeline()
    result = pipeline.process(raw_event_dict, category="security")

    # Bulk:
    results = pipeline.process_batch(events, category="system")
"""

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from utils.logger import get_logger

log = get_logger("pipeline.orchestrator")


# ── Pipeline result dataclass ─────────────────────────────────────────────────

@dataclass
class PipelineResult:
    accepted:      bool  = False
    duplicate:     bool  = False
    db_id:         Optional[int] = None
    risk_score:    int   = 0
    risk_category: str   = ""
    alert_fired:   bool  = False
    reject_reason: Optional[str] = None
    norm_fields:   dict  = field(default_factory=dict)
    stages_passed: list  = field(default_factory=list)
    he_encrypted:  bool  = False   # FR02-01: True if sensitive fields were encrypted


# ── Main orchestrator class ───────────────────────────────────────────────────

class EventPipeline:
    """
    Production event processing pipeline.
    Thread-safe — multiple threads can call process() concurrently.
    """

    def __init__(self):
        self._lock        = threading.Lock()
        self._dedup_cache = {}
        self._dedup_max   = 10_000
        self._stats       = {
            "processed": 0, "accepted": 0,
            "duplicates": 0, "rejected": 0, "alerts_fired": 0,
        }
        # Lazy imports
        self._normalizer  = None
        self._scorer      = None
        self._rule_engine = None
        self._alert_bus   = None
        self._he          = None   # FR02-01: HE engine
        self._initialized = False

    def _lazy_init(self):
        """Load sub-modules on first use — avoids import-time circular deps."""
        if self._initialized:
            return
        try:
            from core.analysis_engine.normalizer  import normalize
            from core.analysis_engine.risk_scorer import score_event
            from core.pipeline.rule_engine        import RuleEngine
            from core.pipeline.alert_bus          import get_alert_bus

            self._normalizer  = normalize
            self._scorer      = score_event
            self._rule_engine = RuleEngine()
            self._alert_bus   = get_alert_bus()

            # ── FR02-01/04/05: Load HE engine ─────────────────────────────────
            try:
                from core.he_engine.he_engine import HEEngine
                self._he = HEEngine()
                log.info("HE engine loaded — sensitive fields will be encrypted at ingestion (FR02-01)")
            except Exception as he_err:
                log.warning(f"HE engine unavailable — events stored in plaintext: {he_err}")
                self._he = None
            # ── END HE ────────────────────────────────────────────────────────

            self._initialized = True
            log.info("Pipeline initialized — all stages loaded")
        except Exception as e:
            log.error(f"Pipeline init error: {e}")

    # ── Stage 1: Validate ─────────────────────────────────────────────────────

    def _validate(self, event: dict, result: PipelineResult) -> bool:
        """Reject events that are clearly malformed."""
        if not event:
            result.reject_reason = "empty_event"
            return False

        if not event.get("timestamp") and not event.get("event_id"):
            result.reject_reason = "missing_timestamp_and_event_id"
            return False

        eid = event.get("event_id")
        if eid is not None:
            try:
                eid_int = int(eid)
                if eid_int < 0 or eid_int > 65535:
                    result.reject_reason = f"invalid_event_id:{eid}"
                    return False
            except (ValueError, TypeError):
                result.reject_reason = f"non_integer_event_id:{eid}"
                return False

        for field_name in ("source", "level", "message", "raw"):
            val = event.get(field_name)
            if val is not None:
                cleaned = str(val).replace("\x00", "").replace("\r", "")
                event[field_name] = cleaned[:8000] if field_name == "message" else cleaned[:500]

        result.stages_passed.append("validate")
        return True

    # ── Stage 2: Normalize ────────────────────────────────────────────────────

    def _normalize(self, event: dict, result: PipelineResult) -> dict:
        """Extract structured fields from raw message."""
        if self._normalizer is None:
            return {}
        try:
            norm = self._normalizer(event)
            result.norm_fields = norm
            result.stages_passed.append("normalize")
            return norm
        except Exception as e:
            log.warning(f"Normalize failed for EID {event.get('event_id')}: {e}")
            return {}

    # ── Stage 2.5: HE Field Encryption (FR02-01, FR02-03) ────────────────────

    def _he_encrypt(self, event: dict, norm: dict, result: PipelineResult) -> dict:
        """
        FR02-01: Encrypt sensitive fields BEFORE writing to DB.
        FR02-03: Only encrypts username, ip_address, machine_name.
                 All other fields (event_id, level, source, message) stay plaintext
                 so regex threat rules in rule_engine.py continue to work.
        FR02-04: FEK and HE seed loaded from KeyManager.
        FR02-05: KeyManager uses Windows DPAPI / Credential Manager for passphrase.
        """
        if self._he is None:
            return event

        try:
            # Merge norm fields into event so encrypt_event_at_ingestion sees them
            merged = dict(event)
            merged["norm_user"] = norm.get("user") or event.get("norm_user", "")
            merged["norm_ip"]   = norm.get("ip")   or event.get("norm_ip", "")

            enc_event = self._he.encrypt_event_at_ingestion(merged)

            # Copy encrypted columns back to event
            for col in ("enc_username", "enc_ip_address", "enc_machine_name",
                        "ip_pseudonym", "user_pseudonym", "he_kid"):
                if col in enc_event:
                    event[col] = enc_event[col]

            # Replace plaintext IP/user in norm with pseudonyms (FR02-03)
            if "ip_pseudonym" in enc_event:
                norm["ip"]   = enc_event["ip_pseudonym"]
            if "user_pseudonym" in enc_event:
                norm["user"] = enc_event["user_pseudonym"]

            result.stages_passed.append("he_encrypt")
            result.he_encrypted = True
            log.debug(f"HE encrypted sensitive fields for EID {event.get('event_id')}")

        except Exception as e:
            # Encryption failure is non-fatal — log and continue
            log.warning(f"HE encryption failed for EID {event.get('event_id')}: {e}")

        return event

    # ── Stage 3: Deduplicate ──────────────────────────────────────────────────

    def _dedup_hash(self, event: dict, category: str) -> str:
        key = (
            f"{category}:"
            f"{event.get('timestamp', '')}:"
            f"{event.get('event_id', '')}:"
            f"{event.get('source', '')}:"
            f"{(event.get('message') or '')[:200]}"
        )
        return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:32]

    def _is_duplicate(self, event_hash: str, result: PipelineResult) -> bool:
        if event_hash in self._dedup_cache:
            result.duplicate = True
            return True
        try:
            from database.db import get_conn
            conn = get_conn()
            c    = conn.cursor()
            c.execute("SELECT 1 FROM event_dedup WHERE content_hash = ? LIMIT 1", (event_hash,))
            found = c.fetchone() is not None
            conn.close()
            if found:
                result.duplicate = True
                self._dedup_cache[event_hash] = time.time()
                return True
        except Exception:
            pass
        return False

    def _record_dedup(self, event_hash: str, category: str):
        if len(self._dedup_cache) >= self._dedup_max:
            oldest = sorted(self._dedup_cache.items(), key=lambda x: x[1])[:1000]
            for k, _ in oldest:
                del self._dedup_cache[k]
        self._dedup_cache[event_hash] = time.time()
        try:
            from database.db import get_conn
            conn = get_conn()
            conn.execute(
                "INSERT OR IGNORE INTO event_dedup (content_hash, category, seen_at) VALUES (?,?,?)",
                (event_hash, category, datetime.now().isoformat())
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ── Stage 4: Risk Score ───────────────────────────────────────────────────

    def _score(self, event: dict, norm: dict, result: PipelineResult) -> tuple:
        if self._scorer is None:
            return 0, "unknown"
        try:
            eid    = int(event.get("event_id") or 0)
            scored = self._scorer(eid, norm)
            result.risk_score    = scored.get("score", 0)
            result.risk_category = scored.get("category", "unknown")
            result.stages_passed.append("risk_score")
            return result.risk_score, result.risk_category
        except Exception as e:
            log.warning(f"Scoring failed: {e}")
            return 0, "unknown"

    # ── Stage 5: Enrich ───────────────────────────────────────────────────────

    def _enrich(self, event: dict, norm: dict, category: str) -> dict:
        try:
            import socket
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"
        event["_hostname"]     = hostname
        event["_category"]     = category
        event["_processed_at"] = datetime.now().isoformat()
        return event

    # ── Stage 6: Store ────────────────────────────────────────────────────────

    def _store(self, event: dict, norm: dict, category: str,
               risk_score: int, risk_category: str,
               event_hash: str, result: PipelineResult):
        """
        Write the enriched event to SQLite.
        FR02-01: Encrypted field columns (enc_username, enc_ip_address,
                 enc_machine_name, ip_pseudonym, user_pseudonym, he_kid)
                 are written here if present.
        """
        try:
            from database.db import get_conn
            attempt = 0
            while attempt < 3:
                conn = get_conn()
                try:
                    c = conn.cursor()
                    ts   = event.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    date = event.get("date") or ts[:10]

                    # Base INSERT (existing columns — unchanged)
                    c.execute(f"""
                        INSERT OR IGNORE INTO logs_{category}
                            (timestamp, date, level, source, message, event_id, raw,
                             norm_user, norm_ip, norm_logon_type, norm_process,
                             risk_score, risk_category, content_hash)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        ts, date,
                        event.get("level"), event.get("source"),
                        event.get("message"), event.get("event_id"),
                        event.get("raw"),
                        norm.get("user"), norm.get("ip"),
                        norm.get("logon_type"), norm.get("process"),
                        risk_score, risk_category,
                        event_hash,
                    ))

                    result.db_id = c.lastrowid
                    conn.commit()
                    result.stages_passed.append("store")

                    # FR02-01: Write encrypted columns if present
                    enc_cols = {
                        "enc_username":     event.get("enc_username"),
                        "enc_ip_address":   event.get("enc_ip_address"),
                        "enc_machine_name": event.get("enc_machine_name"),
                        "ip_pseudonym":     event.get("ip_pseudonym"),
                        "user_pseudonym":   event.get("user_pseudonym"),
                        "he_kid":           event.get("he_kid"),
                    }
                    has_enc = any(v for v in enc_cols.values())
                    if has_enc and result.db_id:
                        self._store_encrypted_cols(conn, category, result.db_id, enc_cols)

                    break
                except sqlite3.OperationalError as e:
                    conn.close()
                    if attempt < 2 and "database is locked" in str(e).lower():
                        time.sleep(0.1 * (attempt + 1))
                        attempt += 1
                        continue
                    raise
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        except Exception as e:
            log.error(f"Store failed for EID {event.get('event_id')}: {e}")
            result.reject_reason = f"store_error:{e}"

    def _store_encrypted_cols(self, conn, category: str, row_id: int, enc_cols: dict):
        """
        FR02-01: Update the newly inserted row with encrypted field columns.
        Uses ALTER TABLE ADD COLUMN to add columns on first use (auto-migrate).
        """
        try:
            c = conn.cursor()

            # Ensure encrypted columns exist (auto-migrate on first HE-encrypted event)
            c.execute(f"PRAGMA table_info(logs_{category})")
            existing = {row[1] for row in c.fetchall()}
            new_cols = [
                ("enc_username",     "TEXT"),
                ("enc_ip_address",   "TEXT"),
                ("enc_machine_name", "TEXT"),
                ("ip_pseudonym",     "TEXT"),
                ("user_pseudonym",   "TEXT"),
                ("he_kid",           "TEXT"),
            ]
            for col_name, col_type in new_cols:
                if col_name not in existing:
                    try:
                        conn.execute(f"ALTER TABLE logs_{category} ADD COLUMN {col_name} {col_type}")
                        conn.commit()
                        log.info(f"Auto-migrated logs_{category}: added {col_name}")
                    except Exception:
                        pass

            # UPDATE the row with encrypted values
            conn.execute(f"""
                UPDATE logs_{category}
                SET enc_username     = ?,
                    enc_ip_address   = ?,
                    enc_machine_name = ?,
                    ip_pseudonym     = ?,
                    user_pseudonym   = ?,
                    he_kid           = ?
                WHERE id = ?
            """, (
                enc_cols.get("enc_username"),
                enc_cols.get("enc_ip_address"),
                enc_cols.get("enc_machine_name"),
                enc_cols.get("ip_pseudonym"),
                enc_cols.get("user_pseudonym"),
                enc_cols.get("he_kid"),
                row_id,
            ))
            conn.commit()
        except Exception as e:
            log.warning(f"Could not write encrypted columns: {e}")

    # ── Stage 7: Per-event rule check ─────────────────────────────────────────

    def _run_rules(self, event: dict, norm: dict, category: str,
                   risk_score: int, result: PipelineResult):
        try:
            if self._rule_engine:
                alerts = self._rule_engine.check_event(event, norm, category, risk_score)
                if alerts:
                    result.stages_passed.append("rule_check")
                    return alerts
        except Exception as e:
            log.warning(f"Rule engine error: {e}")
        return []

    # ── Stage 8: Alert ────────────────────────────────────────────────────────

    def _maybe_alert(self, event: dict, norm: dict, category: str,
                     risk_score: int, rule_alerts: list, result: PipelineResult):
        """
        Decide whether this event deserves a real-time alert.

        REWRITE — was: "any event with score >= 8 fires an alert", which
        meant routine activity (a single 4625 typo, every 4672 admin logon,
        every 4688 process create) flooded the dashboard with alerts.

        New policy:
          - score >= 15  → always fire (CRITICAL — real attack indicators)
          - score 8-14   → fire only when a curated rule_alert also fired,
                           i.e. there is corroborating context (correlator
                           hit, pattern from rule engine, etc.). Otherwise
                           the event is still recorded in the logs table
                           but does not generate a live notification.
          - rule_alerts  → always fire (these come from the rule engine
                           with their own gating)
        The downstream alert_bus.push() then applies a second pass of
        dedup + routine-account suppression.
        """
        try:
            if not self._alert_bus:
                return

            from core.analysis_engine.risk_scorer import EVENT_RISK
            eid   = int(event.get("event_id") or 0)
            label = EVENT_RISK.get(eid, {}).get("label", f"Event {eid}")

            fire_high_risk = False
            if risk_score >= 15:
                fire_high_risk = True
            elif risk_score >= 8 and rule_alerts:
                # corroborated mid-tier — let it through
                fire_high_risk = True

            if fire_high_risk:
                self._alert_bus.push({
                    "type":       "high_risk_event",
                    "severity":   "CRITICAL" if risk_score >= 15 else "HIGH",
                    "event_id":   eid,
                    "label":      label,
                    "category":   category,
                    "risk_score": risk_score,
                    # FR02-03: pseudonym instead of plaintext IP/user
                    "user":       norm.get("user"),
                    "ip":         norm.get("ip"),
                    "source":     event.get("source"),
                    "timestamp":  event.get("timestamp"),
                    "message":    (event.get("message") or "")[:200],
                    "he_encrypted": result.he_encrypted,
                })
                result.alert_fired = True

            for alert in rule_alerts:
                self._alert_bus.push(alert)
                result.alert_fired = True

            if result.alert_fired:
                result.stages_passed.append("alert")
                with self._lock:
                    self._stats["alerts_fired"] += 1
        except Exception as e:
            log.warning(f"Alert push failed: {e}")

    # ── Main entry points ─────────────────────────────────────────────────────

    def process(self, event: dict, category: str) -> PipelineResult:
        """
        Process a single raw event through the full pipeline.
        Thread-safe. Never raises.
        """
        self._lazy_init()
        result = PipelineResult()

        with self._lock:
            self._stats["processed"] += 1

        # Stage 1: Validate
        if not self._validate(event, result):
            with self._lock:
                self._stats["rejected"] += 1
            return result

        # Stage 2: Normalize
        norm = self._normalize(event, result)

        # Stage 2.5: HE Encrypt sensitive fields (FR02-01, FR02-03, FR02-04, FR02-05)
        event = self._he_encrypt(event, norm, result)

        # Stage 3: Deduplicate
        event_hash = self._dedup_hash(event, category)
        if self._is_duplicate(event_hash, result):
            with self._lock:
                self._stats["duplicates"] += 1
            return result

        # Stage 4: Risk Score
        risk_score, risk_category = self._score(event, norm, result)

        # Stage 5: Enrich
        self._enrich(event, norm, category)

        # Stage 6: Store (includes encrypted columns — FR02-01)
        self._store(event, norm, category, risk_score, risk_category, event_hash, result)
        if result.reject_reason:
            with self._lock:
                self._stats["rejected"] += 1
            return result

        self._record_dedup(event_hash, category)

        # Stage 7: Per-event rules
        rule_alerts = self._run_rules(event, norm, category, risk_score, result)

        # Stage 8: Alert
        self._maybe_alert(event, norm, category, risk_score, rule_alerts, result)

        result.accepted = True
        with self._lock:
            self._stats["accepted"] += 1

        return result

    def process_batch(self, events: list, category: str) -> dict:
        """Process a list of events. Returns summary stats."""
        self._lazy_init()
        results = {"accepted": 0, "duplicates": 0, "rejected": 0, "alerts": 0}

        if len(events) > 500:
            chunk_size = 200
            chunks     = [events[i:i+chunk_size] for i in range(0, len(events), chunk_size)]
            chunk_results = [None] * len(chunks)

            def _worker(idx, chunk):
                r = {"accepted": 0, "duplicates": 0, "rejected": 0, "alerts": 0}
                for ev in chunk:
                    pr = self.process(ev, category)
                    r["accepted"]   += int(pr.accepted)
                    r["duplicates"] += int(pr.duplicate)
                    r["rejected"]   += int(pr.reject_reason is not None and not pr.duplicate)
                    r["alerts"]     += int(pr.alert_fired)
                chunk_results[idx] = r

            import threading as _t
            threads = []
            for i, chunk in enumerate(chunks):
                t = _t.Thread(target=_worker, args=(i, chunk), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=30)
            for r in chunk_results:
                if r:
                    for k in results:
                        results[k] += r[k]
        else:
            for ev in events:
                pr = self.process(ev, category)
                results["accepted"]   += int(pr.accepted)
                results["duplicates"] += int(pr.duplicate)
                results["rejected"]   += int(pr.reject_reason is not None and not pr.duplicate)
                results["alerts"]     += int(pr.alert_fired)

        return results

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def decrypt_field_from_db(self, enc_json: str) -> str:
        """
        Decrypt an encrypted field value retrieved from the DB.
        Call only after verifying the user has access rights.
        FR02-01: This is the ONLY authorized decryption path for PII fields.
        """
        self._lazy_init()
        if self._he is None:
            raise RuntimeError("HE engine not available")
        return self._he.decrypt_field(enc_json)


# ── Singleton ─────────────────────────────────────────────────────────────────

_pipeline_instance: Optional[EventPipeline] = None
_pipeline_lock = threading.Lock()


def get_pipeline() -> EventPipeline:
    """Return the global singleton pipeline. Thread-safe."""
    global _pipeline_instance
    if _pipeline_instance is None:
        with _pipeline_lock:
            if _pipeline_instance is None:
                _pipeline_instance = EventPipeline()
                log.info("EventPipeline singleton created")
    return _pipeline_instance
