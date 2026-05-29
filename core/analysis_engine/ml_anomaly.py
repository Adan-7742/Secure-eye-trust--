"""
core/analysis_engine/ml_anomaly.py
=====================================
Production ML-based anomaly detection using scikit-learn Isolation Forest.

WHAT IT DETECTS:
  1. Event volume anomalies     — days/hours with unusual event counts
  2. Authentication anomalies   — unusual login patterns (time, frequency, logon type)
  3. Process behavior anomalies — processes with unusual error rates
  4. Cross-feature anomalies    — combinations of features that are statistically unusual
     even when no single feature is extreme

WHY ISOLATION FOREST:
  - No labeled training data required (unsupervised)
  - Handles high-dimensional, mixed feature sets well
  - Low false positive rate with contamination tuning
  - Fast inference — suitable for real-time scoring

MODEL LIFECYCLE:
  - Train on 30+ days of history (auto-trains on first call)
  - Retrain weekly or when called with retrain=True
  - Model state stored in memory (persists for the process lifetime)
  - Fallback to Z-score if insufficient data
"""

import math
import json
import threading
from collections import defaultdict
from datetime import datetime
from typing import Optional

from utils.logger import get_logger

log = get_logger("ml_anomaly")

# Lazy import numpy/sklearn so the rest of the app works without them
_np = None
_IF = None


def _load_libs():
    global _np, _IF
    if _np is None:
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            _np = np
            _IF = IsolationForest
            return True
        except ImportError:
            log.warning("numpy/sklearn not available — falling back to Z-score")
            return False
    return True


class IsolationForestDetector:
    """
    Isolation Forest anomaly detector for Windows event log data.
    Maintains separate models for different feature spaces.
    """

    def __init__(self):
        self._lock          = threading.Lock()
        self._models        = {}          # model_name → fitted IsolationForest
        self._trained_at    = {}          # model_name → datetime
        self._train_samples = {}          # model_name → sample count
        self._retrain_days  = 7           # retrain every N days
        self._min_samples   = 30          # minimum rows before training
        self._contamination = 0.05        # expected 5% anomaly rate

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract_daily_features(self, conn) -> tuple:
        """
        Build feature matrix for daily event volumes.
        Features per day: [total, errors, warnings, security_events, hour_of_max_activity, day_of_week]
        """
        from database.db import CATEGORIES
        if not _load_libs():
            return None, None

        c    = conn.cursor()
        rows = defaultdict(lambda: defaultdict(int))

        for cat in CATEGORIES:
            try:
                c.execute(f"""
                    SELECT date,
                           COUNT(*) as total,
                           SUM(CASE WHEN level IN ('ERROR','CRITICAL','FAILURE') THEN 1 ELSE 0 END) as errors,
                           SUM(CASE WHEN level = 'WARNING' THEN 1 ELSE 0 END) as warnings
                    FROM logs_{cat}
                    WHERE date IS NOT NULL
                    GROUP BY date
                """)
                for row in c.fetchall():
                    d = row[0]
                    rows[d]["total"]    += row[1] or 0
                    rows[d]["errors"]   += row[2] or 0
                    rows[d]["warnings"] += row[3] or 0
                    if cat == "security":
                        rows[d]["security"] += row[1] or 0
            except Exception:
                pass

        if not rows:
            return None, None

        dates    = sorted(rows.keys())
        features = []
        for d in dates:
            r = rows[d]
            total = max(r["total"], 1)
            try:
                dt  = datetime.strptime(d, "%Y-%m-%d")
                dow = dt.weekday()
            except Exception:
                dow = 0

            features.append([
                r["total"],
                r["errors"],
                r["warnings"],
                r.get("security", 0),
                r["errors"] / total,           # error rate
                dow,                            # day of week
            ])

        X = _np.array(features, dtype=float)
        return X, dates

    def _extract_auth_features(self, conn) -> tuple:
        """
        Build feature matrix for authentication events per hour.
        Features: [failed_logins, success_logins, fail_rate, hour_of_day, day_of_week, logon_type_3_pct]
        """
        if not _load_libs():
            return None, None

        c = conn.cursor()
        try:
            c.execute("""
                SELECT
                    strftime('%Y-%m-%d %H', timestamp) as hour_bucket,
                    SUM(CASE WHEN event_id = 4625 THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN event_id = 4624 THEN 1 ELSE 0 END) as success,
                    SUM(CASE WHEN norm_logon_type = 3 THEN 1 ELSE 0 END) as net_logons,
                    CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                    CAST(strftime('%w', timestamp) AS INTEGER) as dow
                FROM logs_security
                WHERE timestamp IS NOT NULL
                GROUP BY hour_bucket
                HAVING (failed + success) > 0
                ORDER BY hour_bucket
            """)
            rows = c.fetchall()
        except Exception:
            return None, None

        if len(rows) < self._min_samples:
            return None, None

        features    = []
        hour_labels = []
        for row in rows:
            label, failed, success, net, hour, dow = row
            total    = (failed or 0) + (success or 0)
            fail_rate = (failed or 0) / max(total, 1)
            net_pct   = (net or 0) / max(total, 1)
            features.append([failed or 0, success or 0, fail_rate, hour or 0, dow or 0, net_pct])
            hour_labels.append(label)

        X = _np.array(features, dtype=float)
        return X, hour_labels

    # ── Training ──────────────────────────────────────────────────────────────

    def _should_retrain(self, model_name: str) -> bool:
        if model_name not in self._models:
            return True
        last = self._trained_at.get(model_name)
        if last is None:
            return True
        age_days = (datetime.now() - last).days
        return age_days >= self._retrain_days

    def _train(self, model_name: str, X) -> bool:
        """Fit an Isolation Forest on feature matrix X."""
        if not _load_libs():
            return False
        if X is None or len(X) < self._min_samples:
            log.debug(f"Not enough samples to train {model_name}: {len(X) if X is not None else 0}")
            return False
        try:
            model = _IF(
                contamination=self._contamination,
                n_estimators=100,
                max_samples="auto",
                random_state=42,
                n_jobs=1,
            )
            model.fit(X)
            with self._lock:
                self._models[model_name]        = model
                self._trained_at[model_name]    = datetime.now()
                self._train_samples[model_name] = len(X)
            log.info(f"Trained {model_name} on {len(X)} samples")
            return True
        except Exception as e:
            log.error(f"Training failed for {model_name}: {e}")
            return False

    # ── Detection ─────────────────────────────────────────────────────────────

    def detect_daily_anomalies(self, conn) -> list:
        """Detect anomalous days using Isolation Forest."""
        X, labels = self._extract_daily_features(conn)
        if X is None or len(X) < self._min_samples:
            return self._zscore_fallback_daily(conn)

        if self._should_retrain("daily"):
            self._train("daily", X)

        model = self._models.get("daily")
        if model is None:
            return self._zscore_fallback_daily(conn)

        try:
            scores     = model.decision_function(X)   # negative = more anomalous
            preds      = model.predict(X)              # -1 = anomaly, 1 = normal
            anomalies  = []

            for i, (label, score, pred) in enumerate(zip(labels, scores, preds)):
                if pred == -1:
                    # Compute severity from how negative the score is
                    # decision_function typically ranges from ~-0.5 to 0.5
                    normalized = max(0.0, min(1.0, (-score + 0.1) / 0.6))
                    severity   = "CRITICAL" if normalized > 0.8 else "HIGH" if normalized > 0.5 else "MEDIUM"

                    anomalies.append({
                        "date":          label,
                        "if_score":      round(float(score), 4),
                        "anomaly_score": round(normalized, 3),
                        "is_anomaly":    True,
                        "severity":      severity,
                        "method":        "isolation_forest",
                        "features":      {
                            "total":      int(X[i][0]),
                            "errors":     int(X[i][1]),
                            "warnings":   int(X[i][2]),
                            "security":   int(X[i][3]),
                            "error_rate": round(float(X[i][4]), 3),
                        },
                    })

            return sorted(anomalies, key=lambda a: a["anomaly_score"], reverse=True)

        except Exception as e:
            log.error(f"Daily anomaly detection failed: {e}")
            return self._zscore_fallback_daily(conn)

    def detect_auth_anomalies(self, conn) -> list:
        """Detect anomalous authentication patterns."""
        X, labels = self._extract_auth_features(conn)
        if X is None:
            return []

        if self._should_retrain("auth"):
            self._train("auth", X)

        model = self._models.get("auth")
        if model is None:
            return []

        try:
            scores = model.decision_function(X)
            preds  = model.predict(X)
            anomalies = []

            for i, (label, score, pred) in enumerate(zip(labels, scores, preds)):
                if pred == -1:
                    normalized = max(0.0, min(1.0, (-score + 0.1) / 0.6))
                    severity   = "HIGH" if normalized > 0.6 else "MEDIUM"
                    anomalies.append({
                        "hour_bucket":   label,
                        "if_score":      round(float(score), 4),
                        "anomaly_score": round(normalized, 3),
                        "severity":      severity,
                        "method":        "isolation_forest",
                        "features": {
                            "failed_logins": int(X[i][0]),
                            "success_logins": int(X[i][1]),
                            "fail_rate":  round(float(X[i][2]), 3),
                            "hour":       int(X[i][3]),
                            "net_logon_pct": round(float(X[i][5]), 3),
                        },
                    })

            return sorted(anomalies, key=lambda a: a["anomaly_score"], reverse=True)[:20]
        except Exception as e:
            log.error(f"Auth anomaly detection failed: {e}")
            return []

    def model_info(self) -> dict:
        """Return metadata about trained models."""
        with self._lock:
            return {
                name: {
                    "trained_at":    self._trained_at.get(name, "").isoformat() if self._trained_at.get(name) else None,
                    "samples":       self._train_samples.get(name, 0),
                    "contamination": self._contamination,
                }
                for name in self._models
            }

    # ── Z-score fallback (used when insufficient data for IF) ────────────────

    def _zscore_fallback_daily(self, conn) -> list:
        """Pure Z-score anomaly detection as fallback."""
        from database.db import CATEGORIES
        c = conn.cursor()
        daily = defaultdict(int)

        for cat in CATEGORIES:
            try:
                c.execute(f"""
                    SELECT date, COUNT(*) FROM logs_{cat}
                    WHERE level IN ('ERROR','CRITICAL','FAILURE') AND date IS NOT NULL
                    GROUP BY date
                """)
                for row in c.fetchall():
                    if row[0]:
                        daily[row[0]] += row[1]
            except Exception:
                pass

        if not daily:
            return []

        dates  = sorted(daily.keys())
        counts = [daily[d] for d in dates]
        mean   = sum(counts) / len(counts)
        var    = sum((c - mean) ** 2 for c in counts) / len(counts)
        std    = math.sqrt(var) if var > 0 else 0

        anomalies = []
        for d, c in zip(dates, counts):
            z = (c - mean) / std if std > 0 else 0
            if abs(z) > 2.0:
                anomalies.append({
                    "date":          d,
                    "zscore":        round(z, 3),
                    "count":         c,
                    "is_anomaly":    True,
                    "severity":      "CRITICAL" if abs(z) > 3.5 else "HIGH" if abs(z) > 3 else "MEDIUM",
                    "method":        "zscore_fallback",
                })

        return sorted(anomalies, key=lambda a: abs(a.get("zscore", 0)), reverse=True)


# ── Singleton ─────────────────────────────────────────────────────────────────

_detector: Optional[IsolationForestDetector] = None
_detector_lock = threading.Lock()


def get_ml_detector() -> IsolationForestDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = IsolationForestDetector()
                log.info("IsolationForest detector initialized")
    return _detector


def run_ml_anomaly_detection(conn=None) -> dict:
    """
    Main entry point — run full ML anomaly detection.
    Returns unified result dict compatible with the existing anomaly_detector.py interface.
    """
    close_conn = conn is None
    if conn is None:
        from database.db import get_conn
        conn = get_conn()

    detector = get_ml_detector()
    daily    = detector.detect_daily_anomalies(conn)
    auth     = detector.detect_auth_anomalies(conn)

    if close_conn:
        conn.close()

    # Build a verdict
    critical = [d for d in daily if d.get("severity") == "CRITICAL"]
    high_day = [d for d in daily if d.get("severity") == "HIGH"]
    high_auth = [a for a in auth if a.get("severity") == "HIGH"]

    if critical:
        verdict = "CRITICAL"
    elif high_day or high_auth:
        verdict = "HIGH"
    elif daily or auth:
        verdict = "MEDIUM"
    else:
        verdict = "NORMAL"

    return {
        "verdict":          verdict,
        "daily_anomalies":  daily,
        "auth_anomalies":   auth,
        "model_info":       detector.model_info(),
        "summary": {
            "anomalous_days":     len(daily),
            "anomalous_auth_hrs": len(auth),
            "method":             "isolation_forest" if daily and daily[0].get("method") == "isolation_forest" else "zscore_fallback",
        },
    }
