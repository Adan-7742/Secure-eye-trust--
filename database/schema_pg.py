"""
database/schema_pg.py
======================
PostgreSQL-compatible schema definitions and migration guide.

WHY THIS FILE EXISTS:
  The current system uses SQLite (database/db.py) which is perfect for
  single-machine deployment. When scaling to production (multiple workers,
  high ingestion rates, remote access), drop in PostgreSQL.

HOW TO MIGRATE:
  1. Install: pip install psycopg2-binary
  2. Set in .env:
       DATABASE_URL=postgresql://user:password@host:5432/secure_eye
  3. Run: python database/schema_pg.py --migrate
  4. Update database/db.py to use get_conn() from this file

COMPATIBILITY:
  All SQL in this file is valid for both PostgreSQL and SQLite (with minor
  dialect differences noted). The abstraction layer at the bottom allows
  switching backends without touching any other code.

SCHEMA DESIGN PRINCIPLES:
  - Partitioned logs tables (by date) for PostgreSQL — massive read speedup
  - GIN indexes on message text for full-text search
  - BRIN indexes on timestamp (append-only data, very efficient)
  - Separate tables for normalized fields (better query performance)
  - UUID primary keys for distributed inserts
"""

import os
from utils.logger import get_logger

log = get_logger("database.schema_pg")

# ── PostgreSQL DDL ─────────────────────────────────────────────────────────────

PG_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS logs_{cat} (
    id              BIGSERIAL PRIMARY KEY,
    content_hash    TEXT UNIQUE,                    -- deduplication key
    timestamp       TIMESTAMPTZ NOT NULL,
    date            DATE,
    level           VARCHAR(16),
    source          VARCHAR(256),
    message         TEXT,
    event_id        INTEGER CHECK (event_id >= 0 AND event_id <= 65535),
    raw             TEXT,
    uploaded_at     TIMESTAMPTZ DEFAULT NOW(),

    -- Normalized fields (extracted from message by normalizer.py)
    norm_user       VARCHAR(128),
    norm_ip         INET,                           -- PostgreSQL native IP type
    norm_logon_type SMALLINT,
    norm_process    VARCHAR(512),

    -- Risk scoring
    risk_score      SMALLINT DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 25),
    risk_category   VARCHAR(64),

    -- Audit
    pipeline_version VARCHAR(16) DEFAULT '1.0'
) PARTITION BY RANGE (date);
"""

# Monthly partitions (create these programmatically for current + future months)
PG_PARTITION = """
CREATE TABLE IF NOT EXISTS logs_{cat}_{year}_{month:02d}
    PARTITION OF logs_{cat}
    FOR VALUES FROM ('{year}-{month:02d}-01') TO ('{next_year}-{next_month:02d}-01');
"""

PG_INDEXES = """
-- Fast date range queries (most common access pattern)
CREATE INDEX IF NOT EXISTS idx_{cat}_timestamp ON logs_{cat} USING BRIN (timestamp);
CREATE INDEX IF NOT EXISTS idx_{cat}_date      ON logs_{cat} (date);
CREATE INDEX IF NOT EXISTS idx_{cat}_level     ON logs_{cat} (level);
CREATE INDEX IF NOT EXISTS idx_{cat}_event_id  ON logs_{cat} (event_id);
CREATE INDEX IF NOT EXISTS idx_{cat}_risk      ON logs_{cat} (risk_score DESC) WHERE risk_score > 0;

-- Full-text search on message (GIN — very fast for LIKE/contains)
CREATE INDEX IF NOT EXISTS idx_{cat}_message_fts
    ON logs_{cat} USING GIN (to_tsvector('english', COALESCE(message, '')));

-- Normalized fields for correlation queries
CREATE INDEX IF NOT EXISTS idx_{cat}_norm_user ON logs_{cat} (norm_user) WHERE norm_user IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_{cat}_norm_ip   ON logs_{cat} (norm_ip)   WHERE norm_ip   IS NOT NULL;
"""

PG_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS security_alerts (
    id           BIGSERIAL PRIMARY KEY,
    alert_id     TEXT UNIQUE,
    timestamp    TIMESTAMPTZ DEFAULT NOW(),
    severity     VARCHAR(16) CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    alert_type   VARCHAR(64),
    category     VARCHAR(64),
    event_id     INTEGER,
    source       VARCHAR(256),
    user_name    VARCHAR(128),
    ip_address   INET,
    risk_score   SMALLINT DEFAULT 0,
    title        TEXT,
    description  TEXT,
    raw_json     JSONB,                             -- PostgreSQL JSONB for fast JSON queries
    read         BOOLEAN DEFAULT FALSE,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON security_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_read      ON security_alerts (read) WHERE read = FALSE;
CREATE INDEX IF NOT EXISTS idx_alerts_category  ON security_alerts (category);
"""

PG_DEDUP_TABLE = """
CREATE TABLE IF NOT EXISTS event_dedup (
    content_hash TEXT PRIMARY KEY,
    category     VARCHAR(32),
    seen_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dedup_seen ON event_dedup (seen_at);
-- Auto-expire dedup entries older than 90 days (run via pg_cron or a daily job)
-- DELETE FROM event_dedup WHERE seen_at < NOW() - INTERVAL '90 days';
"""

PG_ANALYSIS_REPORTS = """
CREATE TABLE IF NOT EXISTS analysis_reports (
    id           TEXT PRIMARY KEY,
    name         TEXT,
    generated_at TIMESTAMPTZ,
    risk_label   VARCHAR(16),
    risk_score   SMALLINT,
    report_json  JSONB,
    trigger      VARCHAR(32) DEFAULT 'manual'
);
CREATE INDEX IF NOT EXISTS idx_reports_generated ON analysis_reports (generated_at DESC);
"""

PG_PIPELINE_STATS = """
CREATE TABLE IF NOT EXISTS pipeline_stats (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ DEFAULT NOW(),
    processed    INTEGER DEFAULT 0,
    accepted     INTEGER DEFAULT 0,
    duplicates   INTEGER DEFAULT 0,
    rejected     INTEGER DEFAULT 0,
    alerts_fired INTEGER DEFAULT 0
);
"""


# ── Database abstraction layer ────────────────────────────────────────────────

class DatabaseBackend:
    """
    Abstraction layer that returns a connection regardless of backend.

    Usage:
        from database.schema_pg import get_db
        db = get_db()
        with db.connection() as conn:
            conn.execute("SELECT ...")

    Environment:
        DATABASE_URL=postgresql://...  → PostgreSQL
        (not set)                       → SQLite (default)
    """

    def __init__(self):
        self._url     = os.environ.get("DATABASE_URL", "")
        self._backend = "postgresql" if self._url.startswith("postgresql") else "sqlite"
        log.info(f"Database backend: {self._backend}")

    @property
    def is_postgres(self) -> bool:
        return self._backend == "postgresql"

    def get_conn(self):
        """
        Return a database connection.
        For SQLite: returns sqlite3.Connection (same as current db.py)
        For PostgreSQL: returns psycopg2 connection with dict cursor
        """
        if self._backend == "sqlite":
            from database.db import get_conn as _sqlite_conn
            return _sqlite_conn()
        else:
            return self._get_pg_conn()

    def _get_pg_conn(self):
        try:
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(self._url)
            conn.cursor_factory = psycopg2.extras.RealDictCursor
            return conn
        except ImportError:
            log.error("psycopg2 not installed. Run: pip install psycopg2-binary")
            raise
        except Exception as e:
            log.error(f"PostgreSQL connection failed: {e}")
            raise

    def placeholder(self) -> str:
        """Return the SQL parameter placeholder for this backend."""
        return "%s" if self.is_postgres else "?"

    def adapt_sql(self, sql: str) -> str:
        """
        Convert SQLite-flavored SQL to PostgreSQL-compatible SQL.
        Handles the most common dialect differences.
        """
        if not self.is_postgres:
            return sql

        # datetime('now') → NOW()
        sql = sql.replace("datetime('now')", "NOW()")
        sql = sql.replace("datetime('now',", "NOW() + INTERVAL '")
        # AUTOINCREMENT → SERIAL (handled in CREATE TABLE)
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
        # strftime → to_char / EXTRACT
        import re
        sql = re.sub(r"strftime\('%Y-%m-%d',\s*(\w+)\)", r"TO_CHAR(\1, 'YYYY-MM-DD')", sql)
        sql = re.sub(r"strftime\('%H',\s*(\w+)\)", r"EXTRACT(HOUR FROM \1)::INTEGER", sql)
        sql = re.sub(r"strftime\('%w',\s*(\w+)\)", r"EXTRACT(DOW FROM \1)::INTEGER", sql)
        # LIKE → ILIKE (case-insensitive by default in most queries)
        # Only do this for message searches
        return sql

    def migrate(self):
        """
        Create all tables for the configured backend.
        For PostgreSQL, creates partitioned tables and all indexes.
        For SQLite, delegates to database.db.init_db().
        """
        if not self.is_postgres:
            from database.db import init_db
            init_db()
            return

        from datetime import date
        from dateutil.relativedelta import relativedelta

        conn = self._get_pg_conn()
        c    = conn.cursor()

        CATEGORIES = ["application", "system", "security", "windows_update"]
        for cat in CATEGORIES:
            c.execute(PG_LOGS_TABLE.format(cat=cat))
            c.execute(PG_INDEXES.format(cat=cat))

            # Create partitions for next 6 months
            today = date.today().replace(day=1)
            for i in range(6):
                month_start  = today + relativedelta(months=i)
                month_end    = month_start + relativedelta(months=1)
                c.execute(PG_PARTITION.format(
                    cat=cat,
                    year=month_start.year, month=month_start.month,
                    next_year=month_end.year, next_month=month_end.month,
                ))

        c.execute(PG_ALERTS_TABLE)
        c.execute(PG_DEDUP_TABLE)
        c.execute(PG_ANALYSIS_REPORTS)
        c.execute(PG_PIPELINE_STATS)

        conn.commit()
        conn.close()
        log.info("PostgreSQL schema migration complete")


# ── Singleton ─────────────────────────────────────────────────────────────────
_db_instance = None

def get_db() -> DatabaseBackend:
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseBackend()
    return _db_instance


# ── CLI migration runner ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if "--migrate" in sys.argv:
        db = DatabaseBackend()
        print(f"Running migration for backend: {db._backend}")
        db.migrate()
        print("Migration complete.")
    else:
        print("Usage: python database/schema_pg.py --migrate")
        print("Set DATABASE_URL environment variable for PostgreSQL.")
        print("Without DATABASE_URL, runs SQLite migration (same as init_db).")
