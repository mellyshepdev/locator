"""Postgres persistence for Locator.

Backs the in-memory `registry` dict (nodes/services), the event log, and the
client-error log with a real database (unit3, reachable over the Tailscale
mesh) instead of registry.json / process memory. The in-memory `registry`
dict in locator.py remains the runtime source of truth that all the existing
read/write call sites use — this module only handles snapshotting it to and
restoring it from Postgres, plus the append-only events/client_errors tables.

If DATABASE_URL isn't set or the DB is unreachable, every function here
degrades to a no-op (logged once) so locator.py keeps working off
registry.json/in-memory state alone, same as before this module existed.
"""

import os
import json
import threading
from contextlib import contextmanager

try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool
    _PSYCOPG2_AVAILABLE = True
except ImportError:
    _PSYCOPG2_AVAILABLE = False

DATABASE_URL = os.environ.get("DATABASE_URL", "")

_pool = None
_pool_lock = threading.Lock()
_warned = False


def _warn_once(msg):
    global _warned
    if not _warned:
        print(f"⚠️  db.py: {msg} — falling back to registry.json/in-memory only")
        _warned = True


def _get_pool():
    global _pool
    if not _PSYCOPG2_AVAILABLE:
        _warn_once("psycopg2 not installed")
        return None
    if not DATABASE_URL:
        return None
    if _pool is not None:
        return _pool
    with _pool_lock:
        if _pool is None:
            try:
                _pool = psycopg2.pool.ThreadedConnectionPool(1, 5, dsn=DATABASE_URL)
            except Exception as e:
                _warn_once(f"could not connect to Postgres ({e})")
                return None
    return _pool


@contextmanager
def _conn():
    pool = _get_pool()
    if pool is None:
        yield None
        return
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id         TEXT PRIMARY KEY,
    data       JSONB NOT NULL,
    status     TEXT,
    last_seen  TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS services (
    id         TEXT PRIMARY KEY,
    data       JSONB NOT NULL,
    category   TEXT,
    status     TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS registry_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id         BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    data       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at DESC);

CREATE TABLE IF NOT EXISTS client_errors (
    id          BIGSERIAL PRIMARY KEY,
    message     TEXT,
    stack       TEXT,
    source_url  TEXT,
    page_url    TEXT,
    line        INT,
    col         INT,
    user_agent  TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_client_errors_received_at ON client_errors (received_at DESC);
"""


def init_schema():
    """Create tables if they don't exist. Safe to call on every startup."""
    with _conn() as conn:
        if conn is None:
            return
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
        print("🗄️  db.py: schema ready")


def save_registry_snapshot(registry):
    """Upsert the full in-memory registry (nodes + services) into Postgres.
    Called from persist_registry() alongside the existing registry.json write."""
    with _conn() as conn:
        if conn is None:
            return
        with conn.cursor() as cur:
            for node_id, data in registry.get("nodes", {}).items():
                cur.execute(
                    """INSERT INTO nodes (id, data, status, last_seen, updated_at)
                       VALUES (%s, %s, %s, %s, now())
                       ON CONFLICT (id) DO UPDATE
                       SET data = EXCLUDED.data, status = EXCLUDED.status,
                           last_seen = EXCLUDED.last_seen, updated_at = now()""",
                    (node_id, json.dumps(data), data.get("status"), data.get("last_seen") or None),
                )
            for svc_id, data in registry.get("services", {}).items():
                cur.execute(
                    """INSERT INTO services (id, data, category, status, updated_at)
                       VALUES (%s, %s, %s, %s, now())
                       ON CONFLICT (id) DO UPDATE
                       SET data = EXCLUDED.data, category = EXCLUDED.category,
                           status = EXCLUDED.status, updated_at = now()""",
                    (svc_id, json.dumps(data), data.get("category"), data.get("status")),
                )
            cur.execute(
                """INSERT INTO registry_meta (key, value) VALUES ('updated', %s)
                   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""",
                (registry.get("updated", ""),),
            )


def load_registry_snapshot():
    """Return {'nodes': {...}, 'services': {...}, 'updated': str} from Postgres,
    or None if unavailable/empty. Used on startup to restore state instead of
    (or in addition to) registry.json."""
    with _conn() as conn:
        if conn is None:
            return None
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, data FROM nodes")
            nodes = {row["id"]: row["data"] for row in cur.fetchall()}
            cur.execute("SELECT id, data FROM services")
            services = {row["id"]: row["data"] for row in cur.fetchall()}
            cur.execute("SELECT value FROM registry_meta WHERE key = 'updated'")
            row = cur.fetchone()
            updated = row["value"] if row else ""
        if not nodes and not services:
            return None
        return {"nodes": nodes, "services": services, "updated": updated}


def insert_event(event_type, data):
    with _conn() as conn:
        if conn is None:
            return
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO events (event_type, data) VALUES (%s, %s) RETURNING id, created_at",
                (event_type, json.dumps(data)),
            )
            row = cur.fetchone()
            return {"id": row[0], "created_at": row[1].isoformat(), "type": event_type, **data}


def list_events(limit=200):
    with _conn() as conn:
        if conn is None:
            return []
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, event_type, data, created_at FROM events ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {"id": r["id"], "type": r["event_type"], "timestamp": r["created_at"].isoformat(), **r["data"]}
            for r in reversed(rows)
        ]


def insert_client_error(entry):
    with _conn() as conn:
        if conn is None:
            return
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO client_errors
                   (message, stack, source_url, page_url, line, col, user_agent, received_at)
                   VALUES (%(message)s, %(stack)s, %(source_url)s, %(page_url)s,
                           %(line)s, %(col)s, %(user_agent)s, %(received_at)s)""",
                entry,
            )


def list_client_errors(limit=300):
    with _conn() as conn:
        if conn is None:
            return None
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT message, stack, source_url, page_url, line, col, user_agent, received_at
                   FROM client_errors ORDER BY received_at DESC LIMIT %s""",
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {
                "message": r["message"], "stack": r["stack"], "source_url": r["source_url"],
                "page_url": r["page_url"], "line": r["line"], "col": r["col"],
                "user_agent": r["user_agent"], "received_at": r["received_at"].isoformat(),
            }
            for r in rows
        ]
