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
import time
from contextlib import contextmanager

try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool
    _PSYCOPG2_AVAILABLE = True
except ImportError:
    _PSYCOPG2_AVAILABLE = False

DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Locator runs a dozen background threads plus gunicorn's gthread pool, and any
# of them can touch Postgres — heartbeat snapshots, the event log, SSE readers,
# now the command-run recorder. A ceiling of 5 was reached the first time four
# exec jobs were queued at once: every insert failed with "connection pool
# exhausted" and the runs went unrecorded, which is precisely the blindness this
# is all meant to remove. Sized for the thread count, not the query rate.
DB_POOL_MIN = int(os.environ.get("DB_POOL_MIN", 1))
DB_POOL_MAX = int(os.environ.get("DB_POOL_MAX", 20))
DB_CONNECT_TIMEOUT = int(os.environ.get("DB_CONNECT_TIMEOUT", 10))
DB_STATEMENT_TIMEOUT_MS = int(os.environ.get("DB_STATEMENT_TIMEOUT_MS", 15000))

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
                # Bounded waits, both of them. The database is now a tailnet hop
                # away, so an unreachable unit8 or a wedged query must fail the
                # caller rather than park a gunicorn thread forever — locator
                # degrading to registry.json is survivable, locator not answering
                # is not.
                _pool = psycopg2.pool.ThreadedConnectionPool(
                    DB_POOL_MIN, DB_POOL_MAX, dsn=DATABASE_URL,
                    connect_timeout=DB_CONNECT_TIMEOUT,
                    options=f"-c statement_timeout={DB_STATEMENT_TIMEOUT_MS}",
                )
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
    # A burst can still momentarily drain the pool. Wait briefly rather than
    # dropping the write: these calls are short, so a connection frees up fast,
    # and a lost row is worse than a few hundred ms of latency.
    conn = None
    for attempt in range(4):
        try:
            conn = pool.getconn()
            break
        except psycopg2.pool.PoolError:
            if attempt == 3:
                raise
            time.sleep(0.25 * (attempt + 1))
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

-- Every exec job locator hands a unit, and how it ended.
--
-- The in-memory command_queue in locator.py is capped and dies with the
-- process, so before this table a scheduled run left no trace at all: a unit
-- whose refresh failed looked exactly like a unit whose refresh never ran.
-- Rows are written when a command is queued and updated when the unit reports
-- back, so a run that never reports is still visible -- as PENDING/DISPATCHED
-- until the reaper ages it out to MISSED/TIMEOUT, which is the case that
-- matters (a dead lokey, or a unit that dropped off the mesh).
CREATE TABLE IF NOT EXISTS command_runs (
    id            TEXT PRIMARY KEY,
    unit          TEXT NOT NULL,
    label         TEXT,
    source        TEXT,
    script        TEXT,
    job_id        TEXT,
    status        TEXT NOT NULL,
    success       BOOLEAN,
    exit_code     INT,
    queued_at     TIMESTAMPTZ,
    dispatched_at TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    duration_ms   INT,
    stdout        TEXT,
    stderr        TEXT,
    error         TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_command_runs_unit_queued  ON command_runs (unit, queued_at DESC);
CREATE INDEX IF NOT EXISTS idx_command_runs_label_queued ON command_runs (label, queued_at DESC);
CREATE INDEX IF NOT EXISTS idx_command_runs_open         ON command_runs (status)
    WHERE status IN ('PENDING', 'DISPATCHED');
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
    Called from persist_registry() alongside the existing registry.json write.

    Sent as two batched statements, not one per row. Row-at-a-time was harmless
    while Postgres was a container away on the same host, but locator now runs
    on unit4 and the database on unit8: at ~60ms of tailnet round trip, 346 rows
    is over twenty seconds per snapshot, with a pooled connection held the whole
    time. Heartbeats arrive faster than that, so the snapshots stacked up until
    every gunicorn thread was blocked and locator stopped answering — it looked
    exactly like a crash. execute_values collapses each loop to a single round
    trip.
    """
    with _conn() as conn:
        if conn is None:
            return
        nodes = [
            (node_id, json.dumps(data), data.get("status"), data.get("last_seen") or None)
            for node_id, data in registry.get("nodes", {}).items()
        ]
        services = [
            (svc_id, json.dumps(data), data.get("category"), data.get("status"))
            for svc_id, data in registry.get("services", {}).items()
        ]
        with conn.cursor() as cur:
            if nodes:
                psycopg2.extras.execute_values(
                    cur,
                    """INSERT INTO nodes (id, data, status, last_seen, updated_at)
                       VALUES %s
                       ON CONFLICT (id) DO UPDATE
                       SET data = EXCLUDED.data, status = EXCLUDED.status,
                           last_seen = EXCLUDED.last_seen, updated_at = now()""",
                    nodes,
                    template="(%s, %s, %s, %s, now())",
                    page_size=500,
                )
            if services:
                psycopg2.extras.execute_values(
                    cur,
                    """INSERT INTO services (id, data, category, status, updated_at)
                       VALUES %s
                       ON CONFLICT (id) DO UPDATE
                       SET data = EXCLUDED.data, category = EXCLUDED.category,
                           status = EXCLUDED.status, updated_at = now()""",
                    services,
                    template="(%s, %s, %s, %s, now())",
                    page_size=500,
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


def record_command_run(cmd):
    """Insert (or refresh) the row for a queued exec command.

    Called from _queue_exec_command, so the record exists from the moment the
    job is handed out rather than only once it reports back -- the whole point
    is that a run which never completes still leaves evidence.
    """
    with _conn() as conn:
        if conn is None:
            return
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO command_runs
                       (id, unit, label, source, script, job_id, status, queued_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
                   ON CONFLICT (id) DO UPDATE
                   SET status = EXCLUDED.status, updated_at = now()""",
                (cmd.get("id"), cmd.get("unit"), cmd.get("label"), cmd.get("source"),
                 cmd.get("script"), cmd.get("job_id"), cmd.get("status", "PENDING"),
                 cmd.get("queued_at") or None),
            )


def update_command_run(cmd, error=None, duration_ms=None):
    """Write a command's outcome back to its row: status, exit code, output, timings."""
    with _conn() as conn:
        if conn is None:
            return
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE command_runs
                      SET status = %s, success = %s, exit_code = %s,
                          dispatched_at = COALESCE(%s, dispatched_at),
                          completed_at  = COALESCE(%s, completed_at),
                          duration_ms   = COALESCE(%s, duration_ms),
                          stdout = COALESCE(%s, stdout),
                          stderr = COALESCE(%s, stderr),
                          error  = COALESCE(%s, error),
                          updated_at = now()
                    WHERE id = %s""",
                (cmd.get("status"), cmd.get("success"), cmd.get("exit_code"),
                 cmd.get("dispatched_at") or None, cmd.get("completed_at") or None,
                 duration_ms, cmd.get("stdout"), cmd.get("stderr"), error, cmd.get("id")),
            )


def close_orphaned_runs(keep_ids=(), reason="locator restarted before the unit reported back"):
    """Age out rows left open by a locator restart.

    The command queue is in-memory, so anything still PENDING/DISPATCHED after a
    restart can never be completed -- without this it would sit "in progress"
    forever and read as a hung unit. Returns the rows it closed so the caller
    can log them.
    """
    with _conn() as conn:
        if conn is None:
            return []
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """UPDATE command_runs
                      SET status = 'LOST', success = false, error = %s, updated_at = now()
                    WHERE status IN ('PENDING', 'DISPATCHED')
                      AND NOT (id = ANY(%s))
                RETURNING id, unit, label, queued_at""",
                (reason, list(keep_ids)),
            )
            rows = cur.fetchall()
        return [dict(r, queued_at=(r["queued_at"].isoformat() if r["queued_at"] else None))
                for r in rows]


def get_command_run(cmd_id):
    """One run row by id, or None.

    Lets a completion report be honoured even when the in-memory queue no longer
    holds the command — which is the normal case when the unit being refreshed is
    the one hosting locator: refresh redeploys locator, and the result arrives
    after the restart.
    """
    with _conn() as conn:
        if conn is None:
            return None
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM command_runs WHERE id = %s", (cmd_id,))
            row = cur.fetchone()
        return _run_row(row) if row else None


def _run_row(r, with_output=True):
    out = {
        "id": r["id"], "unit": r["unit"], "label": r["label"], "source": r["source"],
        "job_id": r["job_id"], "status": r["status"], "success": r["success"],
        "exit_code": r["exit_code"], "duration_ms": r["duration_ms"], "error": r["error"],
    }
    for field in ("queued_at", "dispatched_at", "completed_at"):
        value = r.get(field)
        out[field] = value.isoformat() if value else None
    if with_output:
        out["script"] = r.get("script")
        out["stdout"] = r.get("stdout")
        out["stderr"] = r.get("stderr")
    return out


def list_command_runs(unit=None, label=None, limit=100, with_output=True):
    """Run history, newest first, optionally narrowed to one unit and/or label."""
    with _conn() as conn:
        if conn is None:
            return []
        clauses, params = [], []
        if unit:
            clauses.append("unit = %s")
            params.append(unit)
        if label:
            clauses.append("label = %s")
            params.append(label)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM command_runs {where} ORDER BY queued_at DESC NULLS LAST LIMIT %s",
                params,
            )
            rows = cur.fetchall()
        return [_run_row(r, with_output) for r in rows]


def latest_run_per_unit(label):
    """The most recent run of `label` on each unit -- the per-unit status view."""
    with _conn() as conn:
        if conn is None:
            return {}
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT DISTINCT ON (unit) *
                     FROM command_runs
                    WHERE label = %s
                 ORDER BY unit, queued_at DESC""",
                (label,),
            )
            rows = cur.fetchall()
        return {r["unit"]: _run_row(r, with_output=False) for r in rows}


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
