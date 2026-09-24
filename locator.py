"""
═══════════════════════════════════════════════
  THE LOCATOR — Universal Service Registry
  
  Single source of truth for every service,
  container, API, and daemon in the mesh.
═══════════════════════════════════════════════
"""

import sys

TERMINAL_HELP = """\
🔦 THE LOCATOR — Universal Service Registry

Usage:
  python locator.py              Run the registry server (this file)
  locator <command> [args]       Terminal client (locatorctl.py)

Terminal commands:
  list             List every registered service with its current status
  status <name>    Show the current status of one service
  start <name>     Queue a container start on its host (runs via Lokey)
  stop <name>      Queue a container stop on its host (runs via Lokey)

  start/stop only confirm the command was queued — Lokey executes it on the
  container's actual host. Use `list`/`status` or the dashboard to see it land.

Server environment:
  PORT, HEARTBEAT_TIMEOUT, REAPER_INTERVAL, DATA_DIR,
  BALANCE_ENABLED, IDLE_ENABLED, GIT_AUTO_PUSH

Client environment:
  LOCATOR_URL      Registry URL (default: https://locator.prime-quality.online)
"""

# Handle -h/--help before the heavy imports so help works without deps installed
if __name__ == "__main__" and any(arg in ("-h", "--help") for arg in sys.argv[1:]):
    print(TERMINAL_HELP)
    raise SystemExit(0)

import os
import json
import socket
import http.client
import threading
import time
import uuid
import hmac
import queue as _queue_module
import requests
import urllib3
import re
import io
import ipaddress
import tempfile
import qrcode
import pandas as pd
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, Response, render_template, g

import notifier
import db
import clearance
import kc_admin
import bao
import renewals
import secretscan
import unitkeys

# ── CONFIG ──────────────────────────────────────────────────────────────────

PORT = int(os.environ.get("LOCATOR_PORT", 5000))
HEARTBEAT_TIMEOUT = int(os.environ.get("HEARTBEAT_TIMEOUT", 90))  # seconds
REAPER_INTERVAL = int(os.environ.get("REAPER_INTERVAL", 30))      # seconds
SCANNER_INTERVAL = int(os.environ.get("SCANNER_INTERVAL", 60))    # seconds
DUPLICATE_KILLER_INTERVAL = int(os.environ.get("DUPLICATE_KILLER_INTERVAL", 60))  # seconds

# Idle auto-shutdown: stop opt-in containers after a period of no network traffic.
# Opt a container in with labels:
#   locator.idle.stop=true          — enable idle shutdown (1h default)
#   locator.idle.timeout=2h         — optional override (accepts 90m / 2h / 5400)
IDLE_ENABLED           = os.environ.get("IDLE_ENABLED", "true").lower() == "true"
IDLE_CHECK_INTERVAL    = int(os.environ.get("IDLE_CHECK_INTERVAL", 60))        # seconds between checks
IDLE_DEFAULT_TIMEOUT   = int(os.environ.get("IDLE_DEFAULT_TIMEOUT", 3600))     # seconds of inactivity before stop
IDLE_TRAFFIC_THRESHOLD = int(os.environ.get("IDLE_TRAFFIC_THRESHOLD", 10240))  # bytes/check below which traffic is "noise"
IDLE_LABEL_ENABLE      = "locator.idle.stop"
IDLE_LABEL_TIMEOUT     = "locator.idle.timeout"

# Compose store + remote deploy config
COMPOSE_DIR = os.environ.get("COMPOSE_DIR", os.path.join(os.environ.get("DATA_DIR", "/app/data"), "compose_store"))
SSH_USER    = os.environ.get("SSH_USER", "swoopg111")
SSH_KEY     = os.environ.get("SSH_KEY", "")  # path to private key, optional

# Fly secrets are env vars, not files — SSH_KEY above wants a path, so accept
# the key's raw PEM/OpenSSH content via SSH_PRIVATE_KEY instead and materialize
# it to a private temp file once at startup. Set SSH_KEY normally for anything
# non-Fly (e.g. running this on a box that already has the key file locally).
if not SSH_KEY and os.environ.get("SSH_PRIVATE_KEY"):
    import stat as _stat
    import tempfile as _tempfile
    _key_fd, _key_path = _tempfile.mkstemp(prefix="locator_ssh_key_")
    with os.fdopen(_key_fd, "w") as _f:
        _f.write(os.environ["SSH_PRIVATE_KEY"].strip() + "\n")
    os.chmod(_key_path, _stat.S_IRUSR | _stat.S_IWUSR)  # 0600 — ssh refuses group/world-readable keys
    SSH_KEY = _key_path

DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
SEED_FILE = os.environ.get("SEED_FILE", "/app/seed_registry.json")
EXCEL_FILE = "registry.xlsx"

# Admin key gating remote-exec / scheduling — these endpoints let the locator
# tell a unit's lokey to run an arbitrary shell command, so unlike the rest of
# the (deliberately open) API they require X-Locator-Admin-Key. Fails closed:
# if the key isn't configured, the endpoints refuse everything rather than
# silently running open.
LOCATOR_ADMIN_KEY = os.environ.get("LOCATOR_ADMIN_KEY", "")


def _require_admin_key():
    """Return None if the request's X-Locator-Admin-Key is valid, else a Flask response to abort with."""
    if not LOCATOR_ADMIN_KEY:
        return jsonify({"error": "LOCATOR_ADMIN_KEY not configured on server"}), 503
    supplied = request.headers.get("X-Locator-Admin-Key", "")
    if not hmac.compare_digest(supplied, LOCATOR_ADMIN_KEY):
        return jsonify({"error": "unauthorized"}), 401
    return None

# DNS zone status/sync (unit9 runs the PowerDNS primary with a sqlite3
# backend, at ns2.theofficialblacksheepco.online — DNS delegation for the
# .online zone completed 2026-08-07, so this resolves publicly now;
# reached over SSH with the SSH_USER/SSH_KEY above since Locator itself runs
# on Fly, not on the DNS box — see /api/dns/status and /api/dns/sync).
DNS_SSH_HOST = os.environ.get("DNS_SSH_HOST", "ns2.theofficialblacksheepco.online")
DNS_SSH_USER = os.environ.get("DNS_SSH_USER", "root")
DNS_ZONES = [z.strip() for z in os.environ.get(
    "DNS_ZONES",
    "prime-quality.online"
    "theofficialblacksheepco.com,theofficialblacksheepco.info,"
    "theofficialblacksheepco.online,theofficialblacksheepco.store",
).split(",") if z.strip()]

# Load-balancer config
BALANCE_ENABLED  = os.environ.get("BALANCE_ENABLED", "true").lower() == "true"
BALANCE_HIGH     = float(os.environ.get("BALANCE_HIGH", "50"))   # % — node is overloaded above this
BALANCE_LOW      = float(os.environ.get("BALANCE_LOW",  "30"))   # % — node is a migration target below this
BALANCE_INTERVAL = int(os.environ.get("BALANCE_INTERVAL", "120"))  # seconds between balance checks
BALANCE_COOLDOWN = int(os.environ.get("BALANCE_COOLDOWN", "300"))  # seconds before re-migrating from same node
BALANCE_DIFF     = float(os.environ.get("BALANCE_DIFF", "25"))     # % spread between busiest/least busy to trigger balance
BALANCE_STRIKES  = int(os.environ.get("BALANCE_STRIKES", "1"))      # consecutive overloaded checks before migrating
OOM_THRESHOLD    = float(os.environ.get("OOM_THRESHOLD", "80"))     # % mem — emergency migration, bypasses anti-flap/cooldown

# Proactive pre-staging: watch nodes trending toward BALANCE_HIGH *before* they
# get there, and validate (not execute) a migration ahead of time so the real
# cutover — if it ends up being needed — has less work left to do. Derived
# from BALANCE_HIGH rather than a second absolute constant, so there's still
# only one number (BALANCE_HIGH) to reason about day to day.
BALANCE_PRESTAGE_ENABLED = os.environ.get("BALANCE_PRESTAGE_ENABLED", "true").lower() == "true"
BALANCE_PRESTAGE_MARGIN  = float(os.environ.get("BALANCE_PRESTAGE_MARGIN", "15"))  # % below BALANCE_HIGH that triggers pre-staging
PRESTAGE_STALE_SECONDS   = int(os.environ.get("PRESTAGE_STALE_SECONDS", "600"))    # re-validate if older than this

UNIT_NAME             = os.environ.get("UNIT_NAME", "unknown")
LOCATOR_CANONICAL_URL = os.environ.get("LOCATOR_CANONICAL_URL", "https://locator.prime-quality.online")

# ── ALERT / TELEMETRY CONFIG ─────────────────────────────────────────────────
TELEMETRY_URL     = os.environ.get("TELEMETRY_URL", "http://beast-telemetry:8087")
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")
LOCATOR_IS_PRIMARY    = os.environ.get("LOCATOR_IS_PRIMARY", "true").lower() == "true"
SELF_CONTAINER_NAME   = os.environ.get("SELF_CONTAINER_NAME", "locator")

_STARTED_AT = datetime.now(timezone.utc)  # used by dedup election to find the oldest instance

# Compose-store git backup
GIT_AUTO_PUSH = os.environ.get("GIT_AUTO_PUSH", "false").lower() == "true"
GIT_REMOTE    = os.environ.get("GIT_REMOTE", "")

# Import docker for discovery
try:
    import docker
    docker_client = docker.from_env()
except Exception:
    docker_client = None

# ── TELEMETRY / LOGGING ───────────────────────────────────────────────────────

_log_queue = _queue_module.Queue(maxsize=500)


def _log_forwarder():
    """Background thread: drains _log_queue and POSTs to beast-telemetry."""
    session = requests.Session()
    while True:
        batch = []
        try:
            batch.append(_log_queue.get(timeout=2))
            while not _log_queue.empty() and len(batch) < 50:
                batch.append(_log_queue.get_nowait())
        except _queue_module.Empty:
            continue
        try:
            session.post(f"{TELEMETRY_URL}/api/log", json=batch, timeout=3)
        except Exception:
            pass  # beast-telemetry may not be reachable; silently drop


def beast_log(line: str, source: str = "locator"):
    """Print to stdout AND enqueue for live-logger display in beast-telemetry."""
    print(line)
    try:
        _log_queue.put_nowait({"source": source, "line": line})
    except _queue_module.Full:
        pass


def _check_battery_threshold(svc_id, current, previous):
    """
    Edge-triggered battery alerting: fires once when a device crosses at/below
    BATTERY_ALERT_THRESHOLD, then re-alerts every BATTERY_REALERT_INTERVAL
    seconds while it stays low, and sends one "cleared" notice on recovery
    (e.g. it started charging). `current`/`previous` are battery_percent
    values as they arrive in a service's metadata (see register_service()) —
    there's no separate battery-specific endpoint, this rides the existing
    heartbeat path Android's DeviceStats.kt already posts to.
    """
    if current is None:
        return
    now = datetime.now(timezone.utc)

    with battery_alert_lock:
        state = battery_alert_state.get(svc_id)

        if current <= BATTERY_ALERT_THRESHOLD:
            if state is None:
                # Newly crossed — first alert, always urgent (attempts a call-invite too).
                battery_alert_state[svc_id] = {"since": now.isoformat(), "last_notified": now.isoformat()}
                fire, urgent = True, True
            else:
                last_notified = datetime.fromisoformat(state["last_notified"])
                if (now - last_notified).total_seconds() >= BATTERY_REALERT_INTERVAL:
                    state["last_notified"] = now.isoformat()
                    fire, urgent = True, False
                else:
                    fire, urgent = False, False
        elif state is not None:
            # Recovered — clear and send one "back above threshold" notice.
            battery_alert_state.pop(svc_id, None)
            fire, urgent = True, False
            current_desc = f"recovered to {current:.0f}%"
        else:
            fire = False

    if not fire:
        return

    if current <= BATTERY_ALERT_THRESHOLD:
        text = f"🔋 LOW BATTERY: {svc_id} at {current:.0f}% (threshold {BATTERY_ALERT_THRESHOLD:.0f}%)"
    else:
        text = f"🔋 {svc_id} battery {current_desc} — alert cleared"
    notifier.notify_all(text, urgent=urgent)


def _send_alert(service_name: str, status: str, extra: str = ""):
    """Fire-and-forget alert to ALERT_WEBHOOK_URL (Slack, Discord, or custom)."""
    if not ALERT_WEBHOOK_URL:
        return
    emoji = "🔴" if status == "OFFLINE" else "🟢"
    text = f"{emoji} *LOCATOR ALERT* — `{service_name}` is now *{status}*"
    if extra:
        text += f"\n{extra}"
    try:
        requests.post(ALERT_WEBHOOK_URL, json={"text": text}, timeout=5)
    except Exception:
        pass



# ── INSTANCE LIMITS ──────────────────────────────────────────────────────────

# Containers that may run up to 3 instances; everything else is singleton (max 1).
TRIPLE_ALLOWED = {"traefik", "apache", "lokey", "openvpn", "wireguard", "headscale", "tailscale", "pdns"}

def _base_name(container_name: str) -> str:
    """Derive a canonical base name by stripping project prefixes and numeric suffixes."""
    name = container_name.lower()
    name = re.sub(r'[-_]v?\d+$', '', name)
    for segment in re.split(r'[-_]', name):
        for known in TRIPLE_ALLOWED:
            if known in segment:
                return known
    return name

def _max_instances(container_name: str) -> int:
    base = _base_name(container_name)
    for known in TRIPLE_ALLOWED:
        if known in base:
            return 3
    return 1

def enforce_instance_limits_global(new_name: str, new_host: str):
    """Cross-node singleton/triple enforcement via the migration queue."""
    import uuid as _uuid_module
    base  = _base_name(new_name)
    limit = _max_instances(new_name)
    with lock:
        instances = [
            (svc_id, svc)
            for svc_id, svc in registry["services"].items()
            if _base_name(svc.get("name", "")) == base
            and svc.get("status") == "ONLINE"
        ]
    if len(instances) <= limit:
        return
    with migration_lock:
        already = any(
            m.get("dedup") and m["status"] in ("pending", "in_progress")
            and _base_name(m.get("container", "")) == base
            for m in migration_queue.values()
        )
    if already:
        return
    instances.sort(key=lambda x: x[1].get("registered_at", ""))
    to_evict = instances[: len(instances) - limit]
    keeper_svc  = instances[-1][1]
    keeper_host = keeper_svc.get("host") or (keeper_svc.get("hosts") or [new_host])[0]
    now = datetime.now(timezone.utc).isoformat()
    for i, (svc_id, svc) in enumerate(to_evict):
        evict_host = svc.get("host") or (svc.get("hosts") or ["unknown"])[0]
        if evict_host == keeper_host:
            continue
        push_id = f"{_uuid_module.uuid4().hex[:8]}-dedup-push"
        with migration_lock:
            migration_queue[push_id] = {
                "id":        push_id,
                "type":      "git_push_and_stop",
                "unit":      evict_host,
                "from_node": evict_host,
                "to_node":   keeper_host,
                "container": svc.get("name", new_name),
                "status":    "pending",
                "queued_at": now,
                "dedup":     True,
            }
        beast_log(
            f"\U0001f502 DEDUP: {svc.get('name', new_name)} \u2014 "
            f"evicting {evict_host} (oldest), keeping {keeper_host} (newest)"
        )

# ── REGISTRY STATE ──────────────────────────────────────────────────────────

registry = {
    "services": {},
    "nodes": {},
    "updated": ""
}

lock = threading.Lock()

# ── CLIENT-SIDE ERROR LOG ────────────────────────────────────────────────────
# Browser JS errors (window.onerror / unhandledrejection) reported from the
# dashboard, /3d-mesh, etc. Bounded in-memory ring buffer + stdout (so `fly
# logs` / any log shipper captures them permanently even across restarts).
# Added 2026-07-27 after a silent tactical-grid rendering crash went
# undiagnosed for hours with no client-side error visibility anywhere.
CLIENT_ERROR_MAX = 300
client_errors: list = []
client_error_lock = threading.Lock()

# Migration queue — keyed by migration ID
migration_queue: dict = {}
migration_lock  = threading.Lock()
# Cooldown: when each node last had a container migrated OUT of it
node_last_migrated: dict = {}
# Anti-flap: how many consecutive balance checks a node has been overloaded
overload_strikes: dict = {}

# Pre-stage state — keyed by svc_id, holds the last validation done for a
# service on a node trending toward overload (see load_balancer()'s prestage
# pass). Purely advisory/read-side: never itself causes a cutover.
prestage_state: dict = {}
prestage_lock = threading.Lock()

# Battery alert state — keyed by svc_id, tracks re-alert-while-low/cleared-on-recovery.
battery_alert_state: dict = {}
battery_alert_lock = threading.Lock()
BATTERY_ALERT_THRESHOLD  = float(os.environ.get("BATTERY_ALERT_THRESHOLD", "30"))
BATTERY_REALERT_INTERVAL = int(os.environ.get("BATTERY_REALERT_INTERVAL", "1800"))  # seconds

# ── COMPOSE STORE HELPERS ───────────────────────────────────────────────────

def _compose_path(name):
    os.makedirs(COMPOSE_DIR, exist_ok=True)
    return os.path.join(COMPOSE_DIR, f"{name}.yml")


def _list_compose_names():
    if not os.path.isdir(COMPOSE_DIR):
        return []
    return [f[:-4] for f in os.listdir(COMPOSE_DIR) if f.endswith(".yml")]


def _first_addr(value):
    """First address out of a free-text node address field, or "".

    Agents report these inconsistently — "10.0.0.236- sheep.client", a bare IP,
    None, or "". The previous inline form was
    `info.get("openvpn_ip", "").split("-")[0].strip().split()[0]`, which raises
    IndexError on an empty string: .split() on "" returns [], so [0] blows up.
    Any node with a blank openvpn_ip therefore 500'd the whole auto-select,
    which is why deploying without pinning a node never worked.
    """
    parts = str(value or "").split("-")[0].strip().split()
    return parts[0] if parts else ""


def _best_available_node():
    """
    Returns (node_id, ip) for the ONLINE node with the most headroom.
    Uses live cpu/mem/disk pushed by agents; falls back to seeded RAM metadata.
    Lower combined load score = more headroom = preferred target.
    """
    with lock:
        nodes_snap = {k: dict(v) for k, v in registry["nodes"].items()}

    candidates = []
    for node_id, info in nodes_snap.items():
        if info.get("status") != "ONLINE":
            continue

        ip = _first_addr(info.get("tailscale_ip")) \
            or _first_addr(info.get("openvpn_ip")) \
            or _first_addr(info.get("ip"))
        if not ip or ip == "unknown":
            continue

        cpu  = info.get("cpu_percent")
        mem  = info.get("mem_percent")
        disk = info.get("disk_percent")

        if cpu is not None and mem is not None:
            divisor = 3 if disk is not None else 2
            score = (cpu + mem + (disk or 0)) / divisor
        else:
            ram_str = info.get("metadata", {}).get("ram", "0").lower()
            try:
                ram_gb = int("".join(filter(str.isdigit, ram_str)))
            except Exception:
                ram_gb = 1
            score = max(0, 100 - ram_gb)

        candidates.append((score, node_id, ip))

    if not candidates:
        return None, None

    candidates.sort(key=lambda x: x[0])
    _, node_id, ip = candidates[0]
    return node_id, ip


def _ranked_nodes():
    """Every deployable node, best headroom first, as [(node_id, ip), ...].

    Same scoring as _best_available_node, but the whole ranking rather than
    just the winner — an auto-target deploy needs somewhere to fall through to
    when the top node turns out not to run containers (unit3 is a Mac mini
    whose non-interactive shell has no `docker` on PATH, and it frequently
    scores best because it is idle).
    """
    with lock:
        nodes_snap = {k: dict(v) for k, v in registry["nodes"].items()}

    ranked = []
    for node_id, info in nodes_snap.items():
        if info.get("status") != "ONLINE":
            continue
        ip = _first_addr(info.get("tailscale_ip")) \
            or _first_addr(info.get("openvpn_ip")) \
            or _first_addr(info.get("ip"))
        if not ip or ip == "unknown":
            continue
        cpu, mem, disk = info.get("cpu_percent"), info.get("mem_percent"), info.get("disk_percent")
        if cpu is not None and mem is not None:
            score = (cpu + mem + (disk or 0)) / (3 if disk is not None else 2)
        else:
            try:
                ram_gb = int("".join(filter(str.isdigit,
                                            info.get("metadata", {}).get("ram", "0").lower())))
            except Exception:
                ram_gb = 1
            score = max(0, 100 - ram_gb)
        ranked.append((score, node_id, ip))

    ranked.sort(key=lambda x: x[0])
    return [(node_id, ip) for _, node_id, ip in ranked]


# ── SELF-ELECTION ───────────────────────────────────────────────────────────

class _UnixConn(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket (Docker API)."""
    def __init__(self): super().__init__("localhost")
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/var/run/docker.sock")


def _stop_self():
    """
    Stop this instance — prevents restart-loop / duplicate serving after
    losing self-election. Uses the Docker API socket when running in a
    container; on a native (Docker-less) host like unit3, just exits the
    process instead — there's no restart-loop risk unless the caller wraps
    this in a supervisor with auto-restart (launchd KeepAlive, systemd
    Restart=always), which native deployments should set to false/no.
    """
    if os.path.exists("/var/run/docker.sock"):
        print(f"⛔ Stopping self ({SELF_CONTAINER_NAME}) via Docker API...")
        try:
            conn = _UnixConn()
            conn.request("POST", f"/containers/{SELF_CONTAINER_NAME}/stop?t=5")
            r = conn.getresponse()
            print(f"   Docker stop response: HTTP {r.status}")
            return
        except Exception as e:
            print(f"   Could not stop self via Docker socket: {e}")
    print(f"⛔ Stopping self (native process on '{UNIT_NAME}', no Docker socket) — exiting")
    os._exit(0)


# ── EVENT LOG ───────────────────────────────────────────────────────────────
# Bounded in-memory feed of notable events (elections, migrations, DNS moves)
# for the dashboard's EVENT LOG panel. Deliberately not persisted: the registry
# is the durable record, this is the live operator view.
EVENT_LOG_MAX = int(os.environ.get("EVENT_LOG_MAX", "300"))
_event_log = []
_event_lock = threading.Lock()
# Last dry-run standings string, so unchanged rankings are not re-logged.
_last_election_signature = None


def record_event(kind, message, **extra):
    """Record an event — delegates to emit_event().

    This started as an in-memory ring buffer written before I noticed the
    Postgres-backed event log already existed. Keeping both meant election
    events lived only in memory (lost on restart) while the events table sat
    empty, so this is now a thin shim onto the persistent path, which also
    pushes to the SSE stream. Defined earlier in the file than emit_event, but
    Python resolves the name at call time.
    """
    return emit_event(kind, message=message, **extra)


# Election tuning. Ranking is by node health rather than start time: the unit
# best able to afford hosting the registry keeps it. RAM is primary; disk acts
# as a veto rather than a tiebreak, because a box can be nearly full on disk
# and still be by far the best place to run a memory-resident registry.
ELECTION_INTERVAL = int(os.environ.get("ELECTION_INTERVAL", "60"))
ELECTION_GRACE    = int(os.environ.get("ELECTION_GRACE", "20"))
DISK_VETO_PERCENT = float(os.environ.get("DISK_VETO_PERCENT", "90"))
# Measured steady-state RSS of this process is ~91 MB; 256 MB is comfortable
# headroom. A unit that cannot clear this has no business hosting the registry.
ELECTION_MIN_RAM_MB = float(os.environ.get("ELECTION_MIN_RAM_MB", "256"))
# Dry run logs the decision without acting, so the ranking can be observed
# against real nodes before _stop_self() is ever armed.
ELECTION_DRY_RUN = os.environ.get("ELECTION_DRY_RUN", "true").lower() == "true"


# ── NODE LIVENESS ────────────────────────────────────────────────────────────
# A missing heartbeat means "lokey is not reporting", which is NOT the same
# fact as "the machine is down" — and the registry used to record them as the
# same thing. unit6 runs no Docker at all, so its containerised lokey can never
# heartbeat, and the box the operator uses every single day sat permanently at
# OFFLINE while being up for over a day. unit3 was in the same state while
# tailscale showed it active.
#
# So before a node is declared OFFLINE we now ask the network. Reachable but
# silent is AGENT_DOWN: the machine is fine, its agent is not. Only genuinely
# unreachable nodes get OFFLINE.
NODE_PROBE_PORTS   = [int(p) for p in
                      os.environ.get("NODE_PROBE_PORTS", "22,5000,41641").split(",")
                      if p.strip().isdigit()]
NODE_PROBE_TIMEOUT = float(os.environ.get("NODE_PROBE_TIMEOUT", "2.0"))

# Node is up, agent is not reporting. Deliberately NOT "ONLINE": every
# scheduling path in this file gates on status == "ONLINE", and a node with no
# lokey cannot execute a deploy, migration or exec command. Keeping it distinct
# means such a node is correctly skipped for work while still being reported as
# the live machine it is.
NODE_STATUS_AGENT_DOWN = "AGENT_DOWN"

# Nodes already sitting at OFFLINE must be re-probed too, or a machine that is
# genuinely up can never be corrected — unit3 and unit6 were both stuck at
# OFFLINE while running, and nothing in the old reaper would ever look at them
# again because it only considered ONLINE nodes. Re-probed on a slower cycle
# than live ones so long-dead hosts (unit1 has been gone 23 days) are not
# retried every REAPER_INTERVAL.
NODE_REPROBE_OFFLINE_SECONDS = int(os.environ.get("NODE_REPROBE_OFFLINE_SECONDS", "300"))
_node_probe_last: dict = {}
_node_probe_lock = threading.Lock()


def _node_probe_due(node_id, status):
    """Rate-limit re-probing of already-OFFLINE nodes."""
    if status != "OFFLINE":
        return True
    now = time.monotonic()
    with _node_probe_lock:
        last = _node_probe_last.get(node_id, 0.0)
        if now - last < NODE_REPROBE_OFFLINE_SECONDS:
            return False
        _node_probe_last[node_id] = now
    return True


def _node_probe_addr(info):
    """The best address to probe this node on, or None if we know of none."""
    addr = (_first_addr(info.get("tailscale_ip"))
            or _first_addr(info.get("openvpn_ip"))
            or _first_addr(info.get("ip"))
            or _first_addr(info.get("private_ip")))
    return addr if addr and addr != "unknown" else None


def _node_reachable(info, timeout=None):
    """Does anything answer at this node's address?

    Returns True (something accepted a TCP connection), False (nothing did on
    any probe port), or None (no address on record, so we cannot tell and must
    not guess). A refused connection still proves the host is UP and answering,
    which is exactly the distinction being drawn here, so ECONNREFUSED counts
    as reachable rather than as a failure.

    Must never be called while holding `lock` — it blocks on the network.
    """
    addr = _node_probe_addr(info)
    if not addr:
        return None
    timeout = NODE_PROBE_TIMEOUT if timeout is None else timeout
    for port in NODE_PROBE_PORTS:
        try:
            with socket.create_connection((addr, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True          # host answered, just nothing on that port
        except OSError:
            continue
    return False


def _node_is_fresh(info):
    """True when the node heartbeated within HEARTBEAT_TIMEOUT."""
    raw = info.get("last_seen")
    if not raw:
        return False
    try:
        seen = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return False
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - seen).total_seconds() <= HEARTBEAT_TIMEOUT


def _node_ram_total_mb(info):
    """Total RAM in MB.

    Prefers the figure lokey reports (mem_total_mb / mem_total_gb) and falls
    back to the seeded metadata string only for nodes that predate that, since
    the seed is static inventory rather than anything the node measured.
    """
    for field, factor in (("mem_total_mb", 1), ("mem_total_gb", 1024)):
        try:
            if info.get(field) is not None:
                return float(info[field]) * factor
        except (TypeError, ValueError):
            pass
    raw = str((info.get("metadata") or {}).get("ram", "")).lower()
    # Parsed as a float, not by stripping non-digits: "1.8 GB" must not become
    # 18 GB. unit9 reports exactly that, and overstating it tenfold would hand
    # the registry to the smallest box in the mesh.
    match = re.search(r"(\d+(?:\.\d+)?)", raw)
    if not match:
        return None
    value = float(match.group(1))
    return value * 1024 if "gb" in raw or raw.strip().endswith("g") else value


def _node_health(unit):
    """(tier, ram_available_mb) for a unit — larger tuples rank better.

    Ranked on ABSOLUTE free megabytes, not percentage. The units are wildly
    heterogeneous (1.8 GB on unit9 vs 16 GB on unit8), so "20% free" means
    ~370 MB on one and 3.2 GB on another; against a fixed ~91 MB requirement
    only the absolute figure says whether a unit can actually host the registry.

    tier  0 = disk below DISK_VETO_PERCENT, tier -1 = disk critical, so a unit
    with room always outranks a full one and RAM decides within a tier.
    ram_available_mb is -1.0 when the unit has never reported usable metrics,
    which sorts it last: an unmeasured node is never promoted on an assumption.
    """
    with lock:
        info = registry["nodes"].get(unit) or {}
    # A node that stopped heartbeating is unmeasured, not healthy. Without this
    # a dead unit keeps whatever figures it last reported and can still look
    # like the best candidate — exactly what the stale unit1 tombstone did,
    # ranking as eligible on numbers frozen when it went away.
    if not _node_is_fresh(info):
        return 0, -1.0
    # Prefer what the node actually measured. psutil's "available" counts
    # reclaimable cache, so it is a truer picture of what a migrated container
    # could claim than total minus used.
    try:
        ram_available_mb = float(info["mem_available_mb"])
    except (KeyError, TypeError, ValueError):
        total_mb = _node_ram_total_mb(info)
        try:
            ram_available_mb = total_mb * (100.0 - float(info.get("mem_percent"))) / 100.0
        except (TypeError, ValueError):
            ram_available_mb = -1.0
    try:
        tier = -1 if float(info.get("disk_percent")) >= DISK_VETO_PERCENT else 0
    except (TypeError, ValueError):
        tier = 0
    return tier, round(ram_available_mb, 1)


def _locator_hosts():
    """Units currently reporting an ONLINE locator, ourselves always included."""
    base = _base_name(SELF_CONTAINER_NAME)
    hosts = {UNIT_NAME}
    with lock:
        for svc in registry["services"].values():
            if svc.get("status") != "ONLINE":
                continue
            if _base_name(svc.get("name", "")) != base:
                continue
            host = svc.get("host") or (svc.get("hosts") or [None])[0]
            if host:
                hosts.add(host)
    return hosts


def _self_election():
    """Keep exactly one locator alive, on the healthiest unit.

    Runs for the process lifetime instead of once at startup: a locator brought
    up later by lokey failover, or a unit whose health degrades after boot, is
    still resolved. Only the winner issues stop commands and only a loser stops
    itself, so a single consistent ranking collapses the set to one instance.
    """
    time.sleep(ELECTION_GRACE)  # let ourselves fully initialise first
    while True:
        try:
            hosts = _locator_hosts()
            if ELECTION_DRY_RUN and len(hosts) == 1:
                # Sole instance: nothing to decide, but publish how the mesh
                # would rank so the scoring can be judged against real nodes
                # before the destructive path is ever enabled.
                with lock:
                    known = list(registry["nodes"].keys())
                board = sorted(
                    ((u, _node_health(u)) for u in known),
                    key=lambda x: (x[1], x[0]), reverse=True,
                )[:5]
                summary = ", ".join(f"{u}(tier={h[0]},{h[1]}MB)" for u, h in board)
                print(f"🗳️  [DRY RUN] sole locator on {UNIT_NAME} "
                      f"{_node_health(UNIT_NAME)} — ranking would be: {summary}")
                # Recorded only when the standings actually change, so a 60s
                # loop cannot flood a 300-entry log with identical rows.
                global _last_election_signature
                if summary != _last_election_signature:
                    _last_election_signature = summary
                    record_event(
                        "election",
                        f"[DRY RUN] Sole locator on {UNIT_NAME}. Ranking: {summary}",
                        winner=UNIT_NAME, dry_run=True,
                    )
            if len(hosts) > 1:
                # Unit name breaks exact ties so every instance derives the same
                # order from the same numbers.
                ranked = sorted(hosts, key=lambda u: (_node_health(u), u), reverse=True)
                winner = ranked[0]
                mine = _node_health(UNIT_NAME)
                theirs = _node_health(winner)
                tag = "[DRY RUN] " if ELECTION_DRY_RUN else ""
                if winner == UNIT_NAME:
                    for loser in ranked[1:]:
                        msg = (f"{tag}Keeping {UNIT_NAME} (tier {mine[0]}, {mine[1]}MB free), "
                               f"evicting {loser} (tier {_node_health(loser)[0]}, "
                               f"{_node_health(loser)[1]}MB free)")
                        print(f"🗳️  {tag}ELECTION: keeping {UNIT_NAME} {mine}, evicting "
                              f"{loser} {_node_health(loser)}")
                        record_event("election", msg, winner=UNIT_NAME, loser=loser,
                                     dry_run=ELECTION_DRY_RUN)
                        if not ELECTION_DRY_RUN:
                            _queue_command(loser, SELF_CONTAINER_NAME, "stop", source="election")
                elif theirs[1] < 0:
                    # Winner has never reported metrics. Standing down for an
                    # unmeasured node risks trading a working registry for a
                    # dead one, so hold position until it proves itself.
                    print(f"🗳️  {tag}ELECTION: {winner} leads but has no metrics yet — holding on {UNIT_NAME}")
                elif theirs[1] < ELECTION_MIN_RAM_MB:
                    # Nobody can host it properly; staying put beats handing the
                    # registry to a unit that will only OOM.
                    print(f"🗳️  {tag}ELECTION: {winner} leads but only {theirs[1]}MB free "
                          f"(< {ELECTION_MIN_RAM_MB}MB) — holding on {UNIT_NAME}")
                    record_event("election",
                                 f"{tag}{winner} leads but only {theirs[1]}MB free "
                                 f"(under {ELECTION_MIN_RAM_MB}MB) — holding on {UNIT_NAME}",
                                 winner=UNIT_NAME, dry_run=ELECTION_DRY_RUN)
                else:
                    print(f"🗳️  {tag}ELECTION: {winner} {theirs} healthier than {UNIT_NAME} {mine} — stopping self")
                    record_event("election",
                                 f"{tag}{winner} (tier {theirs[0]}, {theirs[1]}MB free) is healthier "
                                 f"than {UNIT_NAME} (tier {mine[0]}, {mine[1]}MB free) — stopping self",
                                 winner=winner, loser=UNIT_NAME, dry_run=ELECTION_DRY_RUN)
                    if not ELECTION_DRY_RUN:
                        _stop_self()
                        return
        except Exception as e:
            print(f"🗳️  election error: {e}")
        time.sleep(ELECTION_INTERVAL)


# ── COMPOSE GIT BACKUP ──────────────────────────────────────────────────────
# Single worker thread + event instead of a thread per request — a thread per
# compose POST exhausted the thread pool on unit4 (RuntimeError: can't start
# new thread) and froze the metrics updaters.

_git_push_event = threading.Event()
_git_lock = threading.Lock()


def _git_auto_push():
    import subprocess
    with _git_lock:
        try:
            d = COMPOSE_DIR
            os.makedirs(d, exist_ok=True)
            if not os.path.isdir(os.path.join(d, ".git")):
                subprocess.run(["git", "init"], cwd=d, capture_output=True)
                subprocess.run(["git", "config", "user.email", "locator@blacksheep"], cwd=d, capture_output=True)
                subprocess.run(["git", "config", "user.name", "locator"], cwd=d, capture_output=True)
                if GIT_REMOTE:
                    subprocess.run(["git", "remote", "add", "origin", GIT_REMOTE], cwd=d, capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=d, capture_output=True)
            r = subprocess.run(
                ["git", "commit", "-m", f"auto: compose snapshot {datetime.now(timezone.utc).isoformat()}"],
                cwd=d, capture_output=True, text=True
            )
            if "nothing to commit" in (r.stdout or ""):
                return
            if GIT_REMOTE:
                subprocess.run(
                    ["git", "push", "-u", "origin", "HEAD:main", "--force"],
                    cwd=d, capture_output=True, timeout=30
                )
                print("💾 git-push: compose files pushed")
        except Exception as e:
            print(f"⚠️  git-push error: {e}")


def _git_push_worker():
    while True:
        _git_push_event.wait()
        _git_push_event.clear()
        time.sleep(5)  # debounce: agents push many compose files in bursts
        _git_auto_push()


# ── FLASK APP ───────────────────────────────────────────────────────────────

app = Flask(__name__)

# Clearance gate (levels 1-10). Inert until CLEARANCE_ENFORCE=true.
clearance.install(app)

# Identity administration for the client portal's new-accounts box.
# Routes are gated at clearance 10 by clearance.ROUTE_CLEARANCE.
kc_admin.register(app, clearance)


# ── CORS ────────────────────────────────────────────────────────────────────

@app.after_request
def add_cors(response):
    """Allow access from any origin, any method, any header."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.before_request
def handle_options():
    """Handle CORS preflight requests."""
    if request.method == "OPTIONS":
        return Response(status=200)


# ── ENDPOINTS ───────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Serve the unified dashboard UI."""
    return render_template("dashboard.html")


@app.route("/register-device", methods=["GET"])
def register_device_page():
    """Mobile-friendly page: self-register this phone/tablet into the registry
    and, on Android, download the Lokey app for live heartbeats."""
    return render_template("register_device.html")


@app.route("/register-device-qr.png", methods=["GET"])
def register_device_qr():
    """QR code pointing at /register-device, for scanning off a desktop-viewed
    Tactical Grid straight into the mobile self-register/install page."""
    target_url = request.url_root.rstrip("/") + "/register-device"
    img = qrcode.make(target_url, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(buf.read(), mimetype="image/png")

@app.route("/api/registry", methods=["GET"])
def get_full_registry():
    """Return the registry — services + nodes — scoped to the caller's clearance."""
    with lock:
        snapshot = {
            "services": clearance.project(registry["services"]),
            "nodes":    clearance.project(registry["nodes"]),
            "updated":  registry["updated"],
        }
    return jsonify(snapshot)


@app.route("/services", methods=["GET"])
@app.route("/api/services", methods=["GET"])
def get_services():
    """Return the registered services the caller is cleared to see."""
    with lock:
        return jsonify(clearance.project(registry["services"]))


@app.route("/services/<name>", methods=["GET"])
def get_service(name):
    """Lookup a specific service by name (exact key, or container name with @host suffix)."""
    with lock:
        service = registry["services"].get(name)
        if not service:
            _, service = _find_service_entry(name)
    if service and clearance.visible(service):
        return jsonify(clearance.redact(service))
    return jsonify({"error": f"Service '{name}' not found"}), 404


# A service that cannot be placed right now still gets emitted, pointing at a
# guaranteed-dead upstream: the discard port on the edge itself. Dropping the
# service instead is the worse failure — every router referencing name@http
# becomes invalid, Traefik removes it, and its errors middleware dies with it,
# which turns "registry hiccup" into "the wake path is gone and nothing can
# bring it back". A dead upstream 502s, which is precisely the signal the wake
# middleware exists to catch.
EDGE_DEAD_UPSTREAM = "http://127.0.0.1:9"

# Deployment addressing. A registered service carrying a subdomain+domain pair
# is emitted by /api/traefik as Host(`<sub>.<dom>`) -> its own upstream, so user
# deployments are served at https://<sub>.<dom> with a per-host tlsChallenge
# cert (no wildcard DNS-01 needed). Labels must be DNS-safe: they land inside a
# Traefik rule string verbatim.
_DEPLOY_SUBDOMAIN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_DEPLOY_DOMAIN = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")


def _edge_upstream(name, cfg, port):
    """The tailnet URL an edge should proxy this service to, or the dead
    placeholder when nothing can be resolved yet.

    Order: live registry host → node tailnet address → the policy's declared
    `units:` spec (where a wake would land it) → dead upstream.

    `edge_host` redirects the lookup to another service's registry entry: an
    edge file may need several service objects over one backend (error-pages
    carries passHostHeader: false where the sibling routers carry true), and
    only the backend's name exists in the registry.
    """
    cfg = cfg or {}
    lookup = cfg.get("edge_host") or name
    key, svc = _find_service_entry(lookup)
    host = (svc or {}).get("host") or ((svc or {}).get("hosts") or [None])[0]
    node = registry["nodes"].get(host or "") or {}
    ip = _node_probe_addr(node)
    if not ip:
        units = (_policy_for(lookup) if lookup != name else cfg).get("units")
        for fallback in _expand_unit_spec(units, []):
            ip = _node_probe_addr(registry["nodes"].get(fallback) or {})
            if ip:
                break
    if not ip:
        return EDGE_DEAD_UPSTREAM
    return f"http://{ip}:{port}"


@app.route("/api/traefik", methods=["GET"])
def traefik_all_services():
    """Traefik HTTP-provider view of every edge-routed service in the fleet.

    A service joins by declaring edge_port in locator.yml; its upstream then
    follows the registry, so a migration between units needs no file edit on
    any edge. The single /api/traefik/<name>?port= form below stays for
    services that never declare policy.
    """
    out = {}
    policy = load_policy()
    with lock:
        for name, cfg in policy.items():
            port = cfg.get("edge_port")
            if not port:
                continue
            lb = {"servers": [{"url": _edge_upstream(name, cfg, port)}]}
            pass_host = cfg.get("edge_pass_host")
            if pass_host is not None:
                # YAML gives a bool; a quoted "false" would arrive as a
                # truthy string and silently invert the intent.
                if isinstance(pass_host, str):
                    pass_host = pass_host.strip().lower() == "true"
                lb["passHostHeader"] = bool(pass_host)
            if cfg.get("edge_healthcheck"):
                lb["healthCheck"] = {"path": cfg["edge_healthcheck"],
                                     "interval": "15s", "timeout": "5s"}
            out[name] = {"loadBalancer": lb}
        # User deployments: any registered service carrying a subdomain+domain
        # gets a concrete Host rule (its own cert via tlsChallenge — a wildcard
        # HostRegexp could not be issued one) plus an upstream pointed wherever
        # the deployment's node currently lives. Two claims on one subdomain
        # collapse to a single router; the later registration wins.
        routers = {}
        for svc in registry["services"].values():
            sub, dom = svc.get("subdomain"), svc.get("domain")
            if not sub or not dom:
                continue
            host = svc.get("host") or ((svc.get("hosts") or [None])[0])
            ip = _node_probe_addr(registry["nodes"].get(host or "") or {})
            url = f"http://{ip}:{svc.get('port') or 80}" if ip else EDGE_DEAD_UPSTREAM
            rname = f"deploy-{sub}"
            out[rname] = {"loadBalancer": {"servers": [{"url": url}]}}
            routers[rname] = {
                "rule": f"Host(`{sub}.{dom}`)",
                "entryPoints": ["websecure"],
                "service": rname,
                "tls": {"certResolver": "myresolver"},
            }
    body = {"http": {"services": out}}
    if routers:
        body["http"]["routers"] = routers
    return jsonify(body)


@app.route("/api/traefik/<name>", methods=["GET"])
def traefik_service(name):
    """Traefik HTTP-provider view of a service's live upstream.

    Edges poll this and get the upstream for wherever the container actually
    is, so moving a service between units never means editing a dynamic file.
    The port stays a caller convention (?port=, default 80) - what moves is
    the unit. A stopped service still resolves to its unit: the edge then
    502s, which is exactly what the wake errors-middleware watches for.
    """
    port = request.args.get("port", "80")
    with lock:
        url = _edge_upstream(name, _policy_for(name), port)
    return jsonify({"http": {"services": {
        name: {"loadBalancer": {"servers": [{"url": url}]}}}}})


# Images whose containers hold state on local disk. Matched against the IMAGE
# a unit actually reported, not the container's name: kc-pg-node walked straight
# through the "postgres"/"postgresql" entries in _PINNED_NAMES on 2026-09-04
# because it is spelled "pg", and the dedup worker queued six evictions against
# one half of the Keycloak HA database pair. A name is a human label; the image
# is what the thing IS.
_STATEFUL_IMAGE_MARKERS = (
    "postgres", "postgis", "pg-autofailover", "pgpool", "pgbouncer", "timescale",
    "mysql", "mariadb", "maxscale", "percona",
    "redis", "valkey", "memcached",
    "mongo", "cassandra", "elasticsearch", "opensearch", "influxdb", "clickhouse",
    "etcd", "consul", "vault", "openbao", "minio", "rabbitmq", "kafka", "zookeeper",
)


def _looks_stateful(instances):
    """True when any reported instance runs a known data-holding image.

    Migration moves the compose file and NOT the volume, so evicting one of
    these silently separates a database from its data.
    """
    for svc in instances or []:
        img = str((svc.get("metadata") or {}).get("image") or "").lower()
        if img and any(m in img for m in _STATEFUL_IMAGE_MARKERS):
            return True
    return False


def _is_multi_unit_service(name):
    """True when locator.yml assigns this service to more than one unit.

    Such a service is a per-unit agent — a log shipper, a host agent — not a
    duplicate. _PINNED_NAMES is the hardcoded version of this idea (it is why
    lokey survives running fleet-wide), but a name has to be added by hand,
    and anything missing from it gets torn down: enforce_unit_placement deploys
    the service onto every assigned unit and _enforce_dedup evicts it straight
    back off, the two workers undoing each other indefinitely. Reading the same
    'units:' field that drives placement keeps them from disagreeing.
    """
    spec = (_policy_for(name).get("units") or "").strip().lower()
    if spec == "all":
        return True
    return len(_expand_unit_spec(spec, [])) > 1


def _enforce_dedup(new_name, new_host):
    """
    Cross-node dedup: when a new instance of a non-pinned container registers,
    evict the older running instance on any other node via a git_push_and_stop
    migration. The target's lokey then receives a git_pull_only task once the
    push completes (queued by complete_migration).
    """
    if any(p in new_name.lower() for p in _PINNED_NAMES):
        return  # infrastructure — allowed on multiple nodes
    if _is_multi_unit_service(new_name):
        return  # per-unit agent — locator.yml says it belongs on several units

    with lock:
        instances = [
            dict(svc) for svc in registry["services"].values()
            if svc.get("name") == new_name and svc.get("status") == "ONLINE"
            and svc.get("type") == "container"  # never dedup websites/devices/apis
        ]
    hosts = {svc.get("host") for svc in instances if svc.get("host")}
    if len(hosts) <= 1:
        return  # nothing to evict

    # ── The default is to do NOTHING. ──────────────────────────────────────
    # This worker used to evict any duplicate that was not explicitly exempt,
    # so a service running on two nodes was ASSUMED to be a mistake and intent
    # had to be declared in advance. A forgotten locator.yml line was therefore
    # enough to tear down half of a working HA pair — which is exactly what it
    # tried to do to the Keycloak database on 2026-09-04, six times.
    # Destroying something is now the case that must be justified, not the
    # default. Everything else is reported and left alone; a real accidental
    # duplicate still shows up in the log, it just no longer acts unsupervised.
    if _looks_stateful(instances):
        print(f"🛡️  DEDUP SKIPPED: '{new_name}' on {sorted(hosts)} holds data "
              f"(image looks stateful) — migration moves the compose file, not "
              f"the volume. Declare it in locator.yml if this is wrong.")
        return
    if not _policy_for(new_name):
        print(f"🛡️  DEDUP SKIPPED: '{new_name}' running on {sorted(hosts)} with "
              f"no locator.yml policy. Not evicting on a guess — add an entry "
              f"with 'instances:'/'units:' if one of these should be removed.")
        return

    # Oldest-first by last_heartbeat; the newest (just registered) survives
    instances.sort(key=lambda s: s.get("last_heartbeat", ""))
    keeper = instances[-1]
    to_evict = instances[:-1]

    now = datetime.now(timezone.utc).isoformat()
    with migration_lock:
        if any(
            m.get("dedup") and m["status"] in ("PENDING", "IN_PROGRESS")
            and m.get("container") == new_name
            for m in migration_queue.values()
        ):
            return  # a dedup migration is already pending for this container
        for svc in to_evict:
            evict_host = svc.get("host", "")
            if not evict_host or evict_host == keeper.get("host"):
                continue
            mig_id = uuid.uuid4().hex[:8] + "-dedup-push"
            migration_queue[mig_id] = {
                "id":        mig_id,
                "type":      "git_push_and_stop",
                "unit":      evict_host,
                "container": new_name,
                "from_node": evict_host,
                "to_node":   keeper.get("host", new_host),
                "status":    "PENDING",
                "queued_at": now,
                "dedup":     True,
                "reason":    f"DEDUP: {new_name} duplicated on {evict_host}, keeping {keeper.get('host')}",
            }
            print(f"🧹 DEDUP: evicting {new_name}@{evict_host} → keeping {keeper.get('host')}")


# URLs on these domains are serverless/PaaS deployments (Fly, Vercel, Netlify,
# Supabase, Render, Cloudflare, GitLab/GitHub Pages, ...)
SERVERLESS_URL_PATTERN = re.compile(
    r"(fly\.dev|vercel\.app|netlify\.app|onrender\.com|supabase\.co|pages\.dev|"
    r"workers\.dev|railway\.app|herokuapp\.com|gitlab\.io|github\.io|web\.app|firebaseapp\.com)",
    re.IGNORECASE)


def _client_public_ip():
    """Real client IP behind Traefik, falling back to the direct socket peer."""
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def _infer_category(svc_type, url=""):
    """Default category when a registration doesn't declare one."""
    if svc_type == "native":
        return "devices"
    if svc_type == "vm":
        return "virtual machines"
    if svc_type in ("serverless", "paas"):
        return "serverless"
    if svc_type == "website":
        return "websites"
    if svc_type == "external":
        return "cloud platforms"
    if url and SERVERLESS_URL_PATTERN.search(str(url)):
        return "serverless"
    return "docker containers"


@app.route("/register", methods=["POST"])
def register_service():
    """
    Register or update a service. Also serves as the heartbeat.
    
    Expected JSON payload:
    {
        "name": "service-name",          (required)
        "url": "https://public.url",     (optional — public/Traefik URL)
        "internal": "http://container:port", (optional — Docker network URL)
        "host": "unit2",                 (optional — which node it runs on)
        "port": 8080,                    (optional)
        "type": "container|process|api", (optional, default: "container")
        "metadata": { ... }              (optional — any extra info)
    }
    """
    data = request.get_json(silent=True)
    if not data or "name" not in data:
        return jsonify({"error": "Missing required field: 'name'"}), 400

    sub = data.get("subdomain")
    dom = data.get("domain")
    if sub and not _DEPLOY_SUBDOMAIN.fullmatch(str(sub)):
        return jsonify({"error": "subdomain must be a DNS label ([a-z0-9-])"}), 400
    if dom and not _DEPLOY_DOMAIN.fullmatch(str(dom)):
        return jsonify({"error": "domain must be a DNS name ([a-z0-9.-])"}), 400

    name = data["name"]
    host = data.get("host", "unknown")
    service_id = f"{name}@{host}"
    now = datetime.now(timezone.utc).isoformat()

    with lock:
        existing = registry["services"].get(service_id, {})
        _prev_battery = (existing.get("metadata") or {}).get("battery_percent")

        _svc_type = data.get("type", existing.get("type", "container"))
        _category = data.get("category", existing.get("category", _infer_category(_svc_type, data.get("url", existing.get("url", "")))))
        registry["services"][service_id] = {
            "name": name,
            "category": _category,
            "url": data.get("url", existing.get("url", "")),
            "internal": data.get("internal", existing.get("internal", "")),
            "host": host,
            "hosts": data.get("hosts", [host]),
            "port": data.get("port", existing.get("port", None)),
            "type": _svc_type,
            "status": "ONLINE",
            "last_heartbeat": now,
            "registered_at": existing.get("registered_at", now),
            "metadata": data.get("metadata", existing.get("metadata", {})),
            # Optional migration hints — additive, absent on most existing entries.
            # depends_on: other service_ids ("name@host") that must have an ONLINE
            #   instance somewhere before this one is migrated (see resolve_migration_order()).
            # prereqs: target-host readiness needed before starting this service there
            #   after a native migration (see migrate_native.py, added in Phase 2).
            "depends_on": data.get("depends_on", existing.get("depends_on", [])),
            "prereqs": data.get("prereqs", existing.get("prereqs", {})),
            # Public deployment addressing — consumed by /api/traefik. Re-registering
            # with an empty subdomain clears the pair and withdraws the route.
            "subdomain": data.get("subdomain", existing.get("subdomain")),
            "domain": data.get("domain", existing.get("domain")),
        }

        # Self-registered devices (phones/tablets/laptops via /register-device) are also
        # first-class nodes, so they show up on the Tactical Grid's Devices & Nodes panel
        # (node cards + table), not just in the plain services list.
        if _category == "devices" and host != "unknown":
            existing_node = registry["nodes"].get(host, {})
            meta = data.get("metadata", existing.get("metadata", {})) or {}
            registry["nodes"][host] = {
                **existing_node,
                "type": meta.get("platform", existing_node.get("type", "device")),
                "status": "ONLINE",
                "last_seen": now,
                "ip": existing_node.get("ip", meta.get("ip", "")),
                # Real client-facing IP (not the self-reported LAN "ip" above) —
                # used as the geolocation fallback when a device has no GPS fix
                # (no location permission granted, or an indoor/no-signal node).
                "public_ip": _client_public_ip(),
                "metadata": meta,
            }

        # Update the node as ONLINE whenever any service heartbeats from it
        if host != "unknown" and host in registry["nodes"]:
            registry["nodes"][host]["status"] = "ONLINE"
            registry["nodes"][host]["last_seen"] = now
        registry["updated"] = now

    persist_registry()
    if host != "unknown":
        _enforce_dedup(name, host)

    if _category == "docker containers":
        _cm = data.get("metadata") or {}
        if _cm.get("mem_usage_mb") is not None:
            try:
                db.insert_container_metric(service_id, host,
                                            _cm.get("mem_usage_mb"),
                                            _cm.get("mem_percent"))
            except Exception as e:
                print(f"⚠️  Failed to persist container metric: {e}")

    _new_battery = (registry["services"][service_id].get("metadata") or {}).get("battery_percent")
    if _new_battery is not None:
        _check_battery_threshold(service_id, _new_battery, _prev_battery)

    print(f"📡 REGISTERED: {service_id} → {data.get('internal', data.get('url', 'unknown'))}")
    return jsonify({"result": "registered", "service": service_id}), 200


@app.route("/deregister/<name>", methods=["DELETE"])
def deregister_service(name):
    """Mark a service OFFLINE. Hard-delete only after 90 days offline (enforced by reaper)."""
    with lock:
        if name in registry["services"]:
            now = datetime.now(timezone.utc).isoformat()
            registry["services"][name]["status"] = "OFFLINE"
            # Only start the 90-day clock if it hasn't started already
            if not registry["services"][name].get("offline_since"):
                registry["services"][name]["offline_since"] = now
            registry["updated"] = now

    persist_registry()
    print(f"📴 MARKED OFFLINE (90-day retention): {name}")
    return jsonify({"result": "marked_offline", "retained_for": "90 days", "service": name}), 200


@app.route("/api/registry/<kind>/<path:entry_id>", methods=["DELETE"])
def delete_registry_entry(kind, entry_id):
    """Hard-delete a registry row — unlike /deregister/<name>, which only marks
    a service OFFLINE for the 90-day reaper. Exists for stale node rows and
    orphaned service entries that will never heartbeat again; the dashboard's
    device sheet exposes it as the Delete button. If the thing is still alive
    it simply re-registers on its next heartbeat."""
    denied = _require_admin_key()
    if denied:
        return denied
    if kind not in ("services", "nodes"):
        return jsonify({"error": "kind must be 'services' or 'nodes'"}), 400
    with lock:
        if entry_id not in registry.get(kind, {}):
            return jsonify({"error": f"'{entry_id}' not found in {kind}"}), 404
        del registry[kind][entry_id]
        registry["updated"] = datetime.now(timezone.utc).isoformat()
    persist_registry()
    print(f"🗑️ DELETED {kind[:-1]}: {entry_id}")
    return jsonify({"result": "deleted", "kind": kind, "id": entry_id}), 200


@app.route("/api/container/toggle", methods=["POST"])
def toggle_container():
    """Queue a start/stop command for the Lokey agent on the container's host.
    The Locator never touches Docker itself \u2014 it only tells the owning unit's
    lokey to perform the action (same command_queue used by /api/idle/wake
    and /api/shutdown), which then executes locally and reports back via
    /api/commands/complete."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    name   = data.get("name", "").strip()
    action = data.get("action", "").strip()
    if not name or action not in ("start", "stop"):
        return jsonify({"error": "Provide 'name' and 'action' (start|stop)"}), 400
    unit = _find_container_unit(name)
    if not unit:
        return jsonify({"error": f"Container '{name}' not found in registry"}), 404
    cmd = _queue_command(unit, name, action, source="manual")
    print(f"\U0001f4e8 TOGGLE: queued {action} for '{name}' on {unit}")
    return jsonify({"result": "queued", "container": name, "unit": unit, "command": cmd})

@app.route("/api/compose", methods=["GET"])
def list_compose_files():
    """List all stored compose files."""
    result = {}
    for name in _list_compose_names():
        path = _compose_path(name)
        stat = os.stat(path)
        result[name] = {
            "name": name,
            "saved_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "size_bytes": stat.st_size,
        }
    return jsonify(result)


@app.route("/api/service-networks", methods=["GET"])
def service_networks():
    """Return a map of normalized service name -> [networks] parsed from all compose files."""
    try:
        import yaml as _yaml
    except ImportError:
        return jsonify({"error": "pyyaml not available"}), 500

    net_map = {}  # normalized_name -> [networks]
    for compose_name in _list_compose_names():
        path = _compose_path(compose_name)
        try:
            with open(path) as f:
                doc = _yaml.safe_load(f) or {}
            for svc_name, svc_def in (doc.get("services") or {}).items():
                if not svc_def:
                    continue
                nets_raw = svc_def.get("networks", {})
                if isinstance(nets_raw, dict):
                    nets = list(nets_raw.keys())
                elif isinstance(nets_raw, list):
                    nets = nets_raw
                else:
                    continue
                if not nets:
                    continue
                # Store under service name (raw) and normalized (no - _)
                norm = svc_name.lower().replace("-", "").replace("_", "")
                for key in (svc_name, norm):
                    if key not in net_map:
                        net_map[key] = nets
        except Exception:
            continue
    return jsonify(net_map)


@app.route("/api/compose/<name>", methods=["GET"])
def get_compose_file(name):
    """Return a stored compose file as YAML."""
    path = _compose_path(name)
    if not os.path.exists(path):
        return jsonify({"error": f"Compose file '{name}' not found"}), 404
    with open(path) as f:
        content = f.read()
    return Response(content, mimetype="text/yaml")


@app.route("/api/compose/<name>", methods=["POST", "PUT"])
def save_compose_file(name):
    """Store or replace a compose file. Accepts raw YAML body or JSON {content: '...'}."""
    ct = request.content_type or ""
    if "application/json" in ct:
        data = request.get_json(silent=True) or {}
        content = data.get("content", "")
    else:
        content = request.get_data(as_text=True)

    if not content.strip():
        return jsonify({"error": "Empty compose file"}), 400

    with open(_compose_path(name), "w") as f:
        f.write(content)

    if GIT_AUTO_PUSH:
        _git_push_event.set()
    print(f"💾 COMPOSE STORED: {name}")
    return jsonify({"result": "saved", "name": name}), 200


@app.route("/api/compose/<name>", methods=["DELETE"])
def delete_compose_file(name):
    """Delete a stored compose file."""
    path = _compose_path(name)
    if not os.path.exists(path):
        return jsonify({"error": f"Compose file '{name}' not found"}), 404
    os.remove(path)
    print(f"🗑️  COMPOSE DELETED: {name}")
    return jsonify({"result": "deleted", "name": name}), 200



@app.route("/api/yamls", methods=["GET"])
def list_yamls():
    """Compose files the units have uploaded, for the dashboard's YAMLs tab.

    This used to read com.docker.compose.project.working_dir off live
    containers and stat() those paths \u2014 but they are HOST paths and this
    container mounts no host filesystem (only registry_data, templates, .ssh
    and the docker socket). Every isfile() check therefore failed and the tab
    rendered "No compose files found" while 26 files sat in the store.

    Serve the uploaded store instead: lokey pushes each unit's compose files
    here, the paths are real inside this container, and /api/yaml can read and
    write them unchanged.
    """
    results = []
    # Service policy first — it governs what may migrate and where, so it is the
    # one file most worth being editable from the dashboard.
    if os.path.isfile(LOCATOR_YML):
        results.append({
            "label": "locator.yml (service policy)",
            "container": "locator.yml",
            "path": LOCATOR_YML,
        })
    # The locator's own compose file, so its deployment is editable from the
    # same place as its policy.
    if os.path.isfile(LOCATOR_COMPOSE):
        results.append({
            "label": "docker-compose.yml (locator)",
            "container": "docker-compose.yml",
            "path": LOCATOR_COMPOSE,
        })
    # Blank starting points. Served from constants rather than files so they
    # cannot be overwritten by a stray save — "Save As" writes a copy into the
    # compose store instead.
    for key, label in (
        (TEMPLATE_LOCATOR_YML, "▸ new locator.yml (blank template)"),
        (TEMPLATE_COMPOSE_YML, "▸ new docker-compose.yml (blank template)"),
    ):
        results.append({
            "label": label,
            "container": key,
            "path": key,
            "readonly": True,
        })
    try:
        for fname in sorted(os.listdir(COMPOSE_DIR)):
            if not fname.endswith((".yml", ".yaml")):
                continue
            label = os.path.splitext(fname)[0]
            results.append({
                "label": label,
                "container": label,
                "path": os.path.join(COMPOSE_DIR, fname),
            })
    except FileNotFoundError:
        print(f"\u26a0\ufe0f  YAML store not found at {COMPOSE_DIR}")
    except Exception as e:
        print(f"\u26a0\ufe0f  YAML scan error: {e}")
    return jsonify(results)

@app.route("/api/yaml", methods=["GET"])
def get_yaml():
    path = request.args.get("path", "")
    if path in YAML_TEMPLATES:
        return jsonify({"path": path, "content": YAML_TEMPLATES[path], "readonly": True})
    if not path or not os.path.isfile(path):
        return jsonify({"error": "Not found"}), 404
    try:
        with open(path, "r", errors="replace") as f:
            return jsonify({"path": path, "content": f.read()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/yaml", methods=["POST"])
def save_yaml():
    """Write a YAML back.

    `save_as` writes a new file into the compose store instead of the given
    path — that is the only way to save a blank template, which is otherwise
    read-only so the starting point survives being edited.
    """
    path = request.args.get("path", "")
    data = request.get_json(silent=True)
    if not data or "content" not in data:
        return jsonify({"error": "No content"}), 400

    save_as = (data.get("save_as") or "").strip()
    if save_as:
        name = os.path.basename(save_as)
        if not name.endswith((".yml", ".yaml")):
            name += ".yml"
        if name.startswith("."):
            return jsonify({"error": "Invalid filename"}), 400
        os.makedirs(COMPOSE_DIR, exist_ok=True)
        path = os.path.join(COMPOSE_DIR, name)
    elif path in YAML_TEMPLATES:
        return jsonify({
            "error": "Blank templates are read-only — use Save As to create a copy."
        }), 400

    if not path:
        return jsonify({"error": "No path"}), 400
    try:
        with open(path, "w") as f:
            f.write(data["content"])
        beast_log(f"\U0001f4dd YAML saved: {path}")
        return jsonify({"ok": True, "status": "saved", "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _write_policy_field(service, key, value):
    """Set one key on one service in locator.yml, in place.

    Done as a line edit rather than a yaml.safe_load/dump round-trip on
    purpose: this file is mostly comments — the quoting trap on `units`, why
    each database is stationary — and a dump would silently delete all of it.
    """
    with open(LOCATOR_YML, "r") as fh:
        lines = fh.readlines()

    target = service.lower()
    in_block = False        # inside the top-level "Service:" mapping
    svc_line = None         # index of the "  <service>:" header
    svc_indent = 0
    end = len(lines)
    blk_line = None         # index of the top-level "Service:" header itself
    blk_end = None          # first line after the whole Service mapping
    entry_indent = None     # indent the existing service entries use

    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())

        if indent == 0:
            in_block = stripped.rstrip(":").lower() in ("service", "services")
            if in_block:
                blk_line = i
            elif blk_line is not None and blk_end is None:
                blk_end = i
            if svc_line is not None:
                end = i
                break
            continue
        if not in_block:
            continue

        if entry_indent is None:
            entry_indent = indent

        if svc_line is None:
            if stripped.endswith(":") and stripped[:-1].strip().lower() == target:
                svc_line, svc_indent = i, indent
        elif indent <= svc_indent:
            end = i
            break

    if svc_line is None:
        # Not in the file yet. Append a block rather than refusing: the tactical
        # grid lets any running container be pinned, and most of them have never
        # had a policy entry. Written as text for the same reason the rest of
        # this function is — a yaml round-trip would strip every comment.
        if blk_line is None:
            return False, "locator.yml has no 'Service:' block"

        ind = " " * (entry_indent or 2)
        fields = {
            "deployment_type": DEPLOYMENT_NON_ESSENTIAL,
            "location_type":   "mobile",
            "units":           "current_unit",
            "instances":       1,
        }
        fields[key] = value

        at = blk_end if blk_end is not None else len(lines)
        while at > 0 and not lines[at - 1].strip():   # keep trailing blanks below
            at -= 1

        block = []
        if at > 0 and lines[at - 1].strip():
            block.append("\n")          # keep one blank line between entries
        block += [f"{ind}# added from the tactical grid {datetime.now():%Y-%m-%d}\n",
                  f"{ind}{service}:\n"]
        block += [f"{ind}  {k}: {v}\n" for k, v in fields.items()]
        block.append("\n")
        lines[at:at] = block

        with open(LOCATOR_YML, "w") as fh:
            fh.writelines(lines)
        return True, None

    field_indent = " " * (svc_indent + 2)
    for i in range(svc_line + 1, end):
        stripped = lines[i].strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.split(":")[0].strip().lower() == key:
            lines[i] = f"{field_indent}{key}: {value}\n"
            break
    else:
        lines.insert(svc_line + 1, f"{field_indent}{key}: {value}\n")

    with open(LOCATOR_YML, "w") as fh:
        fh.writelines(lines)
    return True, None


@app.route("/api/policy", methods=["GET"])
def get_policy():
    """Per-service essential/stationary flags for the tactical grid checkboxes."""
    out = {}
    for name, cfg in load_policy().items():
        out[name] = {
            "essential": is_essential(cfg),
            "stationary": cfg.get("location_type") == "stationary",
            "units": cfg.get("units", ""),
            "instances": cfg.get("instances", 1),
        }
    return jsonify(out)


def _is_name_locked(name):
    """True when a name is pinned by code and cannot be unpinned from the grid.

    _PINNED_NAMES is a substring list baked into this file, and _is_pinned()
    consults it regardless of what locator.yml says — so unticking one of these
    in the dashboard changed the YAML but not the behaviour. The box lied.
    These are cemented instead: shown ticked, disabled, and refused server-side.
    """
    low = (name or "").lower()
    return any(p in low for p in _PINNED_NAMES)


@app.route("/api/policy/<unit>", methods=["GET"])
def get_policy_for_unit(unit):
    """Policy entries that apply to one unit — for lokey's local enforcement.

    lokey enforces restart_when_stopped itself from its own Docker socket.
    The locator-side critical_service_watchdog() that used to queue starts
    was removed 2026-09-15: it keyed off registry OFFLINE status, which
    flaps, so it "restarted" running services, and its hardcoded floor
    (lokey, lokey-client, locator, apache on the long-gone unit2) named only
    things a queued command can never restart. Serving the policy lets each
    agent act from its own Docker socket with no round trip, and keep acting
    from its cached copy when this locator is unreachable.

    Sits in INGEST beside commands_pending: lokey presents no user token,
    only a Host header. Exposes strictly less than /api/policy — only entries
    naming this unit, and never the env: block, which carries credentials.
    """
    unit = (unit or "").strip().lower()
    out = {}
    for name, cfg in load_policy().items():
        spec = (cfg.get("units") or "").strip().lower()
        # "all" and "current_unit" are answered without consulting the
        # registry on purpose. Resolving "all" against ONLINE nodes would
        # reintroduce the dependency this endpoint exists to remove, and an
        # agent can only ever start a container already present on its host.
        if spec in ("", "all", "current_unit") or unit in _expand_unit_spec(spec, []):
            out[name] = {
                "restart_when_stopped": bool(cfg.get("restart_when_stopped")),
                "deployment_type": cfg.get("deployment_type", ""),
                "location_type": cfg.get("location_type", ""),
            }
    return jsonify(out)

@app.route("/api/policy/locked", methods=["GET"])
def get_policy_locked():
    """The hardcoded pin substrings, so the grid can cement matching rows."""
    return jsonify({"names": sorted(_PINNED_NAMES)})


@app.route("/api/policy", methods=["POST"])
def set_policy():
    """Flip one flag from the dashboard.

    Body: {"service": "pdns", "essential": true}  or  {"stationary": false}

    Only the flag named in the body is touched, so ticking Essential cannot
    quietly clear a service's stationary pin.
    """
    data = request.get_json(silent=True) or {}
    service = (data.get("service") or "").strip()
    if not service:
        return jsonify({"error": "No service"}), 400

    # A grid row is "name@unit"; policy is keyed on the bare service name.
    service = service.split("@")[0]

    if "essential" in data:
        key, value = "deployment_type", DEPLOYMENT_ESSENTIAL if data["essential"] else DEPLOYMENT_NON_ESSENTIAL
    elif "stationary" in data:
        key, value = "location_type", "stationary" if data["stationary"] else "mobile"
        if not data["stationary"] and _is_name_locked(service):
            return jsonify({"error": f"'{service}' is cemented — pinned in code, "
                                     f"cannot be unpinned"}), 409
    else:
        return jsonify({"error": "Nothing to set"}), 400

    ok, err = _write_policy_field(service, key, value)
    if not ok:
        return jsonify({"error": err}), 404

    _policy_cache["mtime"] = None      # force reload on next read
    beast_log(f"\U0001f4dd policy: {service} {key}={value}")
    return jsonify({"ok": True, "service": service, key: value})


@app.route("/api/policy/bulk", methods=["POST"])
def set_policy_bulk():
    """Apply a batch of grid checkbox changes in one request.

    Body: {"changes": [{"service": "forge", "stationary": true},
                       {"service": "redis", "essential": false}, ...]}

    The tactical grid stages ticks locally and sends them here on Save, so a
    mis-click can be discarded before it ever reaches locator.yml. Each entry
    carries exactly one flag, matching /api/policy's rule that setting Pinned
    must never quietly clear Essential.

    Partial success is normal and reported per service: one unwritable entry
    should not discard the rest of the batch.
    """
    data = request.get_json(silent=True) or {}
    changes = data.get("changes")
    if not isinstance(changes, list) or not changes:
        return jsonify({"error": "No changes"}), 400

    saved, failed = [], []
    for entry in changes:
        if not isinstance(entry, dict):
            failed.append({"service": str(entry), "error": "Malformed entry"})
            continue

        service = (entry.get("service") or "").strip().split("@")[0]
        if not service:
            failed.append({"service": "", "error": "No service"})
            continue

        if "essential" in entry:
            key, value = "deployment_type", DEPLOYMENT_ESSENTIAL if entry["essential"] else DEPLOYMENT_NON_ESSENTIAL
        elif "stationary" in entry:
            key, value = "location_type", "stationary" if entry["stationary"] else "mobile"
            if not entry["stationary"] and _is_name_locked(service):
                failed.append({"service": service,
                               "error": "cemented — pinned in code, cannot be unpinned"})
                continue
        else:
            failed.append({"service": service, "error": "Nothing to set"})
            continue

        ok, err = _write_policy_field(service, key, value)
        if ok:
            saved.append({"service": service, key: value})
            beast_log(f"\U0001f4dd policy: {service} {key}={value}")
        else:
            failed.append({"service": service, "error": err})

    # One invalidation for the whole batch — every write went to the same file.
    _policy_cache["mtime"] = None
    return jsonify({"ok": not failed, "saved": saved, "failed": failed})


SSH_MOUNT_DIR   = "/root/.ssh"
SSH_RUNTIME_DIR = "/root/.ssh-run"
_ssh_dir_cache  = {"ready": False, "opts": None}


def _ssh_base_opts():
    """SSH options that work from inside this container.

    ~/.ssh is bind-mounted read-only from the host, where it is owned by uid
    1000 with a group-writable config. This container runs as root, so OpenSSH
    rejects the lot — 'Bad owner or permissions on /root/.ssh/config' — and
    every ssh/scp call fails before it reaches the network. That is why deploy
    failed for every node regardless of target.

    Copy the mount into a root-owned directory with tight permissions and use
    that instead. The config's IdentityFile lines point at ~/.ssh/..., which
    would resolve straight back to the bad mount, so rewrite them to the copy.
    """
    if _ssh_dir_cache["ready"]:
        return _ssh_dir_cache["opts"]

    opts = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
    try:
        if os.path.isdir(SSH_MOUNT_DIR):
            os.makedirs(SSH_RUNTIME_DIR, exist_ok=True)
            os.chmod(SSH_RUNTIME_DIR, 0o700)
            for fname in os.listdir(SSH_MOUNT_DIR):
                src = os.path.join(SSH_MOUNT_DIR, fname)
                dst = os.path.join(SSH_RUNTIME_DIR, fname)
                if not os.path.isfile(src):
                    continue
                with open(src, "rb") as fh:
                    blob = fh.read()
                if fname == "config":
                    blob = (blob.decode(errors="replace")
                            .replace("~/.ssh/", SSH_RUNTIME_DIR + "/")
                            .replace("/root/.ssh/", SSH_RUNTIME_DIR + "/")
                            .replace("/home/swoopg111/.ssh/", SSH_RUNTIME_DIR + "/")
                            ).encode()
                with open(dst, "wb") as fh:
                    fh.write(blob)
                os.chmod(dst, 0o600)
            cfg = os.path.join(SSH_RUNTIME_DIR, "config")
            if os.path.isfile(cfg):
                opts = ["-F", cfg] + opts
    except Exception as e:
        print(f"⚠️  SSH config prep failed, falling back to defaults: {e}")

    _ssh_dir_cache.update({"ready": True, "opts": opts})
    return opts


@app.route("/api/deploy/<name>", methods=["POST"])
def deploy_compose(name):
    """
    Deploy a stored compose file to the most available node (or a pinned one).

    Optional JSON body:
    { "node": "unit2" }        — pin a target instead of auto-selecting
    { "networks": ["auth"] }   — join these existing (external) networks
    """
    import yaml as _yaml
    import subprocess as _sp

    path = _compose_path(name)
    if not os.path.exists(path):
        return jsonify({"error": f"Compose file '{name}' not found"}), 404

    data = request.get_json(silent=True) or {}
    forced_node = data.get("node")
    join_networks = [n for n in (data.get("networks") or []) if str(n).strip()]

    if forced_node:
        with lock:
            node_info = registry["nodes"].get(forced_node, {})
        # A dead node keeps its last known IP, so without this the deploy
        # spends the full SSH timeout before failing with nothing useful.
        if node_info.get("status") != "ONLINE":
            return jsonify({
                "error": f"Node '{forced_node}' is not ONLINE",
            }), 400
        ip = _first_addr(node_info.get("tailscale_ip")) \
            or _first_addr(node_info.get("openvpn_ip")) \
            or _first_addr(node_info.get("ip"))
        if not ip or ip == "unknown":
            return jsonify({"error": f"No reachable IP for node '{forced_node}'"}), 400
        targets = [(forced_node, ip)]
    else:
        # Ordered by headroom. Only the first few are worth trying — past that
        # the "most available node" claim stops meaning anything.
        targets = _ranked_nodes()[:3]
        if not targets:
            return jsonify({"error": "No online nodes with reachable IPs"}), 503

    remote_dir  = f"/tmp/locator_deploy/{name}"
    remote_file = f"{remote_dir}/docker-compose.yml"
    # Use the SSH config alias (node name) so per-host port/user/key from ~/.ssh/config
    # are respected (e.g. unit1 tunnels through localhost:2222 with its own key).
    # Fall back to explicit user@ip only if no config alias exists.
    ssh_opts   = _ssh_base_opts()

    # Networks picked in the UI are injected into a copy of the compose file —
    # the stored original is never rewritten. They are declared external
    # because /api/networks lists networks that already exist on the host.
    send_path = path
    tmp_path = None
    if join_networks:
        try:
            with open(path) as fh:
                doc = _yaml.safe_load(fh) or {}
            for cfg in (doc.get("services") or {}).values():
                if not isinstance(cfg, dict):
                    continue
                existing = cfg.get("networks") or []
                if isinstance(existing, dict):
                    for net in join_networks:
                        existing.setdefault(net, None)
                else:
                    for net in join_networks:
                        if net not in existing:
                            existing.append(net)
                cfg["networks"] = existing
            declared = doc.get("networks")
            if not isinstance(declared, dict):
                declared = {}
            for net in join_networks:
                declared.setdefault(net, {"external": True})
            doc["networks"] = declared

            fd, tmp_path = tempfile.mkstemp(suffix=".yml", prefix=f"{name}-")
            with os.fdopen(fd, "w") as fh:
                _yaml.safe_dump(doc, fh, sort_keys=False)
            send_path = tmp_path
        except Exception as e:
            return jsonify({"error": f"Could not add networks: {e}"}), 400

    def _attempt(ssh_target):
        """Ship the compose file to one node and bring it up there."""
        _sp.run(
            ["ssh"] + ssh_opts + [ssh_target, f"mkdir -p {remote_dir}"],
            check=True, capture_output=True, timeout=15
        )
        _sp.run(
            ["scp"] + ssh_opts + [send_path, f"{ssh_target}:{remote_file}"],
            check=True, capture_output=True, timeout=15
        )
        return _sp.run(
            ["ssh"] + ssh_opts + [ssh_target, f"cd {remote_dir} && docker compose up -d"],
            capture_output=True, text=True, timeout=120
        )

    try:
        attempts = []
        result = None
        target_node = target_ip = None

        for candidate_node, candidate_ip in targets:
            # SSH config alias (unit1, unit3 …) so per-host user/port/key apply.
            try:
                outcome = _attempt(candidate_node)
            except _sp.CalledProcessError as e:
                stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
                attempts.append({"node": candidate_node, "error": stderr.strip() or str(e)})
                continue
            if outcome.returncode != 0:
                attempts.append({"node": candidate_node, "error": (outcome.stderr or "").strip()})
                continue
            result, target_node, target_ip = outcome, candidate_node, candidate_ip
            break

        if result is None:
            return jsonify({
                "error": "docker compose up failed",
                "stderr": "; ".join(f"{a['node']}: {a['error']}" for a in attempts),
                "attempts": attempts,
                "node": attempts[0]["node"] if attempts else None,
            }), 500

        if len(attempts) > 0:
            print(f"↩️  DEPLOY fell through {[a['node'] for a in attempts]} → {target_node}")

        # Register every service from the compose file
        now = datetime.now(timezone.utc).isoformat()
        try:
            with open(path) as f:
                compose_data = _yaml.safe_load(f) or {}
            with lock:
                for svc_name in compose_data.get("services", {}):
                    svc_id   = f"{svc_name}@{target_node}"
                    existing = registry["services"].get(svc_id, {})
                    registry["services"][svc_id] = {
                        **existing,
                        "name":           svc_name,
                        "host":           target_node,
                        "hosts":          [target_node],
                        "category":       "docker containers",
                        "status":         "ONLINE",
                        "last_heartbeat": now,
                        "registered_at":  existing.get("registered_at", now),
                        "type":           "container",
                        "metadata": {
                            **existing.get("metadata", {}),
                            "compose_name":  name,
                            "deployed_via":  "locator",
                        },
                    }
                registry["updated"] = now
            persist_registry()
        except Exception:
            pass  # registry update is best-effort

        print(f"🚀 DEPLOYED: '{name}' → {target_node} ({target_ip})")
        return jsonify({
            "result":   "deployed",
            "name":     name,
            "node":     target_node,
            "ip":       target_ip,
            "output":   result.stdout,
            "skipped":  attempts,   # nodes tried first and why they failed
        }), 200

    except _sp.TimeoutExpired:
        return jsonify({"error": "SSH/SCP timed out", "node": target_node}), 504
    except _sp.CalledProcessError as e:
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return jsonify({"error": str(e), "stderr": stderr, "node": target_node}), 500
    except Exception as e:
        return jsonify({"error": str(e), "node": target_node}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass


@app.route("/nodes", methods=["GET"])
@app.route("/api/nodes", methods=["GET"])
def get_nodes():
    """Return the known nodes the caller is cleared to see."""
    with lock:
        return jsonify(clearance.project(registry["nodes"]))


def _metrics_range_args():
    """Parse since/until query params (ISO timestamps, required) shared by
    every /api/metrics/* route. Returns (since, until) or a Flask error
    response tuple to short-circuit the caller."""
    since = request.args.get("since")
    until = request.args.get("until")
    if not since or not until:
        return None, None, (jsonify({"error": "since and until (ISO timestamps) are required"}), 400)
    return since, until, None


@app.route("/api/metrics/summary", methods=["GET"])
def metrics_summary():
    """Distinct containers active in [since, until), broken down by host.
    Backs the Metrics tab's time-range picker."""
    since, until, err = _metrics_range_args()
    if err:
        return err
    try:
        result = db.metrics_summary(since, until)
    except Exception as e:
        print(f"⚠️  Failed to read metrics summary: {e}")
        return jsonify({"error": "metrics unavailable"}), 503
    if result is None:
        return jsonify({"error": "metrics unavailable"}), 503
    return jsonify(result)


@app.route("/api/metrics/containers", methods=["GET"])
def metrics_containers():
    """Per-container rollup (first/last seen, avg/max RAM) in [since, until)."""
    since, until, err = _metrics_range_args()
    if err:
        return err
    try:
        return jsonify(db.metrics_containers(since, until))
    except Exception as e:
        print(f"⚠️  Failed to read metrics containers: {e}")
        return jsonify({"error": "metrics unavailable"}), 503


@app.route("/api/metrics/history", methods=["GET"])
def metrics_history():
    """Ordered raw RAM samples for one container, for the history chart."""
    service_id = request.args.get("service_id")
    if not service_id:
        return jsonify({"error": "service_id is required"}), 400
    since, until, err = _metrics_range_args()
    if err:
        return err
    try:
        return jsonify(db.metrics_history(service_id, since, until))
    except Exception as e:
        print(f"⚠️  Failed to read metrics history: {e}")
        return jsonify({"error": "metrics unavailable"}), 503


@app.route("/nodes", methods=["POST"])
def update_nodes():
    """
    Update node information. The sentry pushes devices.json data here.
    
    Expected JSON payload:
    {
        "node_name": {
            "ip": "172.x.x.x",
            "type": "brain|lighthouse|vps",
            "status": "ONLINE",
            "peripherals": []
        }
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided"}), 400

    now = datetime.now(timezone.utc).isoformat()

    with lock:
        for node_name, node_info in data.items():
            registry["nodes"][node_name] = node_info
        registry["updated"] = now

    persist_registry()
    print(f"🌐 NODES UPDATED: {list(data.keys())}")
    return jsonify({"result": "nodes_updated", "count": len(data)}), 200


@app.route("/health", methods=["GET"])
def health_check():
    """Locator health check."""
    with lock:
        service_count = len(registry["services"])
        online_count = sum(1 for s in registry["services"].values() if s.get("status") == "ONLINE")
        node_count = len(registry["nodes"])

    return jsonify({
        "status": "ONLINE",
        "service": "locator",
        "unit_name": UNIT_NAME,
        "is_primary": LOCATOR_IS_PRIMARY,
        "started_at": _STARTED_AT.isoformat(),
        "services_registered": service_count,
        "services_online": online_count,
        "nodes_known": node_count,
        "heartbeat_timeout_seconds": HEARTBEAT_TIMEOUT,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/whoami", methods=["GET"])
def whoami():
    """Identify the caller and report what its clearance unlocks. Public."""
    principal = clearance.current()
    body = principal.to_dict()
    body["levels"] = clearance.LEVEL_NAMES
    if principal.via == "invalid-token":
        body["token_error"] = principal.claims.get("error", "token rejected")
    return jsonify(body)


@app.route("/api/election", methods=["GET"])
def election_status():
    """Live view of the locator election — who would win, and why.

    Exposed so the ranking can be judged at a glance instead of by grepping
    container logs, and so it stays inspectable while ELECTION_DRY_RUN is on.
    """
    hosts = _locator_hosts()
    with lock:
        known = list(registry["nodes"].keys())
        nodes = {u: dict(registry["nodes"].get(u) or {}) for u in known}

    board = []
    for unit in known:
        tier, ram_mb = _node_health(unit)
        info = nodes[unit]
        board.append({
            "unit": unit,
            "tier": tier,
            "disk_critical": tier < 0,
            "ram_available_mb": ram_mb,
            "ram_total_mb": _node_ram_total_mb(info),
            "mem_percent": info.get("mem_percent"),
            "disk_percent": info.get("disk_percent"),
            "runs_locator": unit in hosts,
            "is_self": unit == UNIT_NAME,
            "eligible": ram_mb >= ELECTION_MIN_RAM_MB and tier >= 0,
        })
    board.sort(key=lambda r: ((r["tier"], r["ram_available_mb"]), r["unit"]), reverse=True)

    contenders = [r for r in board if r["runs_locator"]]
    winner = contenders[0]["unit"] if contenders else None
    return jsonify({
        "dry_run": ELECTION_DRY_RUN,
        "self": UNIT_NAME,
        "winner": winner,
        "would_stop_self": bool(winner and winner != UNIT_NAME),
        "locator_hosts": sorted(hosts),
        "thresholds": {
            "min_ram_mb": ELECTION_MIN_RAM_MB,
            "disk_veto_percent": DISK_VETO_PERCENT,
            "interval_seconds": ELECTION_INTERVAL,
        },
        "ranking": board,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/client-error", methods=["POST"])
def report_client_error():
    """Receive a browser-side JS error report (window.onerror / unhandledrejection
    / an explicit try/catch) from the dashboard or any page that includes the
    error-reporter snippet. Stored in-memory (bounded) and printed to stdout so
    it survives in `fly logs` even if the process restarts."""
    payload = request.get_json(silent=True) or {}
    entry = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "message": str(payload.get("message", ""))[:2000],
        "stack": str(payload.get("stack", ""))[:4000],
        "source_url": str(payload.get("sourceUrl", ""))[:500],
        "page_url": str(payload.get("pageUrl", ""))[:500],
        "line": payload.get("line"),
        "col": payload.get("col"),
        "user_agent": str(payload.get("userAgent", ""))[:300],
    }
    with client_error_lock:
        client_errors.append(entry)
        if len(client_errors) > CLIENT_ERROR_MAX:
            del client_errors[: len(client_errors) - CLIENT_ERROR_MAX]

    print(f"\U0001f6a8 CLIENT-ERROR [{entry['page_url']}]: {entry['message']} "
          f"({entry['source_url']}:{entry['line']}:{entry['col']})")

    try:
        db.insert_client_error({**entry, "received_at": entry["received_at"]})
    except Exception as e:
        print(f"⚠️  Failed to persist client error to Postgres: {e}")

    return jsonify({"status": "logged"}), 200


@app.route("/api/client-errors", methods=["GET"])
def list_client_errors():
    """Return recently reported browser-side JS errors, newest first.
    Postgres first (survives restarts), falling back to the in-memory ring buffer."""
    try:
        persisted = db.list_client_errors(CLIENT_ERROR_MAX)
        if persisted is not None:
            return jsonify(persisted)
    except Exception as e:
        print(f"⚠️  Failed to read client errors from Postgres: {e}")
    with client_error_lock:
        return jsonify(list(reversed(client_errors)))


# ── Event log ──────────────────────────────────────────────────────────────
# Backs the tactical grid's EVENT LOG box. Postgres-backed (see db.py); GET
# returns recent history, /stream is a Server-Sent Events feed for live
# updates (not a WebSocket — this app runs under gunicorn's gthread worker
# class, which doesn't support WebSocket upgrades; SSE works over plain HTTP).
_event_stream_queues = []
_event_stream_lock = threading.Lock()


def emit_event(event_type, **data):
    """Record an event to Postgres and push it to any connected SSE streams.
    Call this from wherever something event-worthy happens (migrations, DNS
    sync, etc.) — e.g. emit_event('migration', from_container=..., to_container=..., unit=...)."""
    try:
        event = db.insert_event(event_type, data)
    except Exception as e:
        print(f"⚠️  Failed to persist event to Postgres: {e}")
        event = None
    if not event:
        # insert_event returns None (does not raise) when there's no
        # DATABASE_URL or the DB is down — this branch used to push literal
        # "null" frames to SSE clients and leave /api/events permanently empty.
        # The in-memory ring keeps the event box alive without Postgres.
        event = {"type": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), **data}
    with _event_lock:
        _event_log.append(event)
        del _event_log[:-EVENT_LOG_MAX]
    with _event_stream_lock:
        for q in _event_stream_queues:
            q.put(event)
    return event


@app.route("/api/events", methods=["GET", "POST"])
def list_events_route():
    """Return recent events, oldest first (matches what the dashboard expects to append in order).

    POST lets units report their own events — lokey's repo-sync posts its
    failures here. Those previously reached only a container log on the unit
    itself, which is how a decommissioned locator URL and an eight-commit drift
    went unnoticed for weeks.
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        message = str(data.get("message", ""))[:500]
        if not message:
            return jsonify({"error": "message required"}), 400
        kind = str(data.get("type", "unit"))[:40]
        unit = str(data.get("unit", ""))[:40]
        event = emit_event(kind, message=message, unit=unit)
        return jsonify({"result": "recorded", "timestamp": (event or {}).get("created_at")})

    try:
        events = db.list_events(200)
    except Exception as e:
        print(f"⚠️  Failed to read events from Postgres: {e}")
        events = []
    if not events:
        # No DB (or an empty events table): serve the in-memory ring so the
        # dashboard isn't blank on a fresh/DB-less deploy.
        with _event_lock:
            events = list(_event_log)
    return jsonify(events)


@app.route("/api/events/stream", methods=["GET"])
def stream_events():
    """Server-Sent Events feed of new events as they happen."""
    q = _queue_module.Queue()
    with _event_stream_lock:
        _event_stream_queues.append(q)

    def gen():
        try:
            while True:
                event = q.get()
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            with _event_stream_lock:
                if q in _event_stream_queues:
                    _event_stream_queues.remove(q)

    return Response(gen(), mimetype="text/event-stream",
                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/registry.json", methods=["GET"])
def download_registry():
    """Serve the registry as a downloadable JSON file, scoped to the caller."""
    with lock:
        data = json.dumps({
            "services": clearance.project(registry["services"]),
            "nodes":    clearance.project(registry["nodes"]),
            "updated":  registry["updated"],
        }, indent=2)
    return Response(data, mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=registry.json"})


@app.route("/3d-mesh", methods=["GET"])
def mesh_3d():
    """Serve the 3D mesh visualization."""
    return render_template("mesh.html")


# ── Traccar proxy ─────────────────────────────────────────────────────
# Traccar runs on unit9 behind Caddy at traccar.theofficialblacksheepco.online.
# DNS delegation for the .online zone completed (verified 2026-08-07 — the
# zone's own nameservers answer authoritatively now), so plain hostname
# resolution works and the old IP-pinning shim is gone. Caddy still serves
# this vhost with `tls internal` (self-signed), so verify=False stays until
# that's switched to a real ACME cert — a separate, unrelated fix.
TRACCAR_HOST = os.environ.get("TRACCAR_HOST", "traccar.theofficialblacksheepco.online")
TRACCAR_USER = os.environ.get("TRACCAR_USER", "admin@theofficialblacksheepco.com")
TRACCAR_PASS = os.environ.get("TRACCAR_PASS", "")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # self-signed cert, see note above


def _traccar_request(method, path, **kwargs):
    """Call a Traccar path (REST API or the /osmand/ position endpoint)."""
    return requests.request(
        method, f"https://{TRACCAR_HOST}{path}",
        verify=False, timeout=5, **kwargs,
    )


def _traccar_get(path):
    return _traccar_request("GET", path, auth=(TRACCAR_USER, TRACCAR_PASS))


@app.route("/api/traccar-devices", methods=["GET"])
def traccar_devices():
    """Devices + their latest position, merged, for the 3D mesh's device layer."""
    if not TRACCAR_PASS:
        return jsonify({"error": "TRACCAR_PASS is not set on the locator — the Traccar API needs a login",
                        "devices": []}), 200
    try:
        dev_res = _traccar_get("/api/devices")
        if dev_res.status_code != 200:
            return jsonify({"error": f"traccar /api/devices -> HTTP {dev_res.status_code} "
                                     "(bad login or user lacks device read)",
                            "devices": []}), 200
        devices = dev_res.json()
        pos_res = _traccar_get("/api/positions")
        positions = ({p["deviceId"]: p for p in pos_res.json()}
                     if pos_res.status_code == 200 else {})
    except Exception as e:
        return jsonify({"error": str(e), "devices": []}), 200

    result = []
    for d in devices:
        p = positions.get(d["id"])
        result.append({
            "id": d["id"],
            "name": d.get("name", f"device-{d['id']}"),
            "status": d.get("status", "unknown"),
            "lastUpdate": d.get("lastUpdate"),
            "position": ({
                "lat": p["latitude"], "lon": p["longitude"],
                "speed": p.get("speed"), "course": p.get("course"),
                "fixTime": p.get("fixTime"),
            } if p else None),
        })
    return jsonify({"devices": result})


# ── Traccar feeder ────────────────────────────────────────────────────
# Lokey phones already heartbeat GPS fixes into this registry (DeviceStats.kt
# includes latitude/longitude in the heartbeat metadata whenever location
# permission is granted). Rather than have every phone speak Traccar's
# protocol directly, this background loop is the single bridge: every 60s it
# reads fresh device GPS out of the registry and forwards it into Traccar via
# the OsmAnd HTTP protocol (port 5055, proxied at /osmand/ — see Caddy note
# above), so Traccar's own device list / map / history builds up from data
# Lokey was already sending anyway.
TRACCAR_FIX_MAX_AGE_S = int(os.environ.get("TRACCAR_FIX_MAX_AGE_S", 600))  # ignore stale fixes
_traccar_known_device_ids = set()  # uniqueIds already registered in Traccar this process

# ── IP-based location fallback ──────────────────────────────────────────
# For nodes with no GPS fix (no location permission, indoor/no-signal, or
# non-mobile nodes like servers) we place them approximately from their
# public IP instead of dropping them from the map entirely. Free, no-key
# lookup service (ipwho.is) — city-level accuracy, good enough for a rough
# pin. Results are cached hard since an IP's location practically never
# changes and this must stay well under the service's rate limit.
IP_GEO_CACHE_TTL_S = 24 * 3600
IP_GEO_ACCURACY_M = 50000  # flags these as coarse/IP-derived vs a real GPS fix
_ip_geo_cache = {}  # ip -> (lat, lon, cached_at_s) or (None, None, cached_at_s) for a failed lookup
_ip_geo_fed_at = {}  # node_id -> last time we pushed an IP-derived fix (throttled separately from GPS)
IP_GEO_FEED_INTERVAL_S = 3600  # don't re-push the same rough IP fix every minute


def _geolocate_ip(ip):
    """(lat, lon) for a public IP, or None if it's private/unroutable/unresolvable."""
    if not ip:
        return None
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None

    cached = _ip_geo_cache.get(ip)
    if cached and (time.time() - cached[2]) < IP_GEO_CACHE_TTL_S:
        return (cached[0], cached[1]) if cached[0] is not None else None

    lat, lon = None, None
    try:
        res = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        data = res.json()
        if data.get("success", True) and data.get("latitude") is not None:
            lat, lon = data["latitude"], data["longitude"]
    except Exception as e:
        print(f"_geolocate_ip: lookup failed for {ip}: {e}")

    _ip_geo_cache[ip] = (lat, lon, time.time())
    return (lat, lon) if lat is not None else None


def _traccar_ensure_device(unique_id, name):
    if unique_id in _traccar_known_device_ids:
        return
    try:
        existing = _traccar_get("/api/devices").json()
        if any(d.get("uniqueId") == unique_id for d in existing):
            _traccar_known_device_ids.add(unique_id)
            return
        res = _traccar_request(
            "POST", "/api/devices",
            auth=(TRACCAR_USER, TRACCAR_PASS),
            json={"name": name, "uniqueId": unique_id},
        )
        if res.status_code in (200, 201):
            _traccar_known_device_ids.add(unique_id)
        else:
            print(f"traccar_feeder: device create failed for {unique_id}: {res.status_code} {res.text}")
    except Exception as e:
        print(f"traccar_feeder: device create error for {unique_id}: {e}")


def traccar_feeder():
    while True:
        try:
            with lock:
                candidates = [
                    (node_id, dict(node.get("metadata") or {}), node.get("public_ip", ""))
                    for node_id, node in registry["nodes"].items()
                ]

            now_ms = time.time() * 1000
            now_s = time.time()
            for node_id, meta, public_ip in candidates:
                lat, lon = meta.get("latitude"), meta.get("longitude")
                fix_time_ms = meta.get("location_time_ms")
                is_gps_fix = lat is not None and lon is not None and not (
                    fix_time_ms and (now_ms - fix_time_ms) > TRACCAR_FIX_MAX_AGE_S * 1000
                )
                accuracy_m = meta.get("location_accuracy_m")

                if not is_gps_fix:
                    # No usable GPS — fall back to placing it from its IP, but only
                    # once an hour per node so we're not hammering Traccar (or the
                    # geolocation service) with an identical position every minute.
                    last_fed = _ip_geo_fed_at.get(node_id, 0)
                    if now_s - last_fed < IP_GEO_FEED_INTERVAL_S:
                        continue
                    located = _geolocate_ip(public_ip)
                    if located is None:
                        continue
                    lat, lon = located
                    accuracy_m = IP_GEO_ACCURACY_M
                    _ip_geo_fed_at[node_id] = now_s

                unique_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(node_id))
                _traccar_ensure_device(unique_id, node_id)

                params = {
                    "id": unique_id,
                    "lat": lat,
                    "lon": lon,
                    "timestamp": int((fix_time_ms or now_ms) / 1000),
                }
                if accuracy_m is not None:
                    params["accuracy"] = accuracy_m
                try:
                    _traccar_request("GET", "/osmand/", params=params)
                except Exception as e:
                    print(f"traccar_feeder: position push failed for {unique_id}: {e}")
        except Exception as e:
            print(f"traccar_feeder error: {e}")
        time.sleep(60)


@app.route("/silent-check-sso.html", methods=["GET"])
def silent_check_sso():
    return render_template("silent-check-sso.html")


@app.route("/trigger-browse", methods=["POST"])
def trigger_browse():
    """Opens file browser and returns the selected path."""
    import tkinter as tk
    from tkinter import filedialog
    
    # 1. Secure the Bag (Git Backup)
    secure_the_bag("Pre-deployment browse/backup")

    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        selected_path = filedialog.askdirectory(title="Select Docker Project Folder")
        root.destroy()
        return jsonify({"folder_path": selected_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/networks", methods=["GET"])
def get_available_networks():
    """Returns a unique list of networks from registry metadata AND live Docker networks."""
    networks = set()
    
    # 1. Pull from Registry Metadata
    with lock:
        for svc in registry["services"].values():
            if "metadata" in svc and "networks" in svc["metadata"]:
                net_str = svc["metadata"]["networks"]
                if net_str and net_str != "nan":
                    for n in re.split(r'[,/|\s]+', net_str):
                        if n.strip(): networks.add(n.strip())
        
        for node in registry["nodes"].values():
            if "metadata" in node and "networks" in node["metadata"]:
                net_str = node["metadata"]["networks"]
                if net_str and net_str != "nan":
                    for n in re.split(r'[,/|\s]+', net_str):
                        if n.strip(): networks.add(n.strip())
    
    # 2. Pull Live Docker Networks
    if docker_client:
        try:
            for net in docker_client.networks.list():
                networks.add(net.name)
        except Exception as e:
            print(f"⚠️ Could not fetch Docker networks: {e}")

    # Add defaults if still empty
    if not networks: networks = {"bridge", "host", "none"}
    
    return jsonify(sorted(list(networks)))


@app.route("/trigger-deploy-final", methods=["POST"])
def trigger_deploy_final():
    """Superseded by /api/deploy/<name>; the dashboard no longer calls this.

    It cannot work from inside the container and never could: deploy.py runs
    `docker-compose up -d` locally with cwd=<host folder path>, but this
    container mounts no host filesystem and ships with neither the `docker`
    nor the `docker-compose` binary. It also scored a target node and then
    ignored it, deploying locally regardless of the unit picked in the UI.

    Kept only so any out-of-band caller gets its old response shape rather
    than a 404. New work belongs in deploy_compose().
    """
    from deploy import deploy_from_browse
    data = request.get_json()
    
    path = data.get("folder_path")
    networks = data.get("networks", [])
    servers = data.get("servers", [])
    
    if not path:
        return jsonify({"error": "No path provided"}), 400

    # Pass the user preferences to the deployment logic
    result = deploy_from_browse(path, target_servers=servers, join_networks=networks)
    return jsonify(result)


# ── METRICS & MIGRATION ENDPOINTS ───────────────────────────────────────────

@app.route("/nodes/<node_id>/metrics", methods=["PATCH"])
def update_node_metrics(node_id):
    """
    Agent-side push: merge live CPU/memory readings into an existing node entry
    without overwriting the rest of the node config.

    Expected JSON:
    { "cpu_percent": 45.2, "mem_percent": 67.1, "disk_percent": 93.0 }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data"}), 400

    now = datetime.now(timezone.utc).isoformat()
    with lock:
        node = registry["nodes"].get(node_id)
        if node is None:
            registry["nodes"][node_id] = {"status": "ONLINE", "last_seen": now}
            node = registry["nodes"][node_id]
        node["cpu_percent"]   = data.get("cpu_percent")
        node["mem_percent"]   = data.get("mem_percent")
        node["disk_percent"]  = data.get("disk_percent")
        node["disk_total_gb"] = data.get("disk_total_gb")
        node["disk_used_gb"]  = data.get("disk_used_gb")
        # Absolute capacity figures. Older lokeys omit these, so each is stored
        # only when present rather than overwriting a known value with None.
        for field in ("mem_total_mb", "mem_available_mb", "mem_total_gb",
                      "mem_used_gb", "disk_free_gb", "mounts"):
            if data.get(field) is not None:
                node[field] = data[field]
        # Addresses are stored only when present so a heartbeat that could not
        # determine one does not erase a good value already on record.
        # private_ip is accepted here too: _node_probe_addr() falls back to it,
        # and lokey now reports a freshly-resolved local address every heartbeat
        # (it previously sent none at all, which is why unit3's node record had
        # no address and could not be probed).
        for _addr_field in ("ip", "private_ip", "tailscale_ip", "openvpn_ip"):
            if data.get(_addr_field):
                node[_addr_field] = data[_addr_field]
        node["last_seen"]     = now
        node["status"]        = "ONLINE"
        registry["updated"]   = now

    return jsonify({"result": "metrics_updated", "node": node_id})


@app.route("/api/migrations/pending", methods=["GET"])
def get_pending_migrations():
    """
    Agents poll this to pick up migrations assigned to their unit.
    Returns only PENDING tasks for the requesting unit.
    """
    unit = request.args.get("unit")
    with migration_lock:
        # "unit" on a task = which node must execute it (pull tasks run on the
        # TARGET node); legacy tasks without it are executed by the source node.
        pending = [
            m for m in migration_queue.values()
            if m["status"] == "PENDING"
            and (not unit or m.get("unit", m.get("from_node")) == unit)
        ]
    return jsonify(pending)


@app.route("/api/migrations/<mig_id>/claim", methods=["POST"])
def claim_migration(mig_id):
    """
    Agent claims a migration to prevent double execution.
    Returns 409 if already claimed or not PENDING.

    Expected JSON: { "unit": "unit2" }
    """
    data = request.get_json(silent=True) or {}
    unit = data.get("unit", "unknown")

    with migration_lock:
        mig = migration_queue.get(mig_id)
        if not mig:
            return jsonify({"error": "not found"}), 404
        if mig["status"] != "PENDING":
            return jsonify({"error": "already claimed", "status": mig["status"]}), 409
        owner = mig.get("unit", mig.get("from_node"))
        if unit != "unknown" and owner and owner != unit:
            return jsonify({"error": "not yours", "owner": owner}), 403
        mig["status"]     = "IN_PROGRESS"
        mig["claimed_by"] = unit
        mig["claimed_at"] = datetime.now(timezone.utc).isoformat()
        print(f"🔒 MIGRATION {mig_id}: claimed by {unit}")

    return jsonify({"result": "claimed", "id": mig_id})


# A migration that "succeeded" is not finished — the agent only reports that its
# commands ran, not that the service came up. agent-0 unit8→unit7 stopped on the
# source, reported DONE, and started nowhere. These drive the verify pass that
# turns that silent outage into a loud failure plus a rollback.
MIGRATION_VERIFY_TIMEOUT  = int(os.environ.get("MIGRATION_VERIFY_TIMEOUT", 300))
MIGRATION_VERIFY_INTERVAL = int(os.environ.get("MIGRATION_VERIFY_INTERVAL", 15))
MIGRATION_START_TYPES     = ("git_pull_and_start", "native_prereq_and_start")


def _service_online_at(container, unit):
    """True when the registry shows `container` ONLINE on `unit`."""
    target = (container or "").split("@")[0].lower()
    with lock:
        for svc in registry.get("services", {}).values():
            if ((svc.get("name") or "").split("@")[0].lower() == target
                    and svc.get("host") == unit
                    and svc.get("status") == "ONLINE"):
                return True
    return False


def _verify_migration(mig_id):
    """Confirm the service actually came up on the target; roll back if not.

    Runs in its own thread after a start-type migration reports success. The
    registry only refreshes on the agent's tick, so the timeout has to outlast
    one — hence 300s by default rather than something snappier.

    On failure the source is told to start the container again. That half is the
    whole point: the source was stopped before the target was tried, so without
    it a failed migration leaves the service running on no node at all.
    """
    with migration_lock:
        mig = migration_queue.get(mig_id)
        if not mig:
            return
        container = mig.get("container", "")
        to_node   = mig.get("to_node", "")
        from_node = mig.get("from_node", "")

    deadline = time.time() + MIGRATION_VERIFY_TIMEOUT
    while time.time() < deadline:
        time.sleep(MIGRATION_VERIFY_INTERVAL)
        if _service_online_at(container, to_node):
            with migration_lock:
                mig = migration_queue.get(mig_id)
                if mig:
                    mig["status"]       = "DONE"
                    mig["verified"]     = True
                    mig["completed_at"] = datetime.now(timezone.utc).isoformat()
            print(f"✅ MIGRATION {mig_id}: verified '{container}' ONLINE on {to_node}")
            return

    reason = (f"'{container}' did not come up on {to_node} within "
              f"{MIGRATION_VERIFY_TIMEOUT}s")
    with migration_lock:
        mig = migration_queue.get(mig_id)
        if mig:
            mig["status"]       = "FAILED"
            mig["verified"]     = False
            mig["error"]        = reason
            mig["completed_at"] = datetime.now(timezone.utc).isoformat()
    print(f"❌ MIGRATION {mig_id}: {reason}")

    if from_node and from_node != to_node:
        _queue_command(from_node, container, "start", source="migration-rollback")
        print(f"↩️  ROLLBACK: queued start of '{container}' back on {from_node}")
    emit_event("migration", from_container=from_node, to_container=to_node,
               unit=to_node, container=container, success=False)


@app.route("/api/migrations/complete", methods=["POST"])
def complete_migration():
    """
    Agent calls this when a migration finishes (success or failure).

    Expected JSON:
    { "id": "<migration_id>", "success": true }
    """
    data = request.get_json(silent=True) or {}
    mig_id  = data.get("id")
    success = data.get("success", True)

    verify_after = False
    with migration_lock:
        if mig_id in migration_queue:
            mig = migration_queue[mig_id]

            # A start-type migration reporting success only means its commands
            # ran. Hold it at VERIFYING until the registry actually shows the
            # service up on the target — marking DONE here is what let a
            # target-side failure read as a completed move.
            if success and mig.get("type") in MIGRATION_START_TYPES:
                mig["status"]      = "VERIFYING"
                mig["verifying_at"] = datetime.now(timezone.utc).isoformat()
                verify_after = True
                print(f"🔎 MIGRATION {mig_id}: agent reported success — verifying "
                      f"'{mig.get('container')}' on {mig.get('to_node')}")
            else:
                mig["status"]       = "DONE" if success else "FAILED"
                mig["completed_at"] = datetime.now(timezone.utc).isoformat()
                print(f"{'✅' if success else '❌'} MIGRATION {mig_id}: {'DONE' if success else 'FAILED'}")
            # Deferred while VERIFYING — _verify_migration emits the failure
            # event itself, and a success event here would announce an outcome
            # nothing has checked yet.
            if not verify_after:
                emit_event("migration", from_container=mig.get("from_node", ""),
                           to_container=mig.get("to_node", ""), unit=mig.get("to_node", ""),
                           container=mig.get("container", ""), success=success)

            # When a git_push_and_stop finishes, queue the follow-on pull on the target.
            # dedup     → git_pull_only      (container already running on target, just sync state)
            # rebalance → git_pull_and_start (container needs to be started on target)
            if success and mig.get("type") == "git_push_and_stop":
                pull_type = "git_pull_only" if mig.get("dedup") else "git_pull_and_start"
                pull_id   = uuid.uuid4().hex[:8] + "-pull"
                migration_queue[pull_id] = {
                    "id":          pull_id,
                    "type":        pull_type,
                    "unit":        mig.get("to_node", ""),
                    "container":   mig.get("container", ""),
                    "from_node":   mig.get("from_node", ""),
                    "to_node":     mig.get("to_node", ""),
                    "project_dir": data.get("project_dir", ""),
                    "git_remote":  data.get("git_remote", ""),
                    "status":      "PENDING",
                    "queued_at":   datetime.now(timezone.utc).isoformat(),
                    "reason":      f"follow-on {pull_type} after {mig_id}",
                }
                print(f"🔁 AUTO-QUEUED {pull_type} {pull_id} → {mig.get('to_node')}")

            # Native equivalent: once the source has stopped the unit and pushed
            # its files, queue the target-side prereq-check + start.
            if success and mig.get("type") == "native_stop_and_sync":
                start_id = uuid.uuid4().hex[:8] + "-start"
                migration_queue[start_id] = {
                    "id":           start_id,
                    "type":         "native_prereq_and_start",
                    "unit":         mig.get("to_node", ""),
                    "container":    mig.get("container", ""),
                    "from_node":    mig.get("from_node", ""),
                    "to_node":      mig.get("to_node", ""),
                    "sync_path":    data.get("sync_path", mig.get("sync_path", "")),
                    "systemd_unit": data.get("systemd_unit", mig.get("systemd_unit", "")),
                    "prereqs":      mig.get("prereqs", {}),
                    "status":       "PENDING",
                    "queued_at":    datetime.now(timezone.utc).isoformat(),
                    "reason":       f"follow-on native_prereq_and_start after {mig_id}",
                }
                print(f"🔁 AUTO-QUEUED native_prereq_and_start {start_id} → {mig.get('to_node')}")

    # Outside the lock: the verifier polls for minutes and takes the same lock.
    if verify_after:
        threading.Thread(target=_verify_migration, args=(mig_id,),
                         daemon=True, name=f"verify-{mig_id}").start()

    return jsonify({"result": "acknowledged",
                    "verifying": verify_after})



@app.route("/api/migrations", methods=["GET"])
def list_migrations():
    """Return all migrations (pending, in_progress, and completed) for dashboard visibility."""
    with migration_lock:
        return jsonify(list(migration_queue.values()))


@app.route("/api/migrations", methods=["POST"])
def create_migration():
    """
    Manually enqueue a migration — the CLI/dashboard path for triggering one on
    demand, as opposed to load_balancer()'s automatic threshold-based queueing
    (both write into the same migration_queue, same dict shape, so claim/complete/
    history all work unmodified either way).

    Expected JSON:
    { "service": "name@host", "to_node": "unit4", "force": false }

    "service" is a service_id as shown by GET /services (locatorctl.py's `list`).
    Rejects with 409 + the missing dependency list unless depends_on is satisfied
    (see resolve_migration_order()) or force=true is passed.
    """
    data = request.get_json(silent=True) or {}
    svc_id  = data.get("service")
    to_node = data.get("to_node")
    force   = bool(data.get("force", False))

    if not svc_id or not to_node:
        return jsonify({"error": "requires 'service' and 'to_node'"}), 400

    with lock:
        svc = registry["services"].get(svc_id)
        if not svc:
            return jsonify({"error": f"unknown service '{svc_id}'"}), 404
        # _is_pinned(), not `in _PINNED_NAMES`: set membership only catches
        # exact names, so "mariadb" was protected while "mariadb-11.4" was
        # freely migratable by hand, and locator.yml's location_type:stationary
        # was ignored entirely on this path. The balancer already uses
        # _is_pinned(); this makes the manual path agree with it.
        if _is_pinned(svc.get("name")):
            return jsonify({"error": f"'{svc['name']}' is pinned — never auto/manually migrated"}), 400

        deps, missing = resolve_migration_order(svc_id, registry["services"])
        if missing and not force:
            return jsonify({"error": "unmet dependencies", "missing": missing}), 409

        tgt_info = registry["nodes"].get(to_node)
        if not tgt_info or tgt_info.get("status") != "ONLINE":
            return jsonify({"error": f"target node '{to_node}' is not ONLINE"}), 400
        tgt_ip = _best_ip(tgt_info)
        if not tgt_ip:
            return jsonify({"error": f"target node '{to_node}' has no reachable IP"}), 400

        src_info = registry["nodes"].get(svc.get("host"), {})
        src_ip   = _best_ip(src_info) or ""

        mig_type = "git_push_and_stop" if svc.get("type") == "container" else "native_stop_and_sync"
        mig_id = str(uuid.uuid4())[:8]
        now_iso = datetime.now(timezone.utc).isoformat()
        migration_entry = {
            "id":         mig_id,
            "container":  svc.get("name"),
            "from_node":  svc.get("host"),
            "from_ip":    src_ip,
            "to_node":    to_node,
            "to_ip":      tgt_ip,
            "unit":       svc.get("host"),   # push step runs on the source
            "status":     "PENDING",
            "queued_at":  now_iso,
            "reason":     "manual",
            "type":       mig_type,
            "sync_path":  svc.get("metadata", {}).get("sync_path", ""),
            "systemd_unit": svc.get("metadata", {}).get("systemd_unit", svc.get("name")),
            "prereqs":    svc.get("prereqs", {}),
        }
        with migration_lock:
            migration_queue[mig_id] = migration_entry

    print(f"📦 MANUAL MIGRATION: queued {mig_id} — move '{svc.get('name')}' {svc.get('host')} → {to_node} ({mig_type})")
    return jsonify({"result": "queued", "id": mig_id, "type": mig_type}), 200


@app.route("/api/dns/status", methods=["GET"])
def dns_status():
    """
    Report each configured zone's content as seen directly on ns1 (unit9),
    via `pdnsutil list-zone` over SSH — the box that actually runs PowerDNS.
    Locator runs on Fly, not on the DNS box, so this always goes over the
    network using the SSH_KEY/SSH_USER deploy credential (see DNS_SSH_HOST).
    """
    results = {}
    for zone in DNS_ZONES:
        ok, out = _ssh_exec(DNS_SSH_HOST, DNS_SSH_USER, f"pdnsutil list-zone {zone}")
        results[zone] = {"ok": ok, "content": out if ok else None, "error": None if ok else out}
    return jsonify({"ns1_host": DNS_SSH_HOST, "zones": results})


@app.route("/api/dns/sync", methods=["POST"])
def dns_sync():
    """
    Force ns1 (unit9) to send a DNS NOTIFY for a zone to its configured
    secondaries via `pdns_control notify` — the direct fix for `also-notify=`
    being empty in unit9's PowerDNS config today, which means nothing
    proactively pushes zone changes out right now.

    Expected JSON: { "zone": "theofficialblacksheepco.com" }

    NOTE: this can only confirm the NOTIFY was sent from ns1's side. Whether
    ns2 (unit8) is even configured as a proper AXFR secondary is unconfirmed —
    SSH to unit8 isn't currently available to verify or fix independently, so
    this endpoint deliberately does not claim ns2 actually received/applied it.
    """
    data = request.get_json(silent=True) or {}
    zone = data.get("zone")
    if not zone:
        return jsonify({"error": "requires 'zone'"}), 400
    if zone not in DNS_ZONES:
        return jsonify({"error": f"'{zone}' is not in the configured DNS_ZONES list", "known_zones": DNS_ZONES}), 400

    ok, out = _ssh_exec(DNS_SSH_HOST, DNS_SSH_USER, f"pdns_control notify {zone}")
    emit_event("dns", a_record=zone, pdns_server=DNS_SSH_HOST, ok=ok)
    return jsonify({
        "zone": zone,
        "notified_from": DNS_SSH_HOST,
        "ok": ok,
        "output": out,
        "note": "confirms NOTIFY was sent from ns1 only — ns2 receipt/AXFR success is not independently verifiable (unit8 SSH access unavailable)",
    }), (200 if ok else 502)


@app.route("/api/balance/status", methods=["GET"])
def balance_status():
    """Current load-balancer state: node loads + recent migration history."""
    with lock:
        node_loads = {
            nid: {
                "cpu_percent":  info.get("cpu_percent"),
                "mem_percent":  info.get("mem_percent"),
                "disk_percent": info.get("disk_percent"),
                "disk_used_gb": info.get("disk_used_gb"),
                "disk_total_gb":info.get("disk_total_gb"),
                "status":       info.get("status"),
            }
            for nid, info in registry["nodes"].items()
        }
    with migration_lock:
        recent = sorted(migration_queue.values(), key=lambda m: m["queued_at"], reverse=True)[:20]
    with prestage_lock:
        prestage = dict(prestage_state)

    return jsonify({
        "enabled":          BALANCE_ENABLED,
        "high_threshold":   BALANCE_HIGH,
        "low_threshold":    BALANCE_LOW,
        "diff_threshold":   BALANCE_DIFF,
        "interval_seconds": BALANCE_INTERVAL,
        "cooldown_seconds": BALANCE_COOLDOWN,
        "node_loads":       node_loads,
        "recent_migrations": recent,
        "prestage_enabled":   BALANCE_PRESTAGE_ENABLED,
        "prestage_threshold": BALANCE_HIGH - BALANCE_PRESTAGE_MARGIN,
        "prestage":           prestage,
    })


@app.route("/api/idle/policy", methods=["GET"])
def idle_policy():
    """Which containers a unit is ALLOWED to idle-stop, straight from locator.yml.

    lokey calls this each tick instead of reading the locator.idle.stop label.
    The label still works and is unioned in on the agent side, but this is the
    path that makes the policy file authoritative.

    Two floors, both deliberate:
      * opt-in only — a service is returned solely because it carries
        idle_stop: true, so an undeclared service is never eligible;
      * deployment_type: essential is refused even when idle_stop is set, so
        the two keys cannot contradict each other into stopping a critical
        service.
    """
    unit = (request.args.get("unit") or "").strip().lower()
    if unit and not unit.startswith("unit"):
        unit = "unit" + unit
    out = {}
    for name, cfg in load_policy().items():
        if not cfg.get("idle_stop"):
            continue
        if is_essential(cfg):
            continue
        spec = cfg.get("units") or ""
        if unit and spec not in ("", "all", "current_unit"):
            if unit not in _expand_unit_spec(spec, []):
                continue
        out[name] = {"timeout": cfg.get("idle_timeout") or ""}
    return jsonify({
        "unit": unit,
        "containers": out,
        "default_timeout": IDLE_DEFAULT_TIMEOUT,
    })


@app.route("/api/idle/status", methods=["GET"])
def idle_status():
    """Idle auto-shutdown state: watched containers, idle time, and time remaining."""
    now = datetime.now(timezone.utc)
    with _idle_lock:
        watched = {
            f"{unit}/{name}": {
                "unit":              unit,
                "container":         name,
                "idle_seconds":      int((now - st["last_active"]).total_seconds()),
                "timeout_seconds":   st["timeout"],
                "remaining_seconds": max(0, int(st["timeout"] - (now - st["last_active"]).total_seconds())),
                "last_report":       st["last_report"].isoformat(),
                "stopped_count":     st["stopped_count"],
            }
            for (unit, name), st in _idle_state.items()
        }
    with command_lock:
        recent = sorted(command_queue.values(), key=lambda c: c["queued_at"], reverse=True)[:20]
    return jsonify({
        "enabled":           IDLE_ENABLED,
        "check_interval":    IDLE_CHECK_INTERVAL,
        "default_timeout":   IDLE_DEFAULT_TIMEOUT,
        "traffic_threshold": IDLE_TRAFFIC_THRESHOLD,
        "watched":           watched,
        "recent_commands":   recent,
    })


# ── PERSISTENCE ─────────────────────────────────────────────────────────────

def secure_the_bag(commit_message="Auto-commit: Securing data before container ops"):
    """Stages, commits, and pushes all changes so nothing gets lost."""
    try:
        from git import Repo
        repo_path = os.path.dirname(os.path.abspath(__file__))
        print(f"Checking the repo status at {repo_path}...")
        repo = Repo(repo_path)
        
        if repo.is_dirty(untracked_files=True):
            print("Changes detected. Staging the files...")
            repo.git.add(A=True)
            print(f"Committing: {commit_message}")
            repo.index.commit(commit_message)
            
            try:
                print("Pushing to remote repository...")
                origin = repo.remote(name='origin')
                origin.push()
                print("Push complete!")
            except Exception as push_error:
                print(f"Push failed (data committed locally): {push_error}")
        else:
            print("Repo is clean. No new changes to push.")
            
    except Exception as e:
        print(f"⚠️ Git backup skipped/failed: {e}")


def persist_registry():
    """Write the current registry to disk for file-based consumers, and
    snapshot it into Postgres (unit3) if DATABASE_URL is configured."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        filepath = os.path.join(DATA_DIR, "registry.json")
        with lock:
            snapshot = json.dumps(registry, indent=2)
            registry_copy = {"nodes": dict(registry["nodes"]), "services": dict(registry["services"]),
                              "updated": registry["updated"]}
        with open(filepath, "w") as f:
            f.write(snapshot)
    except Exception as e:
        print(f"⚠️  Failed to persist registry: {e}")
        return

    try:
        db.save_registry_snapshot(registry_copy)
    except Exception as e:
        print(f"⚠️  Failed to persist registry to Postgres: {e}")


def load_seed():
    """Load the seed registry from Excel on startup as a baseline."""
    if os.path.exists(EXCEL_FILE):
        try:
            df = pd.read_excel(EXCEL_FILE)
            now = datetime.now(timezone.utc).isoformat()
            
            category = "devices"
            for _, row in df.iterrows():
                gov = str(row.get('government', '')).strip().lower()
                if not gov or gov == 'nan':
                    continue
                
                # Check for category markers
                if 'docker containers' in gov:
                    category = "docker containers"
                    continue
                elif 'website' in gov:
                    category = "websites"
                    continue
                
                name = str(row.get('government', 'Unknown'))
                
                # Extract hosts from 'Server #' column (can be multiple like "Unit 1/2/4")
                server_val = str(row.get('Server #', '')).strip()
                private_val = str(row.get('private', ''))
                openvpn_val = str(row.get('openvpn', ''))
                detected_hosts = []
                
                # Check 'Server #' column for multiple units
                if server_val and server_val.lower() != 'nan':
                    # Handle "Unit 1/2/4" or "Unit 1, 2, 4" or just "1, 2"
                    parts = re.split(r'[/,\s]+', server_val.lower())
                    for p in parts:
                        p = p.strip()
                        if not p: continue
                        if p.startswith('unit'):
                            # Handle "unit1" or just "unit"
                            m = re.search(r'\d+', p)
                            if m: detected_hosts.append(f"unit{m.group(0)}")
                        elif p.isdigit():
                            detected_hosts.append(f"unit{p}")
                
                # Check network columns if still empty
                if not detected_hosts:
                    for val in [private_val, openvpn_val]:
                        match = re.search(r'\(unit(\d+)\)', val.lower())
                        if match:
                            detected_hosts = [f"unit{match.group(1)}"]
                            break
                        match = re.search(r'unit(\d+)', val.lower())
                        if match:
                            detected_hosts = [f"unit{match.group(1)}"]
                            break
                
                # Was hardcoded to unit1, from when it was the primary node. Any
                # seed row whose host could not be parsed was therefore filed
                # under unit1 — which is how ~140 of unit8's containers ended up
                # attributed to a node that no longer exists.
                if not detected_hosts and category == "docker containers":
                    detected_hosts = ["unknown"]

                item_data = {
                    "name": name,
                    "category": category,
                    "url": str(row.get('publib ip', '')) if pd.notna(row.get('publib ip')) else "",
                    "internal": private_val if pd.notna(row.get('private')) else "",
                    "openvpn": openvpn_val if pd.notna(row.get('openvpn')) else "",
                    "hosts": detected_hosts if detected_hosts else ([name] if category == "devices" else ["unknown"]),
                    "status": "OFFLINE",
                    "last_heartbeat": "",
                    "registered_at": now,
                    "metadata": {
                        "ram": str(row.get('ram', '')),
                        "os": str(row.get('OS', '')),
                        "networks": str(row.get('networks', '')),
                        "server_info": server_val,
                        "mac": str(row.get('mac address', '')),
                        "is_openvpn": bool(openvpn_val and openvpn_val.lower() != 'nan')
                    }
                }

                if category == "devices":
                    # ONLY add if it's a "Unit X" style or we specifically want it as a node
                    node_id = None
                    if detected_hosts: node_id = detected_hosts[0]
                    elif name.lower().startswith('unit'): node_id = name.lower().replace(' ', '')
                    
                    if node_id:
                        registry["nodes"][node_id] = {
                            "name": name,
                            "ip": item_data["internal"] or item_data["openvpn"],
                            "openvpn_ip": item_data["openvpn"],
                            "type": item_data["metadata"]["os"],
                            "status": "OFFLINE",
                            "last_seen": "",
                            "is_openvpn_only": node_id in ['unit2', 'unit4'],
                            "metadata": item_data["metadata"]
                        }
                else:
                    # Multi-instance handling: create unique ID for each host instance
                    base_name = name.lower().replace(" ", "_").replace("/", "_")
                    for h in detected_hosts:
                        instance_id = f"{base_name}_{h}"
                        inst_data = item_data.copy()
                        inst_data["hosts"] = [h] # Each instance linked to exactly one host for mesh clarity
                        registry["services"][instance_id] = inst_data

            registry["updated"] = now
            print(f"🌱 Loaded Excel registry: {len(registry['services'])} services, {len(registry['nodes'])} nodes")
        except Exception as e:
            print(f"⚠️ Failed to load Excel seed: {e}")
    elif os.path.exists(SEED_FILE):
        # Fallback to JSON if Excel is missing
        try:
            with open(SEED_FILE, "r") as f:
                seed = json.load(f)
            # ... existing JSON load logic ...
            now = datetime.now(timezone.utc).isoformat()
            for name, svc in seed.get("services", {}).items():
                svc["name"] = svc.get("name", name)
                svc["status"] = svc.get("status", "PENDING")
                svc["last_heartbeat"] = ""
                svc["registered_at"] = now
                svc.setdefault("category", _infer_category(svc.get("type", "container"), svc.get("url", "")))
                registry["services"][name] = svc
            for node_name, node_info in seed.get("nodes", {}).items():
                registry["nodes"][node_name] = node_info
            registry["updated"] = now
        except Exception as e:
            print(f"⚠️ Failed to load seed: {e}")

    # Restore persisted registry — Postgres first (if configured and has data),
    # falling back to the registry.json file (it takes priority over seed either way).
    persisted = None
    try:
        persisted = db.load_registry_snapshot()
        if persisted:
            print(f"🗄️  Restored registry from Postgres: {len(persisted.get('services', {}))} services, "
                  f"{len(persisted.get('nodes', {}))} nodes")
    except Exception as e:
        print(f"⚠️  Failed to restore registry from Postgres: {e}")

    if not persisted:
        persisted_path = os.path.join(DATA_DIR, "registry.json")
        if os.path.exists(persisted_path):
            try:
                with open(persisted_path, "r") as f:
                    persisted = json.load(f)
                print(f"💾 Restored persisted registry from file: {len(persisted.get('services', {}))} services")
            except Exception as e:
                print(f"⚠️  Failed to restore persisted registry: {e}")

    if persisted:
        for name, svc in persisted.get("services", {}).items():
            registry["services"][name] = svc
        for node_name, node_info in persisted.get("nodes", {}).items():
            registry["nodes"][node_name] = node_info
        registry["updated"] = persisted.get("updated", registry["updated"])

    purge_fabricated_core_services()


def purge_fabricated_core_services():
    """
    One-time cleanup: removes service entries previously fabricated by the old
    ensure_core_services() function, which unconditionally stamped apache/bind/
    traefik/lokey-client entries onto EVERY node (including phones) regardless
    of whether that node actually ran them — tagged discovered_via=core_enforcement.
    Real detection already exists and is trustworthy without this: lokey-native's
    register_stats() self-reports actually-running Docker containers by their
    real names (see hard-stats.py), and active_discovery_scanner() genuinely
    probes each node's Traefik API. Nothing needs to replace this function.
    """
    with lock:
        fabricated = [
            key for key, svc in registry["services"].items()
            if (svc.get("metadata") or {}).get("discovered_via") == "core_enforcement"
        ]
        for key in fabricated:
            del registry["services"][key]
        if fabricated:
            registry["updated"] = datetime.now(timezone.utc).isoformat()
    if fabricated:
        print(f"🧹 Purged {len(fabricated)} fabricated core-service entries (core_enforcement)")


# ── HEARTBEAT REAPER ────────────────────────────────────────────────────────

RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", 90))

def heartbeat_reaper():
    """
    Marks services OFFLINE when heartbeat expires.
    Purges ONLY entries that have been OFFLINE for >= RETENTION_DAYS.
    Entries with no heartbeat history (seeded/manual) are never auto-purged
    unless they first went ONLINE and then went OFFLINE.
    """
    while True:
        time.sleep(REAPER_INTERVAL)
        now = datetime.now(timezone.utc)
        changed = False
        to_purge = []
        stale_nodes = []

        with lock:
            for name, svc in list(registry["services"].items()):
                status = svc.get("status")

                if status == "ONLINE" and svc.get("last_heartbeat"):
                    try:
                        # Websites/serverless are refreshed by the URL checker (every
                        # URL_CHECK_INTERVAL), not by agent heartbeats — give them slack.
                        _timeout = max(HEARTBEAT_TIMEOUT, URL_CHECK_INTERVAL * 5) \
                            if svc.get("category") in ("websites", "serverless") else HEARTBEAT_TIMEOUT
                        last = datetime.fromisoformat(svc["last_heartbeat"])
                        if (now - last).total_seconds() > _timeout:
                            svc["status"] = "OFFLINE"
                            # Only start the 90-day clock now — don't overwrite an existing one
                            if not svc.get("offline_since"):
                                svc["offline_since"] = now.isoformat()
                            changed = True
                            print(f"💀 OFFLINE: {name}")
                            # A lokey service going quiet used to mark its NODE
                            # OFFLINE right here. That is the conflation that
                            # made the registry wrong: it reports that the agent
                            # stopped, never that the machine stopped. Node
                            # status now has exactly one owner — the staleness +
                            # reachability probe below — so a silent agent on a
                            # live box resolves to AGENT_DOWN instead of a flat
                            # untrue OFFLINE. The node's own last_seen goes stale
                            # on its own once lokey stops, which is what hands it
                            # to that probe.
                    except (ValueError, TypeError):
                        pass

                elif status == "OFFLINE":
                    offline_since = svc.get("offline_since")
                    # Never purge entries that were seeded/manually added but never heartbeated
                    # (offline_since is only set when a service that WAS online goes offline)
                    if offline_since:
                        try:
                            age_days = (now - datetime.fromisoformat(offline_since)).days
                            if age_days >= RETENTION_DAYS:
                                to_purge.append(name)
                        except (ValueError, TypeError):
                            pass

            for name in to_purge:
                del registry["services"][name]
                changed = True
                print(f"🗑️  PURGED: {name} (offline > {RETENTION_DAYS} days)")

            # Nodes whose own last_seen has expired go OFFLINE directly, independent of
            # whether a matching "lokey"-named service exists — the check above only
            # catches nodes whose heartbeat comes through a service named after lokey;
            # self-registered devices and any node with a stale-but-present last_seen
            # were previously stuck ONLINE forever with no way to expire.
            for node_id, node in registry["nodes"].items():
                status = node.get("status")
                # AGENT_DOWN nodes are re-examined too. A machine that was only
                # silent can genuinely go down later, and it has to become
                # OFFLINE when that happens instead of being pinned at
                # AGENT_DOWN forever.
                if status not in ("ONLINE", NODE_STATUS_AGENT_DOWN, "OFFLINE"):
                    continue
                if not _node_probe_due(node_id, status):
                    continue
                last_seen = node.get("last_seen")
                if not last_seen:
                    # No heartbeat ever recorded. Previously skipped outright,
                    # which is how a node could sit at OFFLINE with nothing ever
                    # re-examining it. Probe it: an address is enough to tell
                    # whether the machine is actually there.
                    if _node_probe_addr(node):
                        stale_nodes.append((node_id, dict(node)))
                    continue
                try:
                    last = datetime.fromisoformat(last_seen)
                except (ValueError, TypeError):
                    continue
                if (now - last).total_seconds() > HEARTBEAT_TIMEOUT:
                    # Only collected here. The probe runs after the lock is
                    # released — _node_reachable blocks on the network for up to
                    # NODE_PROBE_TIMEOUT per port, and holding the registry lock
                    # across that would stall every API request locator serves.
                    stale_nodes.append((node_id, dict(node)))

        for node_id, info in stale_nodes:
            reachable = _node_reachable(info)
            if reachable:
                new_status = NODE_STATUS_AGENT_DOWN
                reason = f"reachable at {_node_probe_addr(info)}, agent not reporting"
            elif reachable is None:
                new_status = "OFFLINE"
                reason = "stale heartbeat, no address on record to probe"
            else:
                new_status = "OFFLINE"
                reason = "stale heartbeat and unreachable"

            transitioned = False
            with lock:
                node = registry["nodes"].get(node_id)
                if node is not None:
                    # A heartbeat may have arrived while we were probing.
                    if not _node_is_fresh(node) and node.get("status") != new_status:
                        node["status"] = new_status
                        changed = True
                        transitioned = True

            # Outside the lock, and only on an actual transition, so a node
            # sitting in either state does not re-log or re-notify every
            # REAPER_INTERVAL seconds.
            if transitioned:
                if new_status == NODE_STATUS_AGENT_DOWN:
                    print(f"⚠️  NODE AGENT DOWN: {node_id} ({reason})")
                    record_event("node_agent_down",
                                 f"{node_id} is up but its agent is not reporting — {reason}",
                                 unit=node_id)
                else:
                    print(f"💀 NODE OFFLINE: {node_id} ({reason})")
                    record_event("node_offline", f"{node_id} is offline — {reason}",
                                 unit=node_id)

        if changed:
            persist_registry()


# ── LOAD BALANCER ────────────────────────────────────────────────────────────

# Containers that must never be migrated or deduped automatically
LOCATOR_YML = os.environ.get("LOCATOR_YML", os.path.join(os.path.dirname(os.path.abspath(__file__)), "locator.yml"))
LOCATOR_COMPOSE = os.environ.get(
    "LOCATOR_COMPOSE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml"),
)

# Pseudo-paths, not files — see list_yamls().
TEMPLATE_LOCATOR_YML = "template:locator.yml"
TEMPLATE_COMPOSE_YML = "template:docker-compose.yml"

YAML_TEMPLATES = {
    TEMPLATE_LOCATOR_YML: """\
# Service policy. Read by the locator on every change (no restart needed).
#
# location_type:   stationary = never migrate (anything holding data on local
#                  disk, since migration moves the compose file and NOT the
#                  volume). mobile = may be rebalanced between units.
# deployment_type: essential = must always be running; the locator restarts it
#                  as soon as it is seen OFFLINE. non-essential = left alone,
#                  and the only kind idle_stop will ever act on.
#                  ONLY "essential" is matched; every other value, typo included,
#                  reads as non-essential. "optional" is a legacy alias, still
#                  accepted but no longer written.
# units:           current_unit (default) | all | 8 | "7_8_9"
#                  ALWAYS QUOTE the underscore form — YAML 1.1 reads a bare
#                  7_8_9 as the integer 789 and the policy matches nothing.
# instances:       how many per unit (default 1)
# project_dir /
# git_remote:      opt in to placement enforcement. Without one of these the
#                  locator will NOT fan a service out, because a queued deploy
#                  carries only a container name and the target would have
#                  nothing to check out.
# env:             .env values for the target ('common' + per-unit override).
#                  lokey merges them and never overwrites an existing key.

Service:
  my-service:
    deployment_type: non-essential
    location_type: stationary
    units: current_unit
    instances: 1
    # project_dir: /home/swoopg111/projects/my-service
    # git_remote: https://gitlab.com/<group>/my-service.git
    # env:
    #   common:
    #     SOME_KEY: value
    #   unit8:
    #     SOME_KEY: unit8-override
""",
    TEMPLATE_COMPOSE_YML: """\
# Blank compose file. Save As writes it into the locator's compose store,
# where it becomes deployable from the YAMLs tab.

services:
  my-service:
    image: nginx:alpine
    container_name: my-service
    restart: unless-stopped
    # Volumes are NOT moved by a migration — mark anything with data below as
    # location_type: stationary in locator.yml.
    volumes: []
    environment:
      - PYTHONUNBUFFERED=1
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-service.rule=Host(`my-service.example.com`)"
      - "traefik.http.routers.my-service.entrypoints=websecure"
      - "traefik.http.routers.my-service.tls=true"
      - "traefik.http.routers.my-service.tls.certresolver=myresolver"
      - "traefik.http.services.my-service.loadbalancer.server.port=80"
    networks:
      - networking

networks:
  networking:
    external: true
""",
}

_policy_cache = {"mtime": None, "data": {}}


def _as_list(value):
    """Normalise a YAML scalar-or-list into a list of clean strings.

    locator.yml is hand-edited, so `wake_with: reech-db` and
    `wake_with: [reech-db]` both have to mean the same thing — a schema that
    punishes the shorter spelling just produces silently-empty policy.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = [value]
    return [str(v).strip() for v in items if str(v).strip()]


def load_policy():
    """Service policy from locator.yml, keyed by lowercase service name.

    This file existed but nothing read it, so services marked
    'location_type: stationary' were migrated anyway — which is how the
    database behind ns1's PowerDNS came to be queued for a move. Reloaded on
    mtime change so edits take effect without a restart.

    Tolerates the original misspellings ('deployement_type',
    'inactivity_timout_minutes') alongside the corrected ones.
    """
    try:
        mtime = os.path.getmtime(LOCATOR_YML)
    except OSError:
        return {}
    if _policy_cache["mtime"] == mtime:
        return _policy_cache["data"]

    try:
        import yaml as _yaml
        with open(LOCATOR_YML) as fh:
            doc = _yaml.safe_load(fh) or {}
    except Exception as e:
        print(f"⚠️  locator.yml unreadable: {e}")
        return _policy_cache["data"]

    # Accept "Service:" (as written) or a bare top-level mapping.
    services = doc.get("Service") or doc.get("services") or doc
    parsed = {}
    if isinstance(services, dict):
        for name, cfg in services.items():
            if not isinstance(cfg, dict):
                continue
            parsed[str(name).lower()] = {
                "location_type": str(cfg.get("location_type", "")).lower(),
                "deployment_type": str(
                    cfg.get("deployment_type", cfg.get("deployement_type", ""))).lower(),
                "units": str(cfg.get("units", cfg.get("Unit", "current_unit"))).lower(),
                "instances": cfg.get("instances", 1),
                # Read by lokey, not by this file: each agent enforces
                # this against its own Docker socket. Must be whitelisted
                # here or load_policy() silently drops it like any other
                # unknown key, and the setting looks configured but is not.
                "restart_when_stopped": bool(cfg.get("restart_when_stopped", False)),
                # Idle auto-stop, decided HERE rather than by a per-container
                # docker label. A label can only be changed by recreating the
                # container; locator.yml is editable from the dashboard and is
                # the fleet's stated source of truth, so the policy lives with
                # the rest of the policy.
                #
                # STRICTLY OPT-IN. A service becomes eligible only by saying
                # idle_stop: true here, so anything absent from this file can
                # never be stopped by omission — which is the whole point:
                # unit8 alone runs ~40 containers against far fewer policies.
                "idle_stop": bool(cfg.get("idle_stop", False)),
                # Optional per-service override, same spelling the label took
                # ("15m", "2h", "5400"). Empty means use IDLE_DEFAULT_TIMEOUT.
                "idle_timeout": str(cfg.get("idle_timeout", "")),
                # Migration prerequisites: service names (or "name@unit" for a
                # specific instance) that must have an ONLINE instance somewhere
                # before this service may be migrated. Read by
                # resolve_migration_order(), which gates POST /api/migrations.
                #
                # Whitelisted here for the reason stated above restart_when_stopped:
                # an un-whitelisted key is dropped without a word, so declaring
                # depends_on in locator.yml would look configured and do nothing.
                # That is not hypothetical — it is exactly what happened on
                # 2026-09-03, when a test dependency was declared, silently
                # discarded here, and the migration it should have blocked went
                # through and stopped the service.
                "depends_on": (cfg.get("depends_on")
                               if isinstance(cfg.get("depends_on"), list) else []),
                # Needed to deploy onto a unit that has never hosted the
                # service — a queued command carries only a container name,
                # so without these there is nothing to check out there.
                "project_dir": str(cfg.get("project_dir", "")),
                "git_remote": str(cfg.get("git_remote", "")),
                # {"common": {...}, "unit9": {...}} — compose .env values the
                # target needs. Gitignored on nearly every project, so a fresh
                # clone has none and every ${VAR} resolves empty.
                "env": cfg.get("env") if isinstance(cfg.get("env"), dict) else {},
                # Tailnet publish port an edge should reach this service on.
                # Read by /api/traefik: the locator answers where the service
                # IS, and this says on which port. Same opt-in shape as the
                # rest of the policy - undeclared means not edge-routed.
                "edge_port": cfg.get("edge_port"),
                # Resolve this service's placement through ANOTHER service's
                # registry entry. Several edge file-services can sit on one
                # backend — error-pages carries passHostHeader:false where its
                # siblings carry true — and only the backend's name ever
                # registers a container.
                "edge_host": str(cfg.get("edge_host", "")),
                # loadBalancer options the emitted service carries.
                # edge_pass_host: None leaves Traefik's default (true);
                # edge_healthcheck is a path, emitted with the fleet's usual
                # 15s/5s probe.
                "edge_pass_host": cfg.get("edge_pass_host"),
                "edge_healthcheck": str(cfg.get("edge_healthcheck", "")),
                # ── Wake-on-request ──────────────────────────────────────
                # Same argument as idle_stop above, and the other half of the
                # same feature: the thing that STOPS a container is declared
                # here, so the thing that starts it belongs here too rather
                # than being spread across Traefik query strings and frontend
                # constants, which is where it used to live and why it silently
                # rotted (a retired hostname in one place, a missing prop in
                # another, and no single file that said what the truth was).
                #
                # public_wake — STRICTLY OPT-IN, exactly like idle_stop. Lets an
                # anonymous visitor wake this one container and nothing else.
                "public_wake": bool(cfg.get("public_wake", False)),
                # wake_with — dependencies started alongside it. reech needs
                # reech-oauth; forge needs forge-relay. Declared here so a caller asks for
                # ONE name and locator expands it, instead of every Traefik file
                # and every link having to know the dependency list.
                "wake_with": _as_list(cfg.get("wake_with")),
                # wake_triggers — WHAT causes the wake, keyed by trigger kind so
                # new kinds need no code change. `domain:` is the kind in use:
                # the hostnames whose visit should wake this container. Serving
                # it back over /api/wake/triggers is what lets a page ask which
                # container its link needs rather than hardcoding a name that
                # nobody updates when the container is renamed.
                "wake_triggers": {
                    str(k).lower(): _as_list(v)
                    for k, v in cfg["wake_triggers"].items()
                } if isinstance(cfg.get("wake_triggers"), dict) else {},
            }
    _policy_cache.update({"mtime": mtime, "data": parsed})
    print(f"📄 locator.yml loaded — {len(parsed)} service policies")
    return parsed


def _policy_for(name):
    """Policy entry for a container, matching on name or base name."""
    pol = load_policy()
    low = (name or "").lower()
    if low in pol:
        return pol[low]
    base = _base_name(low)
    if base in pol:
        return pol[base]
    # Allow a policy key to match a versioned container (mariadb -> mariadb-11.4)
    for key, cfg in pol.items():
        if key and key in low:
            return cfg
    return {}


def _is_pinned(name):
    """True when a container must never be migrated.

    Honours locator.yml first — anything marked 'location_type: stationary' is
    immovable — then falls back to the built-in list.

    Substring match, not set membership. The balancer used `name in
    _PINNED_NAMES`, which only catches bare names: "postgres" was protected but
    "comms-postgres" was not, and "mariadb" was protected while "mariadb-11.4"
    — the database behind ns1's PowerDNS — was freely migratable. It was queued
    for a move to unit9 that would have taken DNS down for four domains and left
    the only copy of an unbacked-up database behind, because migration moves the
    compose file and not the volume.

    Elsewhere in this file the same list is already applied as a substring test;
    this makes the balancer agree with it.
    """
    low = (name or "").lower()
    if _policy_for(low).get("location_type") == "stationary":
        return True
    return any(p in low for p in _PINNED_NAMES)


_PINNED_NAMES = {
    "traefik", "apache", "apache2", "httpd", "varnish", "bind9", "bind",
    "openvpn", "openvpn-client", "headscale", "tailscale", "wireguard-client", "wireguard",
    "powerdns", "pdns", "ns1-auth", "ns1",
    "postgres", "postgresql", "redis", "mysql", "mariadb",
    "php-fpm", "barcode_db",
    "matrix_synapse", "matrix_element", "matrix_sms_bridge",
    "lokey", "lokey-client",
    "wg-easy", "crowdsec", "fail2ban",
    # Added 2026-08-23, ahead of idle shutdown moving from opt-in to opt-out.
    # None of these has a wake-on-request path, so once stopped they stay
    # stopped until a human notices:
    #   openbao    — the secrets broker every bao:// reference resolves
    #                through; stopping it breaks the next deploy on any unit.
    #   fluent-bit — the log shippers. A quiet shipper is the one you most need
    #                running, and unit8's being down 36h is why its containers
    #                were missing from the log filter lists entirely.
    #   keycloak / freeipa — identity. Stopping either locks people out of
    #                everything that authenticates against them.
    "openbao", "fluent-bit", "keycloak", "freeipa",
    # Public web front doors. Both are bound to unit8 by an A record in pdns and
    # by Traefik's file provider, so migrating one moves the compose file while
    # DNS keeps pointing at unit8 — the site just goes dark. locator.yml already
    # pins them; this makes it uneditable from the grid as well.
    "main-site", "client-portal",
}


def _clean_ip(raw):
    """Strip description suffixes like '10.0.0.1- hostname'."""
    clean = _first_addr(raw)
    return clean if clean and clean != "unknown" else None


def _best_ip(info):
    """Return the best reachable IP for a node (Tailscale preferred)."""
    return (
        info.get("tailscale_ip")
        or _clean_ip(info.get("ip"))
        or _clean_ip(info.get("openvpn_ip"))
    )


def resolve_migration_order(svc_id, services_snap):
    """
    Shallow (one-level) dependency check for a service about to be migrated.
    Returns (deps, missing) — deps is the service's declared depends_on list,
    missing is the subset with no ONLINE instance anywhere in the registry.
    A dependency doesn't need to be co-located with the service being moved
    (Locator services generally reach each other over Tailscale/openvpn, not
    localhost) — it just needs to be reachable somewhere.

    Not a general DAG scheduler: does not recurse into a dependency's own
    depends_on, and does not order multiple simultaneous migrations relative
    to each other.
    """
    svc = services_snap.get(svc_id, {})
    deps = svc.get("depends_on", []) or []

    # Fall back to locator.yml when the registry record carries nothing, which
    # is every record today: depends_on only ever reaches the registry through
    # the /register payload, and no agent sends it -- 0 of 415 services had it
    # populated on 2026-09-03. That made this gate vacuously pass for every
    # migration, which reads as "dependencies satisfied" and is really
    # "dependencies never declared".
    #
    # Policy is the right home for it rather than a per-unit file on each agent:
    # locator.yml is already the single source of truth for placement, already
    # hot-reloads on mtime, is already editable from the dashboard's YAMLs tab,
    # and already expresses this exact shape as wake_with. A file on each unit
    # would scatter the truth across nine boxes and go unreadable precisely when
    # a unit is down, which is when you most need to know what it carried.
    #
    # The registry still wins when set, so an agent that starts sending
    # depends_on keeps overriding policy without a code change here.
    if not deps:
        deps = list((_policy_for(svc.get("name") or "") or {}).get("depends_on") or [])

    # A dependency may be written either way, and both are useful:
    #   "pdns@unit8" — that exact instance, on that node
    #   "pdns"       — any ONLINE instance anywhere, which is the common case and
    #                  the only form policy can express, since locator.yml is
    #                  keyed on bare service names and says nothing about hosts.
    # The bare form matches the co-location rule above: services reach each other
    # over the tailnet, so where a dependency runs does not matter, only that it
    # is up somewhere.
    def _dep_online(dep):
        if "@" in dep:
            return services_snap.get(dep, {}).get("status") == "ONLINE"
        low = dep.lower()
        return any(
            (v.get("name") or "").lower() == low and v.get("status") == "ONLINE"
            for v in services_snap.values()
        )

    missing = [d for d in deps if not _dep_online(d)]
    return deps, missing


def _ssh_exec(host, user, cmd, timeout=20):
    """
    Run a command on a remote host over SSH using the configured deploy key
    (SSH_KEY/SSH_USER — see CONFIG). Used by the DNS status/sync endpoints to
    shell out to `pdnsutil`/`pdns_control` on the box actually running
    PowerDNS, since Locator itself runs on Fly, not on that box.
    Returns (success, stdout_or_error).
    """
    import subprocess
    if not SSH_KEY:
        return False, "SSH_KEY not configured — cannot reach remote host"
    ssh_cmd = [
        "ssh", "-i", SSH_KEY,
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8",
        f"{user}@{host}", cmd,
    ]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()
        return True, result.stdout.strip()
    except Exception as e:
        return False, str(e)


def load_balancer():
    """
    Periodically checks node CPU/memory and queues container migrations
    when a node is overloaded (> BALANCE_HIGH %) and a suitable target
    node is available (< BALANCE_LOW %).

    Anti-flap: a node must be overloaded for two consecutive checks
    before a migration is triggered.
    Cooldown: BALANCE_COOLDOWN seconds must pass before migrating
    another container from the same source node.
    """
    while True:
        time.sleep(BALANCE_INTERVAL)

        if not BALANCE_ENABLED:
            continue

        now = datetime.now(timezone.utc)

        with lock:
            nodes_snap    = {k: dict(v) for k, v in registry["nodes"].items()}
            services_snap = {k: dict(v) for k, v in registry["services"].items()}

        overloaded     = []   # [(node_id, load_pct, node_info)]
        underloaded    = []   # [(node_id, load_pct, node_info)]
        all_nodes_load = []   # all nodes with valid metrics, for spread check
        prestage_candidates = []  # [(node_id, load_pct, node_info)] — trending, not yet overloaded

        prestage_threshold = BALANCE_HIGH - BALANCE_PRESTAGE_MARGIN

        for node_id, info in nodes_snap.items():
            if info.get("status") != "ONLINE":
                overload_strikes.pop(node_id, None)
                continue

            cpu  = info.get("cpu_percent")
            mem  = info.get("mem_percent")
            disk = info.get("disk_percent")
            if cpu is None or mem is None:
                continue  # hasn't reported metrics yet

            # Disk pressure is the primary trigger; CPU/mem are secondary
            load = disk if disk is not None else max(cpu, mem)

            all_nodes_load.append((node_id, load, info))
            if mem is not None and mem >= OOM_THRESHOLD:
                # OOM emergency: always treat as overloaded, bypasses anti-flap/cooldown below
                overloaded.append((node_id, load, info))
            elif load >= BALANCE_HIGH:
                overloaded.append((node_id, load, info))
            elif load <= BALANCE_LOW:
                underloaded.append((node_id, load, info))
            elif load >= prestage_threshold and BALANCE_PRESTAGE_ENABLED:
                # Between prestage_threshold and BALANCE_HIGH: not yet actioned,
                # but worth validating ahead of time (see prestage pass below).
                prestage_candidates.append((node_id, load, info))
                overload_strikes.pop(node_id, None)
            else:
                overload_strikes.pop(node_id, None)  # no longer overloaded

        # Pre-stage pass: validate (never execute) a would-be migration for nodes
        # trending toward BALANCE_HIGH. Runs regardless of whether a real
        # migration fires this cycle — it's watching a different, earlier band.
        # Deliberately non-destructive: reachability + dependency checks only,
        # no package installs or git fetches performed automatically in the
        # background — see prestage_state's docstring for why that was scoped
        # out. This still gives the dashboard early "watching X -> Y" visibility
        # and skips redundant reachability lookups once a real migration is queued.
        if BALANCE_PRESTAGE_ENABLED and prestage_candidates:
            with_ip_underloaded = [
                (nid, ld, inf) for nid, ld, inf in (underloaded + all_nodes_load)
                if _best_ip(inf)
            ]
            for node_id, load, info in prestage_candidates:
                candidates = [
                    (svc_id, svc) for svc_id, svc in services_snap.items()
                    if svc.get("host") == node_id
                    and svc.get("status") == "ONLINE"
                    and svc.get("type") in ("container", "native")
                    and not _is_pinned(svc.get("name"))
                    and not svc.get("metadata", {}).get("pinned")
                ]
                for svc_id, svc in candidates:
                    deps, missing = resolve_migration_order(svc_id, services_snap)
                    tgt = next((t for t in with_ip_underloaded if t[0] != node_id), None)
                    with prestage_lock:
                        prestage_state[svc_id] = {
                            "svc":               svc_id,
                            "candidate_source":  node_id,
                            "candidate_target":  tgt[0] if tgt else None,
                            "load":              load,
                            "deps":              deps,
                            "missing_deps":      missing,
                            "target_reachable":  bool(tgt),
                            "checked_at":        now.isoformat(),
                        }

        # Differential trigger: if spread between busiest and least busy >= BALANCE_DIFF,
        # promote the busiest into overloaded and least busy into underloaded even if
        # neither crosses the absolute thresholds (e.g. 50% vs 1% = 49% spread).
        if all_nodes_load and not (overloaded and underloaded):
            all_nodes_load.sort(key=lambda x: x[1])
            least = all_nodes_load[0]
            busiest = all_nodes_load[-1]
            if busiest[1] - least[1] >= BALANCE_DIFF:
                if busiest not in overloaded:
                    overloaded.append(busiest)
                if least not in underloaded:
                    underloaded.append(least)

        if not overloaded or not underloaded:
            # Reset strikes for any node that's no longer overloaded
            for node_id in list(overload_strikes):
                if node_id not in {n[0] for n in overloaded}:
                    overload_strikes.pop(node_id, None)
            continue

        overloaded.sort(key=lambda x: x[1], reverse=True)   # worst first
        underloaded.sort(key=lambda x: x[1])                 # most free first

        for src_id, src_load, src_info in overloaded:
            is_oom = (src_info.get("mem_percent") or 0) >= OOM_THRESHOLD
            if is_oom:
                print(f"🚨 BALANCE: OOM emergency on {src_id} mem={src_info.get('mem_percent'):.1f}% — bypassing anti-flap/cooldown")

            # Cooldown check (skipped in OOM emergency)
            last_mig = node_last_migrated.get(src_id)
            if not is_oom and last_mig and (now - last_mig).total_seconds() < BALANCE_COOLDOWN:
                remaining = int(BALANCE_COOLDOWN - (now - last_mig).total_seconds())
                print(f"⏳ BALANCE: {src_id} in cooldown ({remaining}s remaining)")
                continue

            # Anti-flap: require consecutive overloaded checks (skipped in OOM emergency)
            if not is_oom:
                overload_strikes[src_id] = overload_strikes.get(src_id, 0) + 1
                if overload_strikes[src_id] < BALANCE_STRIKES:
                    print(f"⚠️  BALANCE: {src_id} at {src_load:.1f}% — strike {overload_strikes[src_id]}/{BALANCE_STRIKES}, watching")
                    continue

            # Find movable services on this node — container OR native, as long as
            # their declared dependencies (if any) are satisfied somewhere in the
            # registry. Native services used to be hard-excluded here entirely.
            movable = [
                (svc_id, svc)
                for svc_id, svc in services_snap.items()
                if svc.get("host") == src_id
                and svc.get("status") == "ONLINE"
                and svc.get("type") in ("container", "native")
                and not _is_pinned(svc.get("name"))
                and not svc.get("metadata", {}).get("pinned")
                and not resolve_migration_order(svc_id, services_snap)[1]  # no missing deps
            ]

            if not movable:
                print(f"⚠️  BALANCE: {src_id} overloaded but no movable services found (container or native, deps satisfied)")
                continue

            # Pick the container: oldest running first (most stable, least disruptive)
            movable.sort(key=lambda x: x[1].get("registered_at", ""))
            svc_id, svc = movable[0]
            container_name = svc["name"]

            # Fast path: if this exact service was already pre-staged (Phase 3)
            # against a reachable target recently enough, skip re-searching for
            # one — the prestage pass already did that reachability lookup.
            tgt_id = tgt_ip = tgt_info = tgt_load = None
            staged = prestage_state.get(svc_id)
            if staged and staged.get("candidate_target") and not staged.get("missing_deps"):
                staged_age = (now - datetime.fromisoformat(staged["checked_at"])).total_seconds()
                if staged_age <= PRESTAGE_STALE_SECONDS:
                    _stid = staged["candidate_target"]
                    _sinfo = nodes_snap.get(_stid, {})
                    _sip = _best_ip(_sinfo)
                    if _sip and _sinfo.get("status") == "ONLINE":
                        tgt_id, tgt_ip, tgt_info = _stid, _sip, _sinfo
                        tgt_load = _sinfo.get("disk_percent") or max(_sinfo.get("cpu_percent") or 0, _sinfo.get("mem_percent") or 0)

            if not tgt_id:
                # Fall back to searching fresh — first underloaded node with a usable IP
                for _tid, _tload, _tinfo in underloaded:
                    _tip = _best_ip(_tinfo)
                    if _tip:
                        tgt_id, tgt_load, tgt_info, tgt_ip = _tid, _tload, _tinfo, _tip
                        break
            if not tgt_id:
                print(f"⚠️  BALANCE: no reachable target node for {src_id}")
                continue

            with prestage_lock:
                prestage_state.pop(svc_id, None)  # consumed — now a real migration, not just watched

            src_ip = _best_ip(src_info) or ""
            mig_id = str(uuid.uuid4())[:8]
            # Explicit type, matching create_migration()'s logic — without this,
            # native services would fall through to the Docker-only legacy rsync
            # path (_execute_rsync_migration) and fail outright.
            mig_type = "git_push_and_stop" if svc.get("type") == "container" else "native_stop_and_sync"
            with migration_lock:
                migration_queue[mig_id] = {
                    "id":         mig_id,
                    "container":  container_name,
                    "from_node":  src_id,
                    "from_ip":    src_ip,
                    "to_node":    tgt_id,
                    "to_ip":      tgt_ip,
                    "unit":       src_id,   # push/stop step runs on the source
                    "status":     "PENDING",
                    "queued_at":  now.isoformat(),
                    "reason":     f"{src_id} disk {src_load:.1f}% → {tgt_id} disk {tgt_load:.1f}%",
                    "type":       mig_type,
                    "sync_path":  svc.get("metadata", {}).get("sync_path", ""),
                    "systemd_unit": svc.get("metadata", {}).get("systemd_unit", container_name),
                    "prereqs":    svc.get("prereqs", {}),
                }

            node_last_migrated[src_id] = now
            overload_strikes[src_id]   = 0

            print(
                f"📦 BALANCE: Queued {mig_id} — move '{container_name}' "
                f"{src_id}({src_load:.1f}%) → {tgt_id}({tgt_load:.1f}%)"
            )

        # Clear strikes for nodes no longer overloaded
        for node_id in list(overload_strikes):
            if node_id not in {n[0] for n in overloaded}:
                overload_strikes.pop(node_id, None)

        # Drop pre-stage entries for services whose node fell back out of the
        # prestage band entirely (not still prestage-watched, and not consumed
        # into a real migration above) — otherwise these accumulate forever.
        watched_nodes = {n[0] for n in prestage_candidates}
        with prestage_lock:
            for svc_id in list(prestage_state):
                if prestage_state[svc_id].get("candidate_source") not in watched_nodes:
                    prestage_state.pop(svc_id, None)


# ── LOCAL DOCKER DISCOVERY ────────────────────────────────────────────────

def local_docker_scanner():
    """Background thread that scans local Docker containers for 'forgotten' services."""
    if not docker_client:
        return

    while True:
        try:
            containers = docker_client.containers.list()
            now = datetime.now(timezone.utc).isoformat()
            changed = False
            
            _local_unit = os.environ.get("UNIT_NAME", "unknown")

            for container in containers:
                name = container.name
                if name == "locator": continue

                # Keyed name@host, matching /register. This used to key on the
                # bare container name, which meant a local scan would refresh
                # whatever entry happened to own that name — including records
                # seeded for a DIFFERENT host. unit8's containers were therefore
                # heartbeating the seeded unit1 records ONLINE forever: the host
                # field was never touched, so they never aged out and looked
                # alive long after unit1 was gone.
                service_id = f"{name}@{_local_unit}"

                with lock:
                    if service_id not in registry["services"]:
                        # Register new container discovered locally
                        registry["services"][service_id] = {
                            "name": name,
                            "category": "docker containers",
                            "host": _local_unit,
                            "hosts": [_local_unit],
                            "status": "ONLINE",
                            "last_heartbeat": now,
                            "registered_at": now,
                            "type": "container",
                            "metadata": {
                                "image": container.image.tags[0] if container.image.tags else "unknown",
                                "discovered_via": "local_docker"
                            }
                        }
                        changed = True
                    else:
                        registry["services"][service_id]["status"] = "ONLINE"
                        registry["services"][service_id]["last_heartbeat"] = now
                        registry["services"][service_id].pop("offline_since", None)

            # Mark the local node ONLINE since we can see its containers
            _local_unit = os.environ.get("UNIT_NAME", "unknown")
            with lock:
                if _local_unit and _local_unit != "unknown" and _local_unit in registry["nodes"]:
                    registry["nodes"][_local_unit]["status"] = "ONLINE"
                    registry["nodes"][_local_unit]["last_seen"] = now

            if changed:
                persist_registry()

        except Exception as e:
            print(f"⚠️ Error in local Docker scanner: {e}")

        time.sleep(SCANNER_INTERVAL)


# ── DUPLICATE KILLER ─────────────────────────────────────────────────────────

def duplicate_killer():
    """
    Detects the *same service* running more than once and stops the oldest.
    Skips infrastructure services listed in _PINNED_NAMES.

    Grouping is by compose project+service, NOT by image alone: several
    distinct services legitimately share one image (e.g. every oauth2-proxy
    guard runs quay.io/oauth2-proxy/oauth2-proxy but fronts a different
    upstream). Keying on the image made those look like duplicates of each
    other and silently stopped all but the newest, taking their sites down.
    Only containers with no compose labels fall back to the image key.
    """
    if not docker_client:
        return

    while True:
        time.sleep(DUPLICATE_KILLER_INTERVAL)
        try:
            containers = docker_client.containers.list()
            by_image: dict = {}
            for ctr in containers:
                if ctr.name in _PINNED_NAMES:
                    continue
                try:
                    ctr.reload()
                except Exception:
                    continue
                tags = ctr.image.tags
                image_key = tags[0].split(":")[0] if tags else ctr.image.id[:12]
                labels = ctr.labels or {}
                project = labels.get("com.docker.compose.project")
                service = labels.get("com.docker.compose.service")
                group_key = f"compose:{project}/{service}" if project and service else f"image:{image_key}"
                by_image.setdefault(group_key, []).append(ctr)

            for image_key, ctrs in by_image.items():
                if len(ctrs) < 2:
                    continue
                # Sort oldest-first by container start time; keep only the newest
                ctrs.sort(key=lambda c: c.attrs.get("State", {}).get("StartedAt", ""))
                for old in ctrs[:-1]:
                    print(f"🛑 DUPLICATE KILLER: stopping '{old.name}' (older instance of {image_key})")
                    try:
                        old.stop(timeout=10)
                        now = datetime.now(timezone.utc).isoformat()
                        with lock:
                            svc = registry["services"].get(old.name)
                            if svc:
                                svc["status"] = "OFFLINE"
                                if not svc.get("offline_since"):
                                    svc["offline_since"] = now
                        persist_registry()
                    except Exception as e:
                        print(f"⚠️ DUPLICATE KILLER: failed to stop '{old.name}': {e}")

        except Exception as e:
            print(f"⚠️ Error in duplicate killer: {e}")


# ── IDLE AUTO-SHUTDOWN ──────────────────────────────────────────────────────
#
# Lokey on each unit reports net-traffic counters for containers labeled
# locator.idle.stop=true (POST /api/idle/report). The locator runs the idle
# clock centrally and queues a stop command for that unit's lokey once a
# container has been quiet past its timeout. A sleeping service's wake link
# (/wake/<container>) queues the matching start command.

# (unit, container) -> {"last_active": dt, "last_bytes": int, "timeout": s,
#                       "last_report": dt, "stopped_count": int}
_idle_state: dict = {}
_idle_lock = threading.Lock()

# Container command queue for lokeys — id -> command dict
command_queue: dict = {}
command_lock = threading.Lock()
COMMAND_RETRY_SECONDS = 180   # re-serve DISPATCHED commands the lokey never completed
COMMAND_RETENTION     = 100   # completed commands kept for history


PLACEMENT_FAIL_BACKOFF = 1800   # don't retry a failed deploy for 30 minutes


def _expand_unit_spec(spec, online_units):
    """locator.yml's 'units:' value → the set of unit names it names.

    Accepts 'all', a single unit ('8' or 'unit8'), or the underscore-separated
    list the file actually uses ('4_7_8_9'). Bare numbers get the 'unit'
    prefix because that is how every entry has always been written.
    'current_unit' — the default when the key is absent — means "wherever it
    already runs", i.e. no fan-out.
    """
    spec = (spec or "").strip().lower()
    if not spec or spec == "current_unit":
        return set()
    if spec == "all":
        return set(online_units)
    # YAML 1.1 treats underscores as digit separators, so an UNQUOTED
    # `units: 4_7_8_9` arrives here as the integer 4789 and would silently
    # expand to one nonexistent "unit4789". Refuse it loudly instead.
    if spec.isdigit() and len(spec) > 2:
        print(f"⚠️  locator.yml: units '{spec}' looks like an unquoted "
              f"underscore list (YAML read 4_7_8_9 as 4789) — quote it")
        return set()
    names = set()
    for part in re.split(r"[_,\s]+", spec):
        if part:
            names.add(part if part.startswith("unit") else f"unit{part}")
    return names


def enforce_unit_placement():
    """Background: queue deploy commands so each service runs on every unit
    locator.yml assigns it to.

    This previously matched only the literal string 'all', and read it from
    svc['metadata']['units'] — a key lokey never sets — so it fired for
    nothing and locator.yml's 'units:' field was decorative. It now reads the
    policy file itself and understands the '4_7_8_9' form used there.

    Only queues for units where the service is NOT already registered, so a
    satisfied policy goes quiet instead of re-queueing every 60s, and backs
    off after a failure rather than hot-looping the way the matomo migration
    did.
    """
    time.sleep(30)  # let registry initialize
    while True:
        try:
            with lock:
                online_units = [
                    unit_id for unit_id, info in registry.get("nodes", {}).items()
                    if info.get("status") == "ONLINE"
                ]
                services = list(registry.get("services", {}).items())

            # Only ONLINE instances count as covered. Counting every registry
            # entry meant a service that had been stopped — or evicted — left
            # an OFFLINE row behind that read as "already there", so placement
            # never redeployed it and the unit stayed empty indefinitely.
            running, known = {}, set()
            for _svc_id, svc in services:
                nm = (svc.get("name") or "").lower()
                known.add(nm)
                if svc.get("status") == "ONLINE" and svc.get("host"):
                    running.setdefault(nm, set()).add(svc.get("host"))

            now = time.time()
            for name in sorted(known):
                pol = _policy_for(name)
                # Opt-in only. Placement predates this enforcement, so most
                # entries in locator.yml were written when 'units:' did
                # nothing — switching it on for all of them at once would
                # start deploying services nobody asked to be fanned out.
                # A policy has to say HOW to deploy before it is acted on,
                # and a command without these fails on the target anyway.
                if not (pol.get("project_dir") or pol.get("git_remote")):
                    continue
                wanted = _expand_unit_spec(pol.get("units"), online_units)
                if not wanted:
                    continue
                missing = (wanted & set(online_units)) - running.get(name, set())
                for unit in sorted(missing):
                    if _recent_placement_failure(unit, name, now):
                        continue
                    # locator itself put it to sleep — the idle reaper and
                    # /api/shutdown both set metadata.idle_stopped, and any
                    # successful start clears it. Deploying over that flag
                    # resurrects the service ~60s after every quiet-hours
                    # stop: store-site looped exactly like this until the
                    # check existed. Wake is the way back, not placement.
                    if _was_idle_stopped(name, unit, services):
                        continue
                    env_cfg = pol.get("env") or {}
                    env_map = {**(env_cfg.get("common") or {}),
                               **(env_cfg.get(unit) or {})}
                    _queue_command(
                        unit, name, "deploy", source="unit_placement",
                        extra={
                            "project_dir": pol.get("project_dir", ""),
                            "git_remote": pol.get("git_remote", ""),
                            "env": {str(k): str(v) for k, v in env_map.items()},
                        },
                    )
        except Exception as e:
            print(f"⚠️  enforce_unit_placement error: {e}")
        time.sleep(60)


def _was_idle_stopped(name, unit, services):
    """True when the service's registry entry on `unit` carries idle_stopped —
    locator queued that stop itself (idle reaper or /api/shutdown) and no
    successful start has landed since. Placement must not resurrect it."""
    for _svc_id, svc in services:
        if (svc.get("name") or "").lower() != name:
            continue
        if svc.get("host") != unit:
            continue
        if (svc.get("metadata") or {}).get("idle_stopped"):
            return True
    return False


def _recent_placement_failure(unit, container, now):
    """True if this unit+container deploy failed inside the backoff window."""
    with command_lock:
        for cmd in command_queue.values():
            if (cmd.get("unit") == unit and cmd.get("container") == container
                    and cmd.get("action") == "deploy" and cmd.get("status") == "FAILED"):
                try:
                    ts = datetime.fromisoformat(cmd.get("completed_at") or "").timestamp()
                except (ValueError, TypeError):
                    continue
                if now - ts < PLACEMENT_FAIL_BACKOFF:
                    return True
    return False


def _parse_duration(value, default):
    """'3600' / '90m' / '2h' / '45s' → seconds."""
    try:
        value = str(value).strip().lower()
        if value.endswith("h"):
            return int(float(value[:-1]) * 3600)
        if value.endswith("m"):
            return int(float(value[:-1]) * 60)
        if value.endswith("s"):
            return int(float(value[:-1]))
        return int(value)
    except (ValueError, TypeError):
        return default


# deployment_type has exactly two meanings, and only one of them was ever
# written down. Every check in this file is `== "essential"`, so ANY other
# string -- including a typo -- silently reads as not-essential and makes the
# service eligible for idle_stop and eviction. "optional" was never a keyword
# the code recognised; it was just the label the toggle path happened to write,
# which made the vocabulary look richer than it is.
#
# The accurate word for "not essential" is NON-ESSENTIAL, so that is now what
# the toggle writes and what the template documents. "optional" stays accepted
# as a legacy alias -- there are existing entries carrying it and they must keep
# working -- but nothing emits it any more.
DEPLOYMENT_ESSENTIAL = "essential"
DEPLOYMENT_NON_ESSENTIAL = "non-essential"
DEPLOYMENT_ALIASES = {"optional", "nonessential", "non_essential"}


def is_essential(cfg):
    """True only for an explicitly essential service.

    Kept as one function so the 'anything not essential is non-essential'
    reading lives in exactly one place instead of four scattered == comparisons.
    """
    return str(cfg.get("deployment_type", "")).strip().lower() == DEPLOYMENT_ESSENTIAL


def _queue_command(unit, container, action, source="idle", extra=None):
    """Queue a container command for a unit's lokey. Deduped on unit+container+action.

    `extra` carries action-specific fields through to lokey — 'deploy' needs
    project_dir/git_remote, since a unit that has never hosted the service has
    nothing to bring up from a container name alone.
    """
    with command_lock:
        for cmd in command_queue.values():
            # .get, not [], because _queue_exec_command shares this queue and
            # its entries carry no "container" at all - they are {action:"exec",
            # script:...}. Subscripting blew up with KeyError the moment any exec
            # job was pending, and since wake_page queues through here, that made
            # EVERY /wake/<name> return 500 - the whole wake-on-request feature,
            # fleet-wide, silently dependent on the exec queue being empty.
            if (cmd["unit"] == unit and cmd.get("container") == container
                    and cmd["action"] == action and cmd["status"] in ("PENDING", "DISPATCHED")):
                return cmd
        cmd_id = str(uuid.uuid4())[:8]
        cmd = {
            "id": cmd_id, "unit": unit, "container": container, "action": action,
            "source": source, "status": "PENDING",
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "dispatched_at": None, "completed_at": None, "success": None,
        }
        cmd.update(extra or {})
        command_queue[cmd_id] = cmd
        done = [c for c in command_queue.values() if c["status"] in ("DONE", "FAILED")]
        if len(done) > COMMAND_RETENTION:
            done.sort(key=lambda c: c["completed_at"] or "")
            for old in done[: len(done) - COMMAND_RETENTION]:
                command_queue.pop(old["id"], None)
        print(f"📨 COMMAND QUEUED: {action} '{container}' on {unit} ({source})")
        return cmd


EXEC_OUTPUT_RETENTION = 500   # completed exec commands kept for history (separate cap — output-bearing)

# A container start/stop that hasn't reported in 3 minutes is stuck, but an exec
# job routinely runs far longer than that — a refresh doing apt + git across a
# dozen repos takes minutes. Re-serving it on the container clock would start a
# SECOND copy on the same unit while the first is still running, so exec carries
# its own, much longer retry window and its own hard timeout.
EXEC_RETRY_SECONDS   = int(os.environ.get("EXEC_RETRY_SECONDS", 1800))
EXEC_RUN_TIMEOUT     = int(os.environ.get("EXEC_RUN_TIMEOUT", 3600))    # DISPATCHED, never reported → TIMEOUT
EXEC_PICKUP_TIMEOUT  = int(os.environ.get("EXEC_PICKUP_TIMEOUT", 1800))  # PENDING, never collected → MISSED
EXEC_REAPER_INTERVAL = int(os.environ.get("EXEC_REAPER_INTERVAL", 60))


def _record_run(cmd):
    """Mirror a queued command into Postgres. Never let a DB hiccup break the
    queue itself — the run must still happen if the bookkeeping fails."""
    try:
        db.record_command_run(cmd)
    except Exception as e:
        print(f"⚠️  Failed to record command run {cmd.get('id')}: {e}")


def _update_run(cmd, error=None, duration_ms=None):
    try:
        db.update_command_run(cmd, error=error, duration_ms=duration_ms)
    except Exception as e:
        print(f"⚠️  Failed to update command run {cmd.get('id')}: {e}")


def _output_tail(text, limit=200):
    """Last meaningful line of a command's output, for an event-log one-liner."""
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if line:
            return line[:limit]
    return ""


def _emit_run_event(cmd, duration_ms=None, error=None):
    """Put an exec outcome on the event log the tactical grid reads.

    A failure names the unit and carries the tail of stderr, so "which unit had
    trouble, and roughly why" is answerable from the event feed alone without
    going and fetching the full output.
    """
    label  = cmd.get("label") or "exec"
    unit   = cmd.get("unit")
    ok     = bool(cmd.get("success"))
    status = cmd.get("status") or ("DONE" if ok else "FAILED")
    if ok:
        message = f"{label} on {unit} completed"
        if duration_ms:
            message += f" in {round(duration_ms / 1000)}s"
    else:
        message = f"{label} on {unit} {status.lower()}"
        if cmd.get("exit_code") not in (None, 0):
            message += f" (exit {cmd['exit_code']})"
        detail = error or _output_tail(cmd.get("stderr")) or _output_tail(cmd.get("stdout"))
        if detail:
            message += f": {detail}"
    return emit_event("exec_ok" if ok else "exec_failed",
                      unit=unit, label=label, message=message, status=status,
                      command_id=cmd.get("id"), exit_code=cmd.get("exit_code"),
                      duration_ms=duration_ms, job_id=cmd.get("job_id"))


def exec_run_reaper():
    """Close out exec jobs that will never report.

    Two distinct silences, kept distinct because they mean different things:
    a job nobody ever collected (MISSED — that unit's lokey is not polling, so
    the unit is effectively unmanaged) versus one collected and never reported
    (TIMEOUT — it started and died, or is wedged). Both are removed from the
    queue so the pending endpoint cannot re-serve them afterwards.
    """
    while True:
        time.sleep(EXEC_REAPER_INTERVAL)
        now = datetime.now(timezone.utc)
        stale = []
        try:
            with command_lock:
                for cmd in list(command_queue.values()):
                    if cmd.get("action") != "exec":
                        continue
                    if cmd["status"] == "PENDING":
                        stamp, limit, status = cmd.get("queued_at"), EXEC_PICKUP_TIMEOUT, "MISSED"
                        reason = "no lokey collected the job — is the unit's agent running?"
                    elif cmd["status"] == "DISPATCHED":
                        stamp, limit, status = cmd.get("dispatched_at"), EXEC_RUN_TIMEOUT, "TIMEOUT"
                        reason = "the unit collected the job and never reported back"
                    else:
                        continue
                    try:
                        age = (now - datetime.fromisoformat(stamp)).total_seconds()
                    except (TypeError, ValueError):
                        continue
                    if age <= limit:
                        continue
                    cmd["status"]       = status
                    cmd["success"]      = False
                    cmd["completed_at"] = now.isoformat()
                    stale.append((dict(cmd), reason))
                    command_queue.pop(cmd["id"], None)
            for cmd, reason in stale:
                print(f"⌛ EXEC {cmd['status']}: '{(cmd.get('label') or cmd.get('script') or '')[:60]}' "
                      f"on {cmd['unit']} — {reason}")
                _update_run(cmd, error=reason)
                _emit_run_event(cmd, error=reason)
        except Exception as e:
            print(f"⚠️ Error in exec run reaper: {e}")


def _queue_exec_command(unit, script, source="manual", label=None, job_id=None):
    """Queue an arbitrary-shell-command job for a unit's lokey. Not deduped —
    every call is its own job, unlike the container start/stop queue above.
    Lokey is a pure executor here: it runs whatever is queued and reports
    stdout/stderr/exit_code back, it never decides what's allowed to run."""
    with command_lock:
        cmd_id = str(uuid.uuid4())[:8]
        cmd = {
            "id": cmd_id, "unit": unit, "action": "exec", "script": script,
            "label": label, "source": source, "status": "PENDING", "job_id": job_id,
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "dispatched_at": None, "completed_at": None, "success": None,
            "stdout": None, "stderr": None, "exit_code": None,
        }
        command_queue[cmd_id] = cmd
        done = [c for c in command_queue.values() if c["status"] in ("DONE", "FAILED")]
        if len(done) > EXEC_OUTPUT_RETENTION:
            done.sort(key=lambda c: c["completed_at"] or "")
            for old in done[: len(done) - EXEC_OUTPUT_RETENTION]:
                command_queue.pop(old["id"], None)
        print(f"📨 EXEC QUEUED: '{script[:80]}' on {unit} ({source})")
        queued = dict(cmd)
    _record_run(queued)
    return queued




# ═══════════════════════════════════════════════════════════════════════
#  SECRETS BROKER  —  locator is the only holder of the OpenBao token
# ═══════════════════════════════════════════════════════════════════════
# locator.yml's env: block holds bao:// REFERENCES, never values. Deploy
# commands carry the reference (a path is not a secret); lokey exchanges it
# here for the value using LOCATOR_ADMIN_KEY. That split exists because
# /api/commands/pending is unauthenticated and Traefik's locator-api router
# bypasses Keycloak for /api/ — anything queued is world-readable.

@app.route("/api/secrets/status", methods=["GET"])
def secrets_status():
    """Broker health. Never returns secret values.

    Ungated but redacted, so the Keycloak-protected dashboard (whose browser
    session carries no admin key) can still show whether the broker is alive.
    Send the admin key to get the full picture.
    """
    try:
        full = bao.status()
    except Exception as e:
        return jsonify({"reachable": False, "error": str(e)}), 200
    if request.headers.get("X-Locator-Admin-Key") and not _require_admin_key():
        return jsonify(full)
    return jsonify({k: full.get(k) for k in
                    ("reachable", "sealed", "configured", "token_ok",
                     "token_ttl_seconds", "cached_secrets", "version")})


@app.route("/api/secrets/resolve", methods=["POST"])
def secrets_resolve():
    """Exchange bao:// references for values. Admin key required.

    Two body shapes:
      {"service": "reech", "unit": "unit8"}  -> that service's whole env block
                                                from locator.yml, resolved
      {"refs": ["bao://secret/reech#client_secret", ...]} -> ref -> value

    Returns 502 and resolves NOTHING on any failure. A partially resolved env
    map is worse than none: it seeds a blank into .env and surfaces days later
    as an auth error nobody can trace back to here.
    """
    denied = _require_admin_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}

    if data.get("refs"):
        refs = data["refs"]
        if not isinstance(refs, list):
            return jsonify({"error": "refs must be a list"}), 400
        out = {}
        try:
            for ref in refs:
                out[ref] = bao.resolve_ref(ref)
        except bao.BaoError as e:
            return jsonify({"error": str(e)}), 502
        return jsonify({"resolved": out, "count": len(out)})

    service = (data.get("service") or "").strip().lower()
    if not service:
        return jsonify({"error": "body needs 'service' or 'refs'"}), 400
    pol = _policy_for(service)
    if not pol:
        return jsonify({"error": f"no policy for '{service}' in locator.yml"}), 404
    env_cfg = pol.get("env") or {}
    unit = (data.get("unit") or "").strip().lower()
    env_map = {**(env_cfg.get("common") or {}), **(env_cfg.get(unit) or {})}
    if not env_map:
        return jsonify({"service": service, "unit": unit, "env": {}, "refs_used": []})
    try:
        resolved, used = bao.resolve_env_map(env_map)
    except bao.BaoError as e:
        emit_event("secrets", action="resolve_failed", service=service, error=str(e))
        return jsonify({"error": str(e), "service": service}), 502
    return jsonify({"service": service, "unit": unit,
                    "env": resolved, "refs_used": used})


@app.route("/api/secrets/refresh", methods=["POST"])
def secrets_refresh():
    """Drop cached secrets so the next resolve re-reads OpenBao. Post-rotation."""
    denied = _require_admin_key()
    if denied:
        return denied
    prefix = (request.get_json(silent=True) or {}).get("prefix")
    dropped = bao.invalidate(prefix)
    return jsonify({"dropped": dropped, "prefix": prefix})


@app.route("/api/secrets/refs", methods=["GET"])
def secrets_refs():
    """Every bao:// reference locator.yml mentions, per service.

    Paths only, never values — this is the map you check after rotating a
    secret to see which services need a redeploy.
    """
    out = {}
    for name, pol in (load_policy() or {}).items():
        env_cfg = pol.get("env") or {}
        refs = {}
        for scope, block in env_cfg.items():
            if not isinstance(block, dict):
                continue
            for k, v in block.items():
                if bao.is_ref(v):
                    refs.setdefault(scope, {})[str(k)] = str(v)
        if refs:
            out[name] = refs
    return jsonify({"services": out, "count": len(out)})


# ═══════════════════════════════════════════════════════════════════════
#  COMPOSE SECRET SWEEP  —  find plaintext credentials, then vault them
# ═══════════════════════════════════════════════════════════════════════
# lokey uploads every unit's docker-compose.yml into COMPOSE_DIR and the store
# is committed and pushed, so a password typed into an environment: block is
# both readable on the unit and permanent in git history. The sweeper reports;
# quarantine is a deliberate, admin-keyed act because it edits live compose
# files on units and a bad rewrite takes a stack down.

SECRETSCAN_INTERVAL = int(os.environ.get("SECRETSCAN_INTERVAL", "900"))
SECRETSCAN_ENABLED = os.environ.get("SECRETSCAN_ENABLED", "true").lower() in ("1", "true", "yes")
# Where a quarantined credential is filed. One secret per compose file keeps
# the bao:// reference readable and the blast radius of a rotation small.
SECRETSCAN_MOUNT = os.environ.get("SECRETSCAN_MOUNT", "secret")
SECRETSCAN_PREFIX = os.environ.get("SECRETSCAN_PREFIX", "compose")

_scan_cache = {"at": None, "findings": [], "files": 0}
_scan_lock = threading.Lock()


def _compose_store_files():
    """(name, path) for every compose file in the store."""
    out = []
    try:
        for fname in sorted(os.listdir(COMPOSE_DIR)):
            if fname.endswith((".yml", ".yaml")):
                out.append((os.path.splitext(fname)[0], os.path.join(COMPOSE_DIR, fname)))
    except FileNotFoundError:
        pass
    return out


def _scan_store():
    """Scan every stored compose file. Findings keep their raw values, so this
    result must be passed through secretscan.public() before it leaves here."""
    findings, files = [], 0
    for name, path in _compose_store_files():
        try:
            with open(path, errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        files += 1
        findings.extend(secretscan.scan_text(text, source=name))
    return findings, files


@app.route("/api/secrets/scan", methods=["GET"])
def secrets_scan():
    """Plaintext credentials found in the compose store. Values are masked.

    ?fresh=1 rescans instead of serving the sweeper's last pass.
    """
    if request.args.get("fresh") in ("1", "true", "yes"):
        findings, files = _scan_store()
        with _scan_lock:
            _scan_cache.update({"at": datetime.now(timezone.utc).isoformat(),
                                "findings": findings, "files": files})
    with _scan_lock:
        findings = list(_scan_cache["findings"])
        at, files = _scan_cache["at"], _scan_cache["files"]

    by_file, by_sev = {}, {}
    for f in findings:
        by_file.setdefault(f["source"], []).append(f["key"])
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return jsonify({
        "scanned_at": at,
        "files_scanned": files,
        "total": len(findings),
        "by_severity": by_sev,
        "by_file": {k: sorted(set(v)) for k, v in sorted(by_file.items())},
        "findings": secretscan.public(findings),
    })


def _bao_path_for(compose_name):
    return f"{SECRETSCAN_PREFIX}/{compose_name}"


def _unit_key_auth():
    """Authenticate a secrets call made with the admin key or a unit's own key.

    Returns (scope, None) on success — scope is None for the admin key (any
    unit) or the unit name the key belongs to — or (None, response) to abort.
    Fails closed: a request carrying neither credential is refused here, since
    clearance.UNIT_KEY lets these routes past the gate for this check to run.
    """
    if request.headers.get("X-Locator-Admin-Key"):
        denied = _require_admin_key()
        return (None, denied) if denied else (None, None)
    unit = request.headers.get("X-Lokey-Unit", "").strip()
    key = request.headers.get("X-Lokey-Key", "")
    if unit and key and unitkeys.verify(unit, key):
        return unit, None
    return None, (jsonify({"error": "unauthorized"}), 401)


# ── INGEST: a unit hands us its .env, we file the credentials in OpenBao ──────
#
# The gap this closes: lokey only ever uploaded docker-compose.yml, and
# secretscan only understood `environment:` blocks — so a credential living in a
# unit's .env was invisible to the sweeper, to /api/secrets/scan and to
# quarantine alike. That is where most of them are. Compose interpolates ${KEY}
# from the .env beside it precisely so the value is NOT in the yaml, which means
# the store scan reads clean exactly where the real secret sits on disk.
#
# This is the ONLY inbound route that carries raw credential values, so unlike
# /api/compose — open by design, and its store is committed and auto-pushed —
# it is admin-keyed and fails closed. Nothing is written to disk here and
# nothing but key NAMES is logged: values go to OpenBao and are then dropped.
#
# It deliberately stops at storing. It does NOT rewrite the unit's .env and does
# NOT queue a redaction. Filing a value is additive, idempotent and reversible;
# editing a live service's config is none of those. Getting the secret INTO
# OpenBao is the half that is safe to automate — taking it back out of the file
# stays the explicit, admin-keyed act it already is in quarantine below.
INGEST_MAX_BYTES = int(os.environ.get("SECRETSCAN_INGEST_MAX", "65536"))
# Verbose tracing for the ingest path. Default ON: this is the only route that
# carries raw credential values, and a rollout of it needs to be watchable in
# live-logger rather than guessed at from a silent 200. Set SECRETSCAN_DEBUG=0
# once it is boring. Every line below is names-and-counts only — a value must
# never reach a log, and beast_log forwards to beast-telemetry.
SECRETSCAN_DEBUG = os.environ.get("SECRETSCAN_DEBUG", "true").lower() in ("1", "true", "yes")


def _ingest_log(line):
    if SECRETSCAN_DEBUG:
        beast_log(f"\U0001f510 ingest: {line}")
_INGEST_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@app.route("/api/secrets/ingest", methods=["POST"])
def secrets_ingest():
    """File a unit's .env credentials into OpenBao.

    Body: {"unit": "unit8", "source": "pdns",
           "path": "/home/.../pdns/.env", "content": "<raw .env text>",
           "dry_run": false}

    Returns the bao:// refs to paste into locator.yml, what was skipped, and
    masked values only — the response is safe to log and to show in an event.
    """
    scope, denied = _unit_key_auth()
    if denied:
        return denied

    body = request.get_json(silent=True) or {}
    unit = str(body.get("unit") or "").strip() or (scope or "unknown")
    source = str(body.get("source") or "").strip()
    origin = str(body.get("path") or "").strip()
    content = body.get("content")

    # A unit key files under its own unit and nowhere else. Checked before
    # anything is parsed, so a key cannot be used to write another unit's path.
    if scope and unit != scope:
        return jsonify({"error": f"this key belongs to {scope}, not {unit}"}), 403

    if not source:
        return jsonify({"error": "source (the compose project name) is required"}), 400
    # `source` becomes a path segment in OpenBao, so it gets the same charset
    # discipline as a stored compose name — a '../' here would write outside
    # the prefix the broker policy allows.
    if not _INGEST_NAME_RE.match(source):
        return jsonify({"error": f"invalid source name {source!r}"}), 400
    if not isinstance(content, str) or not content.strip():
        return jsonify({"error": "empty content"}), 400
    if len(content) > INGEST_MAX_BYTES:
        return jsonify({"error": f"content exceeds {INGEST_MAX_BYTES} bytes"}), 413

    _ingest_log(f"{unit} offered {source} ({len(content)} bytes) from {origin or 'unknown path'}")

    findings = secretscan.scan_env_text(content, source=source)
    actionable = [f for f in findings if f["severity"] not in ("placeholder", "hashed")]
    skipped = [f for f in findings if f["severity"] in ("placeholder", "hashed")]
    # Names and severities only. This is the line that tells you, mid-rollout,
    # whether the scanner is seeing what you expect it to see on that unit.
    _ingest_log(f"{source}: {len(findings)} finding(s) — "
                f"store {[f['key'] for f in actionable] or 'nothing'}, "
                f"skip {[(f['key'], f['severity']) for f in skipped] or 'nothing'}")

    if not actionable:
        # Not an error: most .env files are ports and flags. Reported so a unit
        # can tell "nothing to file" apart from "the call never landed".
        _ingest_log(f"{source}: nothing storable — not calling OpenBao")
        return jsonify({"unit": unit, "source": source, "path": origin,
                        "stored": [], "refs": {},
                        "skipped": secretscan.public(skipped),
                        "note": "no storable credential found"})

    values = {f["key"]: f["value"] for f in actionable}
    # Unit-key filings live under compose/units/<unit>/<source>, the one prefix
    # /api/secrets/unit-resolve lets that same unit read back.
    bao_path = (f"{unitkeys.secret_prefix(SECRETSCAN_PREFIX, scope)}/{source}" if scope
                else _bao_path_for(source))
    refs = {k: f"bao://{SECRETSCAN_MOUNT}/{bao_path}#{k}" for k in sorted(values)}
    masked = {f["key"]: f["masked"] for f in actionable}

    if body.get("dry_run"):
        return jsonify({"unit": unit, "source": source, "path": origin, "dry_run": True,
                        "would_store": sorted(values), "refs": refs, "masked": masked,
                        "bao_path": f"{SECRETSCAN_MOUNT}/{bao_path}",
                        "skipped": secretscan.public(skipped)})

    try:
        _ingest_log(f"{source}: writing {sorted(values)} -> {SECRETSCAN_MOUNT}/{bao_path}")
        bao.write_secret(SECRETSCAN_MOUNT, bao_path, values)
        # Read back for the same reason quarantine does: a write that reports
        # success but stored nothing must never be reported as success, or the
        # next step redacts a file against a secret that is not there.
        stored = bao.read_secret(SECRETSCAN_MOUNT, bao_path, use_cache=False)
        mismatch = sorted(k for k, v in values.items() if stored.get(k) != v)
        _ingest_log(f"{source}: read-back {'OK' if not mismatch else 'MISMATCH ' + str(mismatch)} "
                    f"({len(stored)} field(s) now at {SECRETSCAN_MOUNT}/{bao_path})")
        if mismatch:
            raise bao.BaoError(f"read-back mismatch for {mismatch}")
    except bao.BaoError as e:
        beast_log(f"\U0001f510 INGEST FAILED for {unit}:{source} — {e}")
        emit_event("secrets", action="ingest_failed", unit=unit, source=source,
                   path=origin, error=str(e))
        return jsonify({"error": f"OpenBao write failed: {e}"}), 502

    emit_event("secrets", action="ingested", unit=unit, source=source, path=origin,
               keys=sorted(values), bao_path=f"{SECRETSCAN_MOUNT}/{bao_path}")
    beast_log(f"\U0001f510 INGESTED {len(values)} credential(s) from "
              f"{unit}:{origin or source} \u2192 {SECRETSCAN_MOUNT}/{bao_path} "
              f"({', '.join(sorted(values))})")
    # `stored` lists exactly the keys whose values OpenBao returned unchanged on
    # read-back. It is the confirmation lokey waits for before deleting those
    # keys from the unit's .env — and nothing absent from it may be deleted.
    return jsonify({"unit": unit, "source": source, "path": origin,
                    "stored": sorted(values), "verified": True, "refs": refs, "masked": masked,
                    "bao_path": f"{SECRETSCAN_MOUNT}/{bao_path}",
                    "skipped": secretscan.public(skipped)})


@app.route("/api/secrets/unit-resolve", methods=["POST"])
def secrets_unit_resolve():
    """A unit reads back the secrets it filed — and only those.

    Body: {"refs": ["bao://secret/compose/units/unit8/matomo#DB_PASSWORD", ...]}
    Auth: X-Lokey-Unit + X-Lokey-Key. Every ref must sit under
    compose/units/<that unit>/; one out-of-scope ref refuses the whole request,
    and nothing is resolved on any failure (same rule as /api/secrets/resolve).
    """
    scope, denied = _unit_key_auth()
    if denied:
        return denied
    if not scope:
        return jsonify({"error": "unit key required; admins use /api/secrets/resolve"}), 400
    refs = (request.get_json(silent=True) or {}).get("refs")
    if not isinstance(refs, list) or not refs:
        return jsonify({"error": "refs must be a non-empty list"}), 400
    try:
        parsed = [(r, *bao.parse_ref(r)) for r in refs]
    except bao.BaoError as e:
        return jsonify({"error": str(e)}), 400
    outside = [r for r, mount, path, _f in parsed
               if mount != SECRETSCAN_MOUNT or not unitkeys.path_in_scope(path, SECRETSCAN_PREFIX, scope)]
    if outside:
        _ingest_log(f"{scope} asked for {len(outside)} ref(s) outside its scope — refused")
        return jsonify({"error": f"refs outside {scope}'s scope", "refs": outside}), 403
    out = {}
    try:
        for ref in refs:
            out[ref] = bao.resolve_ref(ref)
    except bao.BaoError as e:
        return jsonify({"error": str(e)}), 502
    return jsonify({"resolved": out, "count": len(out)})


@app.route("/api/secrets/unit-keys", methods=["POST"])
def secrets_unit_keys_mint():
    """Mint or rotate a unit's ingest key. Body: {"unit": "unit8"}.

    The key is in this response and nowhere else — only its hash is kept.
    Minting again replaces (and so revokes) that unit's previous key.
    """
    denied = _require_admin_key()
    if denied:
        return denied
    unit = str((request.get_json(silent=True) or {}).get("unit") or "").strip()
    try:
        key = unitkeys.mint(unit)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    emit_event("secrets", action="unit_key_minted", unit=unit)
    return jsonify({"unit": unit, "key": key,
                    "note": "shown once; put it in this unit's lokey as LOKEY_UNIT_KEY"})


@app.route("/api/secrets/unit-keys", methods=["GET"])
def secrets_unit_keys_list():
    """Which units hold an ingest key, and when it was minted. Never the keys."""
    denied = _require_admin_key()
    if denied:
        return denied
    return jsonify({"units": unitkeys.listing()})


@app.route("/api/secrets/quarantine", methods=["POST"])
def secrets_quarantine():
    """Move one compose file's plaintext credentials into OpenBao.

    Body: {"file": "matomo-db", "keys": [...optional subset...],
           "dry_run": true}

    Order matters and is not negotiable: the value goes into OpenBao FIRST and
    is read back, then the file is rewritten. Rewriting first would, on a bao
    write failure, leave a ${VAR} with nothing behind it — the credential gone
    from the file and never stored anywhere.

    This rewrites the STORE copy and queues a redact_env command for the unit
    that owns the container, so the real file on the unit is fixed too.
    """
    denied = _require_admin_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    name = (data.get("file") or "").strip()
    if not name:
        return jsonify({"error": "body needs 'file'"}), 400
    dry_run = bool(data.get("dry_run"))
    only = set(data.get("keys") or [])

    path = os.path.join(COMPOSE_DIR, f"{name}.yml")
    if not os.path.isfile(path):
        path = os.path.join(COMPOSE_DIR, f"{name}.yaml")
    if not os.path.isfile(path):
        return jsonify({"error": f"no compose file '{name}' in the store"}), 404
    with open(path, errors="replace") as f:
        text = f.read()

    findings = secretscan.scan_text(text, source=name)
    actionable = [f for f in findings
                  if f["severity"] not in ("placeholder", "hashed")
                  and (not only or f["key"] in only)]
    skipped = [f for f in findings if f not in actionable]
    if not actionable:
        return jsonify({"file": name, "quarantined": [], "skipped": secretscan.public(skipped),
                        "note": "nothing actionable"})

    # Same key twice in one file (a password repeated across two services) must
    # agree, or we cannot store one value under one field name.
    values = {}
    for f in actionable:
        prev = values.get(f["key"])
        if prev is not None and prev != f["value"]:
            return jsonify({"error": f"'{f['key']}' appears twice in {name} with "
                                     f"different values — resolve by hand"}), 409
        values[f["key"]] = f["value"]

    bao_path = _bao_path_for(name)
    new_text, changed = secretscan.redact_text(text, actionable)
    refs = {k: f"bao://{SECRETSCAN_MOUNT}/{bao_path}#{k}" for k in sorted(values)}

    if dry_run:
        return jsonify({"file": name, "dry_run": True,
                        "would_store": sorted(values), "bao_path": f"{SECRETSCAN_MOUNT}/{bao_path}",
                        "refs": refs, "skipped": secretscan.public(skipped),
                        "diff_lines": sorted({f["line"] for f in actionable})})

    try:
        bao.write_secret(SECRETSCAN_MOUNT, bao_path, values)
        # Read back before touching the file. A write that reported success but
        # stored nothing would otherwise be discovered only after redaction.
        stored = bao.read_secret(SECRETSCAN_MOUNT, bao_path, use_cache=False)
        missing = [k for k, v in values.items() if stored.get(k) != v]
        if missing:
            raise bao.BaoError(f"read-back mismatch for {missing}")
    except bao.BaoError as e:
        emit_event("secrets", action="quarantine_failed", file=name, error=str(e))
        return jsonify({"error": f"OpenBao write failed, file left untouched: {e}"}), 502

    backup = f"{path}.bak-prequarantine-{int(time.time())}"
    try:
        with open(backup, "w") as f:
            f.write(text)
        with open(path, "w") as f:
            f.write(new_text)
    except OSError as e:
        return jsonify({"error": f"secrets stored in OpenBao but the store file "
                                 f"could not be rewritten: {e}"}), 500

    queued = _queue_redactions(name, sorted(values), refs)
    emit_event("secrets", action="quarantined", file=name,
               keys=sorted(values), bao_path=f"{SECRETSCAN_MOUNT}/{bao_path}",
               units=queued)
    if GIT_AUTO_PUSH:
        _git_push_event.set()
    print(f"🔐 QUARANTINED {len(changed)} credential(s) from {name} → "
          f"{SECRETSCAN_MOUNT}/{bao_path}; redaction queued for {queued or 'no unit'}")
    return jsonify({"file": name, "quarantined": sorted(values),
                    "bao_path": f"{SECRETSCAN_MOUNT}/{bao_path}", "refs": refs,
                    "store_backup": backup, "units_queued": queued,
                    "skipped": secretscan.public(skipped)})


def _queue_redactions(compose_name, keys, refs):
    """Tell whichever unit runs this container to strip the same lines locally.

    The command carries only key names and bao:// references, never a value —
    /api/commands/pending is unauthenticated.
    """
    units = set()
    with lock:
        services = dict(registry.get("services") or {})
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if (svc.get("name") or svc_name or "").lower() != compose_name.lower():
            continue
        # ONLINE only. The registry still carries unit1 as the host of half the
        # estate — that laptop has been dead for months — and queuing a
        # redaction there would park a command nobody ever collects while the
        # unit actually running the container keeps its plaintext copy.
        if str(svc.get("status", "")).upper() != "ONLINE":
            continue
        unit = svc.get("host")
        if unit and unit != "external":
            units.add(unit)
    for unit in sorted(units):
        _queue_command(unit, compose_name, "redact_env", source="secret_sweep",
                       extra={"keys": list(keys), "refs": refs})
    return sorted(units)


def bao_token_renewer():
    """Keep the broker's periodic token alive.

    A periodic token never expires WHILE it is renewed, and dies without a
    sound the moment renewal stops. Renewing at a fraction of the remaining TTL
    means a few missed passes (a locator restart, a bao restart) cost nothing.
    """
    while True:
        try:
            st = bao.status()
            if not st.get("token_ok"):
                # Not configured yet is the normal state before
                # provision-bao-broker.sh has been run; don't spam about it.
                time.sleep(300)
                continue
            ttl = st.get("token_ttl_seconds") or 0
            if ttl and ttl < 7 * 24 * 3600:
                lease = bao.renew_self()
                print(f"🔐 OpenBao broker token renewed — lease now {lease}s")
            time.sleep(max(3600, min(int(ttl / 4) if ttl else 3600, 21600)))
        except bao.BaoError as e:
            print(f"⚠️  OpenBao token renewal failed: {e}")
            time.sleep(600)
        except Exception as e:
            print(f"⚠️  token renewer error: {e}")
            time.sleep(600)


def secret_sweeper():
    """Background pass over the compose store. Reports only — never edits."""
    if not SECRETSCAN_ENABLED:
        print("🔐 secret sweeper disabled (SECRETSCAN_ENABLED=false)")
        return
    known = set()
    while True:
        try:
            findings, files = _scan_store()
            with _scan_lock:
                _scan_cache.update({"at": datetime.now(timezone.utc).isoformat(),
                                    "findings": findings, "files": files})
            # Alert on what is NEW since the last pass. Re-announcing 27 known
            # findings every 15 minutes trains everyone to ignore the channel.
            seen = {(f["source"], f["key"], f["severity"]) for f in findings}
            fresh = seen - known
            if fresh and known:
                for source, key, sev in sorted(fresh):
                    print(f"🔐 NEW plaintext credential: {source} → {key} ({sev})")
                    emit_event("secrets", action="exposed", file=source,
                               key=key, severity=sev)
            elif fresh:
                print(f"🔐 secret sweep: {len(findings)} plaintext credential(s) "
                      f"across {files} compose file(s) — GET /api/secrets/scan")
            known = seen
        except Exception as e:
            print(f"⚠️  secret sweeper error: {e}")
        time.sleep(SECRETSCAN_INTERVAL)


@app.route("/api/exec", methods=["POST"])
def queue_exec():
    """Queue a shell command/script to run on a unit's lokey. Requires admin key —
    this is remote code execution across the fleet, gated accordingly."""
    denied = _require_admin_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    unit   = (data.get("unit") or "").strip()
    script = data.get("script") or ""
    label  = data.get("label")
    if not unit or not script.strip():
        return jsonify({"error": "Provide 'unit' and 'script'"}), 400
    cmd = _queue_exec_command(unit, script, source="manual", label=label)
    return jsonify({"result": "queued", "command": cmd})


@app.route("/api/commands", methods=["GET"])
def list_commands():
    """List recent commands (container + exec), newest first. Requires admin key
    since exec commands carry script text/output that may be sensitive."""
    denied = _require_admin_key()
    if denied:
        return denied
    unit = request.args.get("unit")
    with command_lock:
        cmds = [dict(c) for c in command_queue.values() if not unit or c["unit"] == unit]
    cmds.sort(key=lambda c: c["queued_at"], reverse=True)
    return jsonify(cmds[:200])


@app.route("/api/commands/<cmd_id>", methods=["GET"])
def get_command(cmd_id):
    """Fetch a single command's status/output — used to poll an exec job to completion."""
    denied = _require_admin_key()
    if denied:
        return denied
    with command_lock:
        cmd = command_queue.get(cmd_id)
        if not cmd:
            return jsonify({"error": "unknown command"}), 404
        return jsonify(dict(cmd))


# ── SCRIPT SCHEDULER ─────────────────────────────────────────────────────────
# Recurring exec jobs: "run this script on this unit every N" registered once,
# fired forever by script_scheduler() below via the same _queue_exec_command
# path a one-off /api/exec call uses.
#
# Two ways to say when. `interval` (reuses _parse_duration, e.g. "24h") counts
# forward from the last firing, so its clock drifts by however long locator was
# restarting — a job meant for 08:00 slides later every week. `times`
# (["08:00","20:00"], UTC) pins the job to wall-clock slots instead, which is
# what the fleet refresh needs to keep the staggered per-unit ordering the
# crontabs had. Still not cron: no day-of-week or day-of-month.

scheduled_jobs: dict = {}
schedule_lock = threading.Lock()
SCHEDULE_FILE = os.path.join(DATA_DIR, "scheduled_jobs.json")
SCHEDULE_CHECK_INTERVAL = int(os.environ.get("SCHEDULE_CHECK_INTERVAL", 30))


def _parse_times(value):
    """['08:00', '20:00'] or '08:00,20:00' → sorted [(h, m), …]. [] if unusable."""
    if not value:
        return []
    if isinstance(value, str):
        value = [p for p in re.split(r"[,\s]+", value) if p]
    out = []
    for item in value:
        m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(item).strip())
        if not m:
            continue
        hour, minute = int(m.group(1)), int(m.group(2))
        if 0 <= hour < 24 and 0 <= minute < 60:
            out.append((hour, minute))
    return sorted(set(out))


def _next_wall_clock(times, after=None):
    """Next UTC datetime matching one of `times`, strictly after `after`."""
    after = after or datetime.now(timezone.utc)
    for day in (0, 1):
        base = (after + timedelta(days=day)).replace(second=0, microsecond=0)
        for hour, minute in times:
            candidate = base.replace(hour=hour, minute=minute)
            if candidate > after:
                return candidate
    return after + timedelta(days=1)


def _advance_job(job, now=None):
    """Set job['next_run'] to its next firing. Wall-clock jobs land on their
    next slot; interval jobs count forward from now, as they always did."""
    now = now or datetime.now(timezone.utc)
    times = _parse_times(job.get("times"))
    if times:
        job["next_run"] = _next_wall_clock(times, now).isoformat()
    else:
        job["next_run"] = (now + timedelta(seconds=job["interval_seconds"])).isoformat()
    return job["next_run"]


def persist_schedule():
    """Write scheduled_jobs to disk so registrations survive a restart/redeploy."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with schedule_lock:
            snapshot = json.dumps(list(scheduled_jobs.values()), indent=2)
        with open(SCHEDULE_FILE, "w") as f:
            f.write(snapshot)
    except Exception as e:
        print(f"⚠️  Failed to persist schedule: {e}")


def load_schedule():
    """Load scheduled_jobs from disk on startup, if present.

    A job whose next_run is already in the past was due while locator was down.
    Firing every one of those on boot would stampede the fleet (every unit
    refreshing at once, hours off schedule), so instead each is recorded as a
    MISSED run against its unit and rolled forward to the next slot. That way a
    locator outage shows up in the same place as a failed run rather than as
    silence — which is exactly how the last outage went unnoticed.
    """
    if not os.path.exists(SCHEDULE_FILE):
        return
    try:
        with open(SCHEDULE_FILE) as f:
            jobs = json.load(f)
        now = datetime.now(timezone.utc)
        missed = []
        with schedule_lock:
            for job in jobs:
                scheduled_jobs[job["id"]] = job
                if not job.get("enabled", True):
                    continue
                try:
                    due = datetime.fromisoformat(job["next_run"])
                except (TypeError, ValueError, KeyError):
                    continue
                if due < now:
                    missed.append((dict(job), due))
                    _advance_job(job, now)
        print(f"📅 Loaded {len(jobs)} scheduled job(s) from disk")
        for job, due in missed:
            _record_missed_run(job, due, now)
        if missed:
            persist_schedule()
    except Exception as e:
        print(f"⚠️  Failed to load schedule: {e}")


def _record_missed_run(job, due, now=None):
    """Log a firing that never happened because locator was not running."""
    now = now or datetime.now(timezone.utc)
    late = round((now - due).total_seconds() / 60)
    cmd = {
        "id": str(uuid.uuid4())[:8], "unit": job.get("unit"), "action": "exec",
        "label": job.get("label"), "source": "scheduled", "script": job.get("script"),
        "job_id": job.get("id"), "status": "MISSED", "success": False,
        "queued_at": due.isoformat(), "completed_at": now.isoformat(),
        "exit_code": None, "stdout": None, "stderr": None,
    }
    reason = f"locator was not running at the scheduled time ({late} min late, run skipped)"
    print(f"⌛ SCHEDULE MISSED: {job.get('label') or job.get('id')} on {job.get('unit')} — {reason}")
    _record_run(cmd)
    _update_run(cmd, error=reason)
    _emit_run_event(cmd, error=reason)


def script_scheduler():
    """Fires due scheduled exec jobs. Runs forever in a daemon thread."""
    while True:
        time.sleep(SCHEDULE_CHECK_INTERVAL)
        now = datetime.now(timezone.utc)
        try:
            with schedule_lock:
                due = [dict(j) for j in scheduled_jobs.values()
                       if j.get("enabled", True) and j.get("next_run")
                       and datetime.fromisoformat(j["next_run"]) <= now]
            for job in due:
                cmd = _queue_exec_command(job["unit"], job["script"], source="scheduled",
                                           label=job.get("label"), job_id=job["id"])
                with schedule_lock:
                    live = scheduled_jobs.get(job["id"])
                    if live:
                        live["last_run"] = now.isoformat()
                        live["last_command_id"] = cmd["id"]
                        _advance_job(live, now)
                print(f"📅 SCHEDULED EXEC fired: job {job['id']} ('{job['script'][:60]}') on {job['unit']}")
            if due:
                persist_schedule()
        except Exception as e:
            print(f"⚠️ Error in script scheduler: {e}")


@app.route("/api/schedule", methods=["POST"])
def create_schedule():
    """Register a recurring exec job.

    Body: {unit, script, label?} plus EITHER 'interval' ('3600'/'90m'/'24h',
    the same shorthand idle timeouts use) OR 'times' (["08:00","20:00"], UTC
    wall-clock slots). Wall-clock is the right choice for anything that should
    land at a particular hour; interval for "every N regardless of when".
    """
    denied = _require_admin_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    unit     = (data.get("unit") or "").strip()
    script   = data.get("script") or ""
    interval = data.get("interval")
    label    = data.get("label")
    times    = _parse_times(data.get("times"))
    if not unit or not script.strip() or (not interval and not times):
        return jsonify({"error": "Provide 'unit', 'script', and either 'interval' or 'times'"}), 400
    if data.get("times") and not times:
        return jsonify({"error": f"Couldn't parse times {data.get('times')!r} — expected e.g. [\"08:00\",\"20:00\"]"}), 400

    interval_seconds = None
    if not times:
        interval_seconds = _parse_duration(interval, None)
        if not interval_seconds or interval_seconds <= 0:
            return jsonify({"error": f"Couldn't parse interval '{interval}'"}), 400

    now = datetime.now(timezone.utc)
    job_id = str(uuid.uuid4())[:8]
    job = {
        "id": job_id, "unit": unit, "script": script, "label": label,
        "interval": None if times else interval,
        "interval_seconds": interval_seconds,
        "times": [f"{h:02d}:{m:02d}" for h, m in times] or None,
        "enabled": True, "created_at": now.isoformat(),
        "next_run": None, "last_run": None, "last_command_id": None,
    }
    _advance_job(job, now)
    with schedule_lock:
        scheduled_jobs[job_id] = job
    persist_schedule()
    when = f"at {', '.join(job['times'])} UTC" if times else f"every {interval}"
    print(f"📅 SCHEDULE CREATED: '{script[:60]}' on {unit} {when}")
    return jsonify({"result": "scheduled", "job": job})


@app.route("/api/schedule", methods=["GET"])
def list_schedule():
    """List all registered scheduled jobs."""
    denied = _require_admin_key()
    if denied:
        return denied
    with schedule_lock:
        jobs = sorted(scheduled_jobs.values(), key=lambda j: j["created_at"], reverse=True)
        return jsonify(jobs)


@app.route("/api/schedule/<job_id>", methods=["DELETE"])
def delete_schedule(job_id):
    """Remove a scheduled job."""
    denied = _require_admin_key()
    if denied:
        return denied
    with schedule_lock:
        job = scheduled_jobs.pop(job_id, None)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    persist_schedule()
    return jsonify({"result": "deleted", "id": job_id})


@app.route("/api/schedule/<job_id>/toggle", methods=["POST"])
def toggle_schedule(job_id):
    """Enable/disable a scheduled job without deleting it. Body: {enabled: bool}."""
    denied = _require_admin_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    with schedule_lock:
        job = scheduled_jobs.get(job_id)
        if not job:
            return jsonify({"error": "unknown job"}), 404
        job["enabled"] = bool(data.get("enabled", True))
        job = dict(job)
    persist_schedule()
    return jsonify({"result": "ok", "job": job})


# ── FLEET REFRESH ────────────────────────────────────────────────────────────
# The twice-daily housekeeping run (repo sync, package updates, docker prune)
# used to be a crontab on each unit, which meant nothing anywhere knew whether
# it had actually run: unit8's copy of the script was truncated to 0 bytes by a
# failed self-update on 2026-08-19 and failed silently twice a day for three
# days, and unit4 lost its copy in the rebuild and simply stopped refreshing.
# Locator now owns the schedule, so every run is a command_runs row and every
# failure is an event tagged with the unit it happened on.

REFRESH_LABEL  = "refresh"
REFRESH_SCRIPT = os.environ.get(
    "REFRESH_SCRIPT",
    # REFRESH_NO_FANOUT keeps each unit refreshing only itself — locator is what
    # fans out now. UNIT_NAME is passed explicitly because lokey's chroot does
    # not change the UTS namespace, so `hostname` inside it returns a container
    # id rather than the unit.
    'REFRESH_NO_FANOUT=1 UNIT_NAME={unit} "$HOME/.local/bin/refresh"',
)


def _refresh_script_for(unit):
    return REFRESH_SCRIPT.format(unit=unit)


def _refresh_jobs():
    """Registered schedule entries that are fleet-refresh jobs."""
    with schedule_lock:
        return [dict(j) for j in scheduled_jobs.values() if j.get("label") == REFRESH_LABEL]


@app.route("/api/refresh/status", methods=["GET"])
def refresh_status():
    """Per-unit refresh health: last outcome, when, how long, and what's next.

    Deliberately unauthenticated and output-free — it carries status, timings
    and exit codes but never script text or captured output, so the dashboard
    can render it without handing anyone the fleet's command history.
    """
    try:
        latest = db.latest_run_per_unit(REFRESH_LABEL)
    except Exception as e:
        print(f"⚠️  Failed to read refresh status: {e}")
        return jsonify({"error": "run history unavailable"}), 503

    now = datetime.now(timezone.utc)
    units = {}
    for job in _refresh_jobs():
        unit = job["unit"]
        entry = units.setdefault(unit, {"unit": unit})
        entry["scheduled"] = job.get("times") or job.get("interval")
        entry["enabled"]   = job.get("enabled", True)
        entry["next_run"]  = job.get("next_run")
    for unit, run in latest.items():
        entry = units.setdefault(unit, {"unit": unit})
        entry["last_run"] = run
        # Overdue = the last run we have is older than a full cycle. Late
        # answers "is this unit quietly not refreshing any more", which a
        # per-run failure alone does not.
        try:
            age_h = (now - datetime.fromisoformat(run["queued_at"])).total_seconds() / 3600
            entry["hours_since_last_run"] = round(age_h, 1)
        except (TypeError, ValueError, KeyError):
            pass

    healthy = [u for u, e in units.items() if (e.get("last_run") or {}).get("status") == "DONE"]
    return jsonify({
        "label": REFRESH_LABEL,
        "checked_at": now.isoformat(),
        "units": sorted(units.values(), key=lambda e: e["unit"]),
        "summary": {"units": len(units), "last_run_ok": len(healthy),
                    "last_run_not_ok": len(units) - len(healthy)},
    })


@app.route("/api/refresh/runs", methods=["GET"])
def refresh_runs():
    """Full run history including captured output. Admin-gated: the output of a
    refresh names repos, paths and package state."""
    denied = _require_admin_key()
    if denied:
        return denied
    unit  = request.args.get("unit")
    limit = min(int(request.args.get("limit", 50)), 500)
    label = request.args.get("label", REFRESH_LABEL)
    try:
        return jsonify(db.list_command_runs(unit=unit, label=(label or None), limit=limit))
    except Exception as e:
        print(f"⚠️  Failed to read run history: {e}")
        return jsonify({"error": "run history unavailable"}), 503


@app.route("/api/refresh/run", methods=["POST"])
def refresh_run_now():
    """Fire a refresh immediately. Body: {unit} for one, or {all: true} for
    every unit that has a refresh job registered."""
    denied = _require_admin_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    unit = (data.get("unit") or "").strip()
    if unit:
        units = [unit]
    elif data.get("all"):
        units = sorted({j["unit"] for j in _refresh_jobs() if j.get("enabled", True)})
    else:
        return jsonify({"error": "Provide 'unit' or 'all': true"}), 400
    if not units:
        return jsonify({"error": "no refresh jobs registered"}), 404
    queued = [_queue_exec_command(u, _refresh_script_for(u), source="manual",
                                  label=REFRESH_LABEL)
              for u in units]
    return jsonify({"result": "queued", "commands": queued})


@app.route("/api/idle/report", methods=["POST"])
def idle_report():
    """Lokey posts net-byte counters for its idle-watched containers each tick."""
    data = request.get_json(silent=True) or {}
    unit = data.get("unit")
    if not unit:
        return jsonify({"error": "unit required"}), 400
    now = datetime.now(timezone.utc)
    reported = set()
    with _idle_lock:
        for entry in data.get("containers", []):
            name  = entry.get("name")
            total = entry.get("net_bytes")
            if not name or total is None:
                continue
            # Substring match so compose-suffixed names stay covered
            # (the-beast-postgres-1, openvpn-client, pdns-db, ...)
            if any(p in name.lower() for p in _PINNED_NAMES):
                continue
            reported.add(name)
            timeout = _parse_duration(entry.get("timeout"), IDLE_DEFAULT_TIMEOUT)
            key = (unit, name)
            st = _idle_state.get(key)
            if st is None or total < st["last_bytes"]:
                # New to us, or counters reset (container restarted) — fresh clock
                _idle_state[key] = {"last_active": now, "last_bytes": total,
                                    "timeout": timeout, "last_report": now,
                                    "stopped_count": (st or {}).get("stopped_count", 0)}
                continue
            if total - st["last_bytes"] > IDLE_TRAFFIC_THRESHOLD:
                st["last_active"] = now
            st["last_bytes"]  = total
            st["timeout"]     = timeout
            st["last_report"] = now
        # Containers this unit no longer reports are stopped or unlabeled — drop them
        for key in [k for k in _idle_state if k[0] == unit and k[1] not in reported]:
            del _idle_state[key]
    return jsonify({"ok": True, "watched": len(reported)})


@app.route("/api/commands/pending", methods=["GET"])
def commands_pending():
    """Lokey polls this with its unit name; served commands move to DISPATCHED."""
    unit = request.args.get("unit")
    now = datetime.now(timezone.utc)
    out = []
    with command_lock:
        for cmd in command_queue.values():
            if unit and cmd["unit"] != unit:
                continue
            if cmd["status"] == "DISPATCHED":
                # Re-serve only if the lokey never reported back (crashed mid-command).
                # Exec jobs get the long window — see EXEC_RETRY_SECONDS — because
                # 3 minutes of silence from a refresh means "still working", not
                # "crashed", and re-serving would run a second copy alongside it.
                retry_after = (EXEC_RETRY_SECONDS if cmd.get("action") == "exec"
                               else COMMAND_RETRY_SECONDS)
                try:
                    age = (now - datetime.fromisoformat(cmd["dispatched_at"])).total_seconds()
                except (TypeError, ValueError):
                    age = retry_after + 1
                if age <= retry_after:
                    continue
            elif cmd["status"] != "PENDING":
                continue
            cmd["status"] = "DISPATCHED"
            cmd["dispatched_at"] = now.isoformat()
            out.append(dict(cmd))
    for cmd in out:
        if cmd.get("action") == "exec":
            _update_run(cmd)
    return jsonify(out)


EXEC_OUTPUT_CAP = 20000   # chars kept per stdout/stderr field


@app.route("/api/commands/complete", methods=["POST"])
def commands_complete():
    """Lokey reports command results; stop/start results update the registry,
    exec results just carry stdout/stderr/exit_code for later retrieval."""
    data = request.get_json(silent=True) or {}
    cmd_id  = data.get("id")
    success = bool(data.get("success"))
    now = datetime.now(timezone.utc)
    with command_lock:
        cmd = command_queue.get(cmd_id)
    if not cmd:
        # Not in memory — but if it is a recorded exec run, honour the report
        # anyway. Refreshing the unit that hosts locator redeploys locator
        # mid-run, so the result legitimately arrives after a restart that
        # emptied the queue; refusing it there would lose exactly the outcome
        # this is meant to capture. Anything genuinely unknown still 404s.
        try:
            known = db.get_command_run(cmd_id)
        except Exception as e:
            print(f"⚠️  Failed to look up command run {cmd_id}: {e}")
            known = None
        if not known:
            return jsonify({"error": "unknown command"}), 404
        late = {
            "id": cmd_id, "unit": known["unit"], "action": "exec",
            "label": known.get("label"), "source": known.get("source"),
            "script": known.get("script"), "job_id": known.get("job_id"),
            "queued_at": known.get("queued_at"), "dispatched_at": known.get("dispatched_at"),
            "completed_at": now.isoformat(),
            "status": "DONE" if success else "FAILED", "success": success,
            "stdout": str(data.get("stdout") or "")[:EXEC_OUTPUT_CAP],
            "stderr": str(data.get("stderr") or "")[:EXEC_OUTPUT_CAP],
            "exit_code": data.get("exit_code"),
        }
        print(f"{'✅' if success else '❌'} EXEC (late report) '{(late.get('label') or '')}' "
              f"on {late['unit']}: exit {late.get('exit_code')}")
        _update_run(late, error=None if success else "reported after a locator restart")
        _emit_run_event(late)
        return jsonify({"ok": True, "note": "recorded after locator restart"})

    with command_lock:
        cmd["status"] = "DONE" if success else "FAILED"
        cmd["success"] = success
        cmd["completed_at"] = now.isoformat()
        if cmd["action"] == "exec":
            cmd["stdout"]    = str(data.get("stdout") or "")[:EXEC_OUTPUT_CAP]
            cmd["stderr"]    = str(data.get("stderr") or "")[:EXEC_OUTPUT_CAP]
            cmd["exit_code"] = data.get("exit_code")
        cmd = dict(cmd)

    if cmd["action"] == "exec":
        print(f"{'✅' if success else '❌'} EXEC '{(cmd.get('script') or '')[:80]}' on {cmd['unit']}: "
              f"{'ok' if success else 'failed'} (exit {cmd.get('exit_code')})")
        duration_ms = None
        try:
            started = datetime.fromisoformat(cmd["dispatched_at"] or cmd["queued_at"])
            duration_ms = int((now - started).total_seconds() * 1000)
        except (TypeError, ValueError):
            pass
        _update_run(cmd, duration_ms=duration_ms)
        _emit_run_event(cmd, duration_ms=duration_ms)
        return jsonify({"ok": True})

    print(f"{'✅' if success else '❌'} COMMAND {cmd['action']} '{cmd.get('container')}' on {cmd['unit']}: {'ok' if success else 'failed'}")

    if success:
        with lock:
            _, svc = _find_service_entry(cmd.get("container"))
            if svc:
                if cmd["action"] == "stop":
                    svc["status"] = "OFFLINE"
                    svc["metadata"] = {**svc.get("metadata", {}),
                                       "idle_stopped": True,
                                       "idle_stopped_at": now.isoformat()}
                    if not svc.get("offline_since"):
                        svc["offline_since"] = now.isoformat()
                elif cmd["action"] == "start" and svc.get("metadata"):
                    svc["metadata"].pop("idle_stopped", None)
        persist_registry()
        if cmd["action"] == "stop" and cmd["source"] == "idle":
            with _idle_lock:
                st = _idle_state.get((cmd["unit"], cmd.get("container")))
                if st:
                    st["stopped_count"] += 1
    return jsonify({"ok": True})


def _find_service_entry(container):
    """Locate a container's registry entry — keys may be 'name' or 'name@host'.

    Prefers an ONLINE instance. The exact-key lookup used to win outright, which
    meant a stale bare-name record beat the live 'name@host' one: asking to stop
    'matomo' resolved to a record still attributed to unit1, so the command was
    queued for a node that no longer exists and the container kept running while
    the UI reported success.

    Caller must hold `lock`. Returns (key, svc) or (None, None).
    """
    candidates = []
    svc = registry["services"].get(container)
    if svc:
        candidates.append((container, svc))
    for key, s in registry["services"].items():
        if key == container:
            continue
        if key.split("@")[0] == container or s.get("name") == container:
            candidates.append((key, s))
    if not candidates:
        return None, None

    # An ONLINE instance is the one worth acting on; among equals prefer a
    # name@host key, since that names the host explicitly.
    #
    # Third key, freshest heartbeat first: duplicate records accumulate for one
    # container (bare name, name@host, name_host) from different discovery
    # paths and older hostname conventions, and they can ALL be OFFLINE - a
    # STOPPED container has no online record anywhere, which is exactly when
    # something wants to start it. With only the first two keys the choice
    # among equals fell to insertion order. For one service that picked between a
    # record attributed to unit1 (the dead laptop) and one to the pre-rename
    # host "BlackSheepUnit4", which no lokey polls under - either way the start
    # command was queued somewhere nothing would ever execute it, and the wake
    # silently did nothing while reporting success.
    def _hb_epoch(value):
        try:
            return datetime.fromisoformat(str(value)).timestamp()
        except (TypeError, ValueError):
            return 0.0

    def rank(item):
        key, s = item
        return (0 if s.get("status") == "ONLINE" else 1,
                0 if "@" in key else 1,
                -_hb_epoch(s.get("last_heartbeat")))

    candidates.sort(key=rank)
    return candidates[0]


def _find_container_unit(container):
    """Best-effort: which unit hosts this container?"""
    with _idle_lock:
        for unit, name in _idle_state:
            if name == container:
                return unit
    with lock:
        key, svc = _find_service_entry(container)
        if svc:
            unit = svc.get("host") or (svc.get("hosts") or [None])[0]
            if not unit and key and "@" in key:
                unit = key.split("@", 1)[1]
            return unit
    return None


@app.route("/api/idle/wake/<container>", methods=["POST"])
def idle_wake(container):
    """Queue a start command so the hosting unit's lokey wakes the container."""
    unit = _find_container_unit(container)
    if not unit:
        return jsonify({"error": f"unknown container '{container}'"}), 404
    cmd = _queue_command(unit, container, "start", source="wake")
    return jsonify({"ok": True, "command": cmd})


@app.route("/api/shutdown/<name>", methods=["POST"])
def shutdown_container(name):
    """Queue a stop command for a running container via lokey."""
    unit = _find_container_unit(name)
    if not unit:
        return jsonify({"error": f"unknown container '{name}'"}), 404
    cmd = _queue_command(unit, name, "stop", source="manual")
    return jsonify({"ok": True, "command": cmd})


# ── PUBLIC WAKE ─────────────────────────────────────────────────────────────
# A service that has been idle-stopped answers its front door with a 502, and
# whoever gets that 502 has no token and no way to get one — the login is
# often BEHIND the very service that is asleep. So /wake has to answer before
# authentication, or the whole wake-on-request design is unreachable from a
# browser. That is exactly what it had quietly become: wake_page sat at
# CLIENT, Traefik's errors middleware forwards only the visitor's own headers,
# and every anonymous hit came back {"error":"insufficient clearance"}.
#
# Opening it wholesale is not the answer either. Opting a container in here
# grants an anonymous caller exactly one verb — queue a `start` for a container
# ALREADY in the registry, deduped by _queue_command so a refresh cannot pile
# up work — and nothing else. No registry data is disclosed: see wake_page for
# why the page no longer reads /services/<name>.
PUBLIC_WAKE = {n.strip() for n in os.environ.get(
    "PUBLIC_WAKE", "forge,forge-relay,agent-0,rasa").split(",") if n.strip()}

# Hostnames that ARE locator. Anything else arriving at /wake got here through
# another service's Traefik errors middleware, which serves this page under the
# SLEEPING SERVICE's hostname, not ours. That distinction decides how the page
# checks back — see wake_page.
LOCATOR_HOSTS = {h.strip().lower() for h in os.environ.get(
    "LOCATOR_HOSTS",
    "locator.prime-quality.online,locator.theofficialblacksheepco.online",
).split(",") if h.strip()}

# Where ?to= may send a browser. prime-quality.online is here because forge
# lives on it: forge.theofficialblacksheepco.online was retired 2026-08-14 and
# has no cert, so without this the one hostname that answers was the one
# hostname the redirect refused.
WAKE_REDIRECT_RE = re.compile(
    r"^https://[a-z0-9.-]+\.(?:theofficialblacksheepco\.(?:com|info|online|store)"
    r"|prime-quality\.online)(?:/|$)")


def _is_locator_origin(host):
    """True when this request was addressed to locator itself."""
    host = (host or "").lower()
    bare = host.split(":")[0]
    if host in LOCATOR_HOSTS or bare in LOCATOR_HOSTS:
        return True
    if bare.split(".")[0] == "locator":
        return True
    # Traefik reaches us at http://100.99.131.20:50500 over the tailnet.
    return bool(bare) and bare.replace(".", "").isdigit()


def _wake_policy(container):
    """This container's wake stanza from locator.yml, or {}."""
    return load_policy().get(str(container).strip().lower(), {})


def _may_wake(container):
    """CLIENT and above may wake anything; anonymous only the opted-in.

    locator.yml is checked FIRST and is the real answer — it reloads on mtime
    change, so opting a new service in is a YAML edit rather than a rebuild of
    an image that has the list frozen inside it. PUBLIC_WAKE stays as the
    escape hatch for a container with no policy stanza at all.
    """
    principal = getattr(g, "principal", None)
    if principal is not None and principal.level >= clearance.CLIENT:
        return True
    if _wake_policy(container).get("public_wake"):
        return True
    return container in PUBLIC_WAKE


def _wake_companions(container):
    """Dependencies locator.yml says must come up with this container.

    Kept here rather than in each caller so a Traefik file or a link asks for
    ONE name: /wake/reech starts reech's database too, without reech.yml or the
    portal's HTML having to know that the database exists.
    """
    return [d for d in _wake_policy(container).get("wake_with", [])
            if d and d != container]


@app.route("/api/wake/triggers", methods=["GET"])
def wake_triggers():
    """Which container a trigger should wake, straight from locator.yml.

    This is the half that stops the mapping rotting. Before it, every entry
    point hardcoded a container name and a hostname of its own — the welcome
    card, the Traefik file, the frontend constant — and they drifted apart
    silently: a card still pointed at a hostname retired months earlier, and
    nothing anywhere would have told you. A page can now ASK:

        GET /api/wake/triggers?domain=search.theofficialblacksheepco.com
        -> {"domain": "...", "container": "searchsearcher-app", ...}

    and then GET /wake/<container>, so renaming a container or moving a
    hostname is a locator.yml edit and every entry point follows.

    Only containers carrying public_wake are listed. Everything here is
    already public by construction — a hostname a browser just visited and the
    container name it is allowed to wake — so there is nothing to redact, and
    no registry record is reachable through it.
    """
    # Look up by ANY trigger kind — ?domain=… or ?link=… — because the kinds
    # live in locator.yml, not in this function. A kind added to the YAML
    # tomorrow is queryable the same day with no code change here; hardcoding
    # `domain` was how the previous mapping calcified in the first place.
    query = {k.strip().lower(): v.strip().lower()
             for k, v in request.args.items() if v and v.strip()}

    # A caller passing a full URL for a domain should not have to remember to
    # strip it first.
    if "domain" in query:
        d = query["domain"]
        if "://" in d:
            d = d.split("://", 1)[1]
        query["domain"] = d.split("/")[0].split(":")[0]

    out = {}
    for name, cfg in load_policy().items():
        if not cfg.get("public_wake"):
            continue
        triggers = cfg.get("wake_triggers") or {}
        if query:
            matched = any(
                value in [t.lower() for t in triggers.get(kind, [])]
                for kind, value in query.items()
            )
            if not matched:
                continue
            return jsonify({
                "matched": query,
                "container": name,
                "wake_url": f"/wake/{name}",
                "wake_with": cfg.get("wake_with", []),
            })
        out[name] = {
            "triggers": triggers,
            "wake_with": cfg.get("wake_with", []),
            "wake_url": f"/wake/{name}",
        }
    if query:
        return jsonify({"matched": query, "container": None,
                        "error": "no container declares this trigger"}), 404
    return jsonify({"containers": out, "count": len(out)})



# Hosts that get the PuffBase slime wake page; everything else gets the
# generic BlackSheep realm page — the loading.jpg flock artwork, embedded so
# it still renders when the main site is the service that's down. Same split
# as the edge VCL synth and HAProxy be_wake.
_WAKE_PUFFBASE_HOST_RE = re.compile(
    r"(?i)(^|\.)puff-base\.com$|^puffbase\.prime-quality\.online$"
    r"|^puff\.dashboard\.prime-quality\.online$")

_WAKE_REALM_HTML = """<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Waking up</title>
<link rel="icon" href="https://www.theofficialblacksheepco.com/favicon.png">
<style>
  html, body { margin:0; height:100%; background:#000; overflow:hidden; }
  body { background:#000 url('data:image/jpeg;base64,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DRYxLQReMVplAWefiZAj6LECAAACEmp1bWIAAAAnanVtZGMyY2wAEQAQgAAAqgA4m3EDYzJwYS5jbGFpbS52MgAAAAHjY2JvcqVqaW5zdGFuY2VJRHgkMmI2MmI1MDgtY2M5MS0xZGFmLWZjYTAtNDNiYzRlZTM5OWY2dGNsYWltX2dlbmVyYXRvcl9pbmZvomRuYW1leCJHb29nbGUgQzJQQSBDb3JlIEdlbmVyYXRvciBMaWJyYXJ5Z3ZlcnNpb25zOTgzMjU4ODQ0Ojk4MzI1ODg0NHJjcmVhdGVkX2Fzc2VydGlvbnODomN1cmx4LXNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M2RoYXNoWCBDz0EFJn7uvMHSBBy3UTXMLwBhbHgn7YgnufvOe1g5lqJjdXJseCpzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjJkaGFzaFggWsQ+PDr/YhKf68EO/9Z0jEOdUV9rh+H2iXFDI7nGqlyiY3VybHgpc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGFkaGFzaFggAKuBodnpERAf3MC8orFTPFE06RfZ1RelWDdVbHGbADBpc2lnbmF0dXJleBlzZWxmI2p1bWJmPWMycGEuc2lnbmF0dXJlY2FsZ2ZzaGEyNTYAAAM2anVtYgAAAClqdW1kYzJhcwARABCAAACqADibcQNjMnBhLmFzc2VydGlvbnMAAAAAnGp1bWIAAAAoanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5oYXNoLmRhdGEAAAAAbGNib3KkamV4Y2x1c2lvbnOBomVzdGFydBRmbGVuZ3RoGRjKY2FsZ2ZzaGEyNTZkaGFzaFgg5zj4msKLzjCaY6bt0Q1ViWIsObLqyRsIu3hd/2oW5bpjcGFkTgAAAAAAAAAAAAAAAAAAAAAB+Gp1bWIAAAApanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5hY3Rpb25zLnYyAAAAAcdjYm9yoWdhY3Rpb25zgqRmYWN0aW9ubGMycGEuY3JlYXRlZGtkZXNjcmlwdGlvbnggQ3JlYXRlZCBieSBHb29nbGUgR2VuZXJhdGl2ZSBBSS5xZGlnaXRhbFNvdXJjZVR5cGV4Rmh0dHA6Ly9jdi5pcHRjLm9yZy9uZXdzY29kZXMvZGlnaXRhbHNvdXJjZXR5cGUvdHJhaW5lZEFsZ29yaXRobWljTWVkaWFqcGFyYW1ldGVyc6FraW5ncmVkaWVudHOBomN1cmx4LXNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M2RoYXNoWCBDz0EFJn7uvMHSBBy3UTXMLwBhbHgn7YgnufvOe1g5lqNmYWN0aW9ua2MycGEuZWRpdGVka2Rlc2NyaXB0aW9ueChBcHBsaWVkIGltcGVyY2VwdGlibGUgU3ludGhJRCB3YXRlcm1hcmsucWRpZ2l0YWxTb3VyY2VUeXBleEZodHRwOi8vY3YuaXB0Yy5vcmcvbmV3c2NvZGVzL2RpZ2l0YWxzb3VyY2V0eXBlL3RyYWluZWRBbGdvcml0aG1pY01lZGlhAAAAcWp1bWIAAAAsanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5pbmdyZWRpZW50LnYzAAAAAD1jYm9yomxyZWxhdGlvbnNoaXBnaW5wdXRUb2tkZXNjcmlwdGlvbnJJbnB1dCBpbmdyZWRpZW50IDAAACRNanVtYgAAAEdqdW1kYzJtYQARABCAAACqADibcQN1cm46YzJwYTozMDQ0OWI3YS0zZmU0LTRiMGMtNjc3Mi00OWM3MWExODllODUAAAAZOGp1bWIAAAAoanVtZGMyY3MAEQAQgAAAqgA4m3EDYzJwYS5zaWduYXR1cmUAAAAZCGNib3LShFkGKKIBJhghglkDPDCCAzgwggK/oAMCAQICE1TD4sn4dryMTmbpOpkyq0RK7hIwCgYIKoZIzj0EAwMwUTELMAkGA1UEBhMCVVMxEzARBgNVBAoMCkdvb2dsZSBMTEMxLTArBgNVBAMMJEdvb2dsZSBDMlBBIE1lZGlhIFNlcnZpY2VzIDFQIElDQSBHMzAeFw0yNjA0MTYxNDAwNDVaFw0yNzA0MTExNDAwNDRaMGsxCzAJBgNVBAYTAlVTMRMwEQYDVQQKEwpHb29nbGUgTExDMRwwGgYDVQQLExNHb29nbGUgU3lzdGVtIDY3MTU0MSkwJwYDVQQDEyBHb29nbGUgTWVkaWEgUHJvY2Vzc2luZyBTZXJ2aWNlczBZMBMGByqGSM49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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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MHJjcmVhdGVkX2Fzc2VydGlvbnODomN1cmx4LXNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M2RoYXNoWCA249JwWYLNcu4YhenR7axR+CrBfxyaq5KtXmwkb1TiGqJjdXJseCpzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjJkaGFzaFggHF614UHiknXcsElW3asZX4dZBJ6i/c0c5G6e3oRdTkKiY3VybHgpc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGFkaGFzaFggBf2SAxWH8sc0pDYoBfhtJGAP3nm6lh51R0PKcvp0Vs9pc2lnbmF0dXJleBlzZWxmI2p1bWJmPWMycGEuc2lnbmF0dXJlY2FsZ2ZzaGEyNTYAAAi0anVtYgAAAClqdW1kYzJhcwARABCAAACqADibcQNjMnBhLmFzc2VydGlvbnMAAAAAnGp1bWIAAAAoanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5oYXNoLmRhdGEAAAAAbGNib3KkamV4Y2x1c2lvbnOBomVzdGFydBghZmxlbmd0aBk9F2NhbGdmc2hhMjU2ZGhhc2hYIEM27qzXeJKq1fG7q/IAizSx8KX5pYvHkW4cZtUz7L9SY3BhZE0AAAAAAAAAAAAAAAAAAAABhGp1bWIAAAApanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5hY3Rpb25zLnYyAAAAAVNjYm9yoWdhY3Rpb25zg6JmYWN0aW9ua2MycGEub3BlbmVkanBhcmFtZXRlcnOha2luZ3JlZGllbnRzgaJjdXJseC1zZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNkaGFzaFggNuPScFmCzXLuGIXp0e2sUfgqwX8cmquSrV5sJG9U4hqjZmFjdGlvbmtjMnBhLmVkaXRlZGtkZXNjcmlwdGlvbndBZGRlZCB2aXNpYmxlIHdhdGVybWFya3FkaWdpdGFsU291cmNlVHlwZXg4aHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS9jb21wb3NpdGWiZmFjdGlvbm5jMnBhLmNvbnZlcnRlZGtkZXNjcmlwdGlvbnFDb252ZXJ0ZWQgdG8gLnBuZwAABmNqdW1iAAAALGp1bWRjYm9yABEAEIAAAKoAOJtxA2MycGEuaW5ncmVkaWVudC52MwAAAAYvY2JvcqRscmVsYXRpb25zaGlwaHBhcmVudE9mcXZhbGlkYXRpb25SZXN1bHRzoW5hY3RpdmVNYW5pZmVzdKNnZmFpbHVyZYBnc3VjY2Vzc4qiZGNvZGVzdGltZVN0YW1wLnZhbGlkYXRlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MmFiN2FlODUtYTVmOC0wOTYzLWQ3M2QtNDM2NGM0NzIxYWMyL2MycGEuc2lnbmF0dXJlomRjb2RlcXRpbWVTdGFtcC50cnVzdGVkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyYWI3YWU4NS1hNWY4LTA5NjMtZDczZC00MzY0YzQ3MjFhYzIvYzJwYS5zaWduYXR1cmWiZGNvZGV4IXNpZ25pbmdDcmVkZW50aWFsLm9jc3Aubm90UmV2b2tlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MmFiN2FlODUtYTVmOC0wOTYzLWQ3M2QtNDM2NGM0NzIxYWMyL2MycGEuc2lnbmF0dXJlomRjb2RleBlzaWduaW5nQ3JlZGVudGlhbC50cnVzdGVkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyYWI3YWU4NS1hNWY4LTA5NjMtZDczZC00MzY0YzQ3MjFhYzIvYzJwYS5zaWduYXR1cmWiZGNvZGV4HWNsYWltU2lnbmF0dXJlLmluc2lkZVZhbGlkaXR5Y3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyYWI3YWU4NS1hNWY4LTA5NjMtZDczZC00MzY0YzQ3MjFhYzIvYzJwYS5zaWduYXR1cmWiZGNvZGV4GGNsYWltU2lnbmF0dXJlLnZhbGlkYXRlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MmFiN2FlODUtYTVmOC0wOTYzLWQ3M2QtNDM2NGM0NzIxYWMyL2MycGEuc2lnbmF0dXJlomRjb2RleBlhc3NlcnRpb24uaGFzaGVkVVJJLm1hdGNoY3VybHhhc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyYWI3YWU4NS1hNWY4LTA5NjMtZDczZC00MzY0YzQ3MjFhYzIvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M6JkY29kZXgZYXNzZXJ0aW9uLmhhc2hlZFVSSS5tYXRjaGN1cmx4XnNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MmFiN2FlODUtYTVmOC0wOTYzLWQ3M2QtNDM2NGM0NzIxYWMyL2MycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjKiZGNvZGV4GWFzc2VydGlvbi5oYXNoZWRVUkkubWF0Y2hjdXJseF1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjJhYjdhZTg1LWE1ZjgtMDk2My1kNzNkLTQzNjRjNDcyMWFjMi9jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGGiZGNvZGV4GGFzc2VydGlvbi5kYXRhSGFzaC5tYXRjaGN1cmx4XXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MmFiN2FlODUtYTVmOC0wOTYzLWQ3M2QtNDM2NGM0NzIxYWMyL2MycGEuYXNzZXJ0aW9ucy9jMnBhLmhhc2guZGF0YW1pbmZvcm1hdGlvbmFsgG5hY3RpdmVNYW5pZmVzdKJjdXJseD5zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjJhYjdhZTg1LWE1ZjgtMDk2My1kNzNkLTQzNjRjNDcyMWFjMmRoYXNoWCBV0dwnjFOccg++l8bOMpWtFSIUBUCEHHg8QNTsixL3RG5jbGFpbVNpZ25hdHVyZaJjdXJseE1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjJhYjdhZTg1LWE1ZjgtMDk2My1kNzNkLTQzNjRjNDcyMWFjMi9jMnBhLnNpZ25hdHVyZWRoYXNoWCD0P44Xx13aXbnHdhbN9rEhkv4srOPRdE1L0CuhmQa6vwAAIT5qdW1iAAAAR2p1bWRjMm1hABEAEIAAAKoAOJtxA3VybjpjMnBhOmVkMmRhZDc4LWI3NDctMmViOC0xYmMxLTQ3MzMyNjc5NWYxZgAAABMBanVtYgAAAChqdW1kYzJjcwARABCAAACqADibcQNjMnBhLnNpZ25hdHVyZQAAABLRY2JvctKE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anVtYmY9YzJwYS5zaWduYXR1cmVjYWxnZnNoYTI1NgAAC35qdW1iAAAAKWp1bWRjMmFzABEAEIAAAKoAOJtxA2MycGEuYXNzZXJ0aW9ucwAAAACcanVtYgAAAChqdW1kY2JvcgARABCAAACqADibcQNjMnBhLmhhc2guZGF0YQAAAABsY2JvcqRqZXhjbHVzaW9uc4GiZXN0YXJ0FGZsZW5ndGgZXlVjYWxnZnNoYTI1NmRoYXNoWCC7J93ulrhIvLG6u6WgSCAmFkae1P1fsKdmZEwyEvhSv2NwYWROAAAAAAAAAAAAAAAAAAAAAAJWanVtYgAAAClqdW1kY2JvcgARABCAAACqADibcQNjMnBhLmFjdGlvbnMudjIAAAACJWNib3KhZ2FjdGlvbnOCpGZhY3Rpb25sYzJwYS5jcmVhdGVka2Rlc2NyaXB0aW9ueCBDcmVhdGVkIGJ5IEdvb2dsZSBHZW5lcmF0aXZlIEFJLnFkaWdpdGFsU291cmNlVHlwZXhGaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS90cmFpbmVkQWxnb3JpdGhtaWNNZWRpYWpwYXJhbWV0ZXJzoWtpbmdyZWRpZW50c4KiY3VybHgtc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzZGhhc2hYIEPPQQUmfu68wdIEHLdRNcwvAGFseCftiCe5+857WDmWomN1cmx4MHNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fMWRoYXNoWCBwt1VyOx3VB4COYjR9l7yW5/Lzh2ZJjNd4jL1GTMyHaKNmYWN0aW9ua2MycGEuZWRpdGVka2Rlc2NyaXB0aW9ueChBcHBsaWVkIGltcGVyY2VwdGlibGUgU3ludGhJRCB3YXRlcm1hcmsucWRpZ2l0YWxTb3VyY2VUeXBleEZodHRwOi8vY3YuaXB0Yy5vcmcvbmV3c2NvZGVzL2RpZ2l0YWxzb3VyY2V0eXBlL3RyYWluZWRBbGdvcml0aG1pY01lZGlhAAAH6mp1bWIAAAAvanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5pbmdyZWRpZW50LnYzX18xAAAAB7NjYm9ypmlkYzpmb3JtYXRpaW1hZ2UvcG5nbHJlbGF0aW9uc2hpcGdpbnB1dFRvcXZhbGlkYXRpb25SZXN1bHRzom5hY3RpdmVNYW5pZmVzdKNnZmFpbHVyZYBnc3VjY2Vzc4uiZGNvZGVzdGltZVN0YW1wLnZhbGlkYXRlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MzA0NDliN2EtM2ZlNC00YjBjLTY3NzItNDljNzFhMTg5ZTg1L2MycGEuc2lnbmF0dXJlomRjb2RlcXRpbWVTdGFtcC50cnVzdGVkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTozMDQ0OWI3YS0zZmU0LTRiMGMtNjc3Mi00OWM3MWExODllODUvYzJwYS5zaWduYXR1cmWiZGNvZGV4IXNpZ25pbmdDcmVkZW50aWFsLm9jc3Aubm90UmV2b2tlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MzA0NDliN2EtM2ZlNC00YjBjLTY3NzItNDljNzFhMTg5ZTg1L2MycGEuc2lnbmF0dXJlomRjb2RleBlzaWduaW5nQ3JlZGVudGlhbC50cnVzdGVkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTozMDQ0OWI3YS0zZmU0LTRiMGMtNjc3Mi00OWM3MWExODllODUvYzJwYS5zaWduYXR1cmWiZGNvZGV4HWNsYWltU2lnbmF0dXJlLmluc2lkZVZhbGlkaXR5Y3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTozMDQ0OWI3YS0zZmU0LTRiMGMtNjc3Mi00OWM3MWExODllODUvYzJwYS5zaWduYXR1cmWiZGNvZGV4GGNsYWltU2lnbmF0dXJlLnZhbGlkYXRlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MzA0NDliN2EtM2ZlNC00YjBjLTY3NzItNDljNzFhMTg5ZTg1L2MycGEuc2lnbmF0dXJlomRjb2RleBlhc3NlcnRpb24uaGFzaGVkVVJJLm1hdGNoY3VybHhhc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTozMDQ0OWI3YS0zZmU0LTRiMGMtNjc3Mi00OWM3MWExODllODUvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M6JkY29kZXgZYXNzZXJ0aW9uLmhhc2hlZFVSSS5tYXRjaGN1cmx4XnNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MzA0NDliN2EtM2ZlNC00YjBjLTY3NzItNDljNzFhMTg5ZTg1L2MycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjKiZGNvZGV4GWFzc2VydGlvbi5oYXNoZWRVUkkubWF0Y2hjdXJseF1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjMwNDQ5YjdhLTNmZTQtNGIwYy02NzcyLTQ5YzcxYTE4OWU4NS9jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGGiZGNvZGV4I2luZ3JlZGllbnQuY2xhaW1TaWduYXR1cmUudmFsaWRhdGVkY3VybHhhc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTozMDQ0OWI3YS0zZmU0LTRiMGMtNjc3Mi00OWM3MWExODllODUvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M6JkY29kZXgYYXNzZXJ0aW9uLmRhdGFIYXNoLm1hdGNoY3VybHhdc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTozMDQ0OWI3YS0zZmU0LTRiMGMtNjc3Mi00OWM3MWExODllODUvYzJwYS5hc3NlcnRpb25zL2MycGEuaGFzaC5kYXRhbWluZm9ybWF0aW9uYWyAcGluZ3JlZGllbnREZWx0YXOBonZpbmdyZWRpZW50QXNzZXJ0aW9uVVJJeGFzZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjMwNDQ5YjdhLTNmZTQtNGIwYy02NzcyLTQ5YzcxYTE4OWU4NS9jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzcHZhbGlkYXRpb25EZWx0YXOjZ2ZhaWx1cmWAZ3N1Y2Nlc3OAbWluZm9ybWF0aW9uYWyAbmFjdGl2ZU1hbmlmZXN0omN1cmx4PnNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MzA0NDliN2EtM2ZlNC00YjBjLTY3NzItNDljNzFhMTg5ZTg1ZGhhc2hYIG4gwcSJwzvZRMqlGvN+rOQU7A/KyjIFKitrJ5/RhHYgbmNsYWltU2ln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Ojk4MjUzNTA5NHJjcmVhdGVkX2Fzc2VydGlvbnODomN1cmx4LXNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M2RoYXNoWCBz+LWLZqqABERMZuHrXz/l1x4L62u5ZtkcfOKT082fsqJjdXJseCpzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjJkaGFzaFggWpWBTXFxXAAep1WQ10IZl04nRm2sbIQMlhaSYHLDrZyiY3VybHgpc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGFkaGFzaFgg8rxlBeQUoIwSaSIdYUtJIUNZ6BaKZMg+c7qMOpI/0oZpc2lnbmF0dXJleBlzZWxmI2p1bWJmPWMycGEuc2lnbmF0dXJlY2FsZ2ZzaGEyNTYAAAukanVtYgAAAClqdW1kYzJhcwARABCAAACqADibcQNjMnBhLmFzc2VydGlvbnMAAAAAnGp1bWIAAAAoanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5oYXNoLmRhdGEAAAAAbGNib3KkamV4Y2x1c2lvbnOBomVzdGFydBkPuGZsZW5ndGgZf1hjYWxnZnNoYTI1NmRoYXNoWCB9rcaASVZdrFX4cP3uwiIhiH3ALPvwssWPwUHkYM686WNwYWRMAAAAAAAAAAAAAAAAAAABzmp1bWIAAAApanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5hY3Rpb25zLnYyAAAAAZ1jYm9yoWdhY3Rpb25zgqNmYWN0aW9ua2MycGEub3BlbmVka2Rlc2NyaXB0aW9ucE9wZW5lZCBieSBHb29nbGVqcGFyYW1ldGVyc6FraW5ncmVkaWVudHOBomN1cmx4LXNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M2RoYXNoWCBz+LWLZqqABERMZuHrXz/l1x4L62u5ZtkcfOKT082fsqNmYWN0aW9ub2MycGEudHJhbnNjb2RlZHFkaWdpdGFsU291cmNlVHlwZXhGaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS9hbGdvcml0aG1pY2FsbHlFbmhhbmNlZGpwYXJhbWV0ZXJzoWtpbmdyZWRpZW50c4GiY3VybHgtc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzZGhhc2hYIHP4tYtmqoAERExm4etfP+XXHgvra7lm2Rx84pPTzZ+yAAAJCWp1bWIAAAAsanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5pbmdyZWRpZW50LnYzAAAACNVjYm9ypWlkYzpmb3JtYXRqaW1hZ2UvanBlZ2xyZWxhdGlvbnNoaXBocGFyZW50T2ZxdmFsaWRhdGlvblJlc3VsdHOibmFjdGl2ZU1hbmlmZXN0o2dmYWlsdXJlgGdzdWNjZXNzjKJkY29kZXN0aW1lU3RhbXAudmFsaWRhdGVkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTplZDJkYWQ3OC1iNzQ3LTJlYjgtMWJjMS00NzMzMjY3OTVmMWYvYzJwYS5zaWduYXR1cmWiZGNvZGVxdGltZVN0YW1wLnRydXN0ZWRjdXJseE1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOmVkMmRhZDc4LWI3NDctMmViOC0xYmMxLTQ3MzMyNjc5NWYxZi9jMnBhLnNpZ25hdHVyZaJkY29kZXghc2lnbmluZ0NyZWRlbnRpYWwub2NzcC5ub3RSZXZva2VkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTplZDJkYWQ3OC1iNzQ3LTJlYjgtMWJjMS00NzMzMjY3OTVmMWYvYzJwYS5zaWduYXR1cmWiZGNvZGV4GXNpZ25pbmdDcmVkZW50aWFsLnRydXN0ZWRjdXJseE1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOmVkMmRhZDc4LWI3NDctMmViOC0xYmMxLTQ3MzMyNjc5NWYxZi9jMnBhLnNpZ25hdHVyZaJkY29kZXgdY2xhaW1TaWduYXR1cmUuaW5zaWRlVmFsaWRpdHljdXJseE1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOmVkMmRhZDc4LWI3NDctMmViOC0xYmMxLTQ3MzMyNjc5NWYxZi9jMnBhLnNpZ25hdHVyZaJkY29kZXgYY2xhaW1TaWduYXR1cmUudmFsaWRhdGVkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTplZDJkYWQ3OC1iNzQ3LTJlYjgtMWJjMS00NzMzMjY3OTVmMWYvYzJwYS5zaWduYXR1cmWiZGNvZGV4GWFzc2VydGlvbi5oYXNoZWRVUkkubWF0Y2hjdXJseGFzZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOmVkMmRhZDc4LWI3NDctMmViOC0xYmMxLTQ3MzMyNjc5NWYxZi9jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzomRjb2RleBlhc3NlcnRpb24uaGFzaGVkVVJJLm1hdGNoY3VybHhkc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTplZDJkYWQ3OC1iNzQ3LTJlYjgtMWJjMS00NzMzMjY3OTVmMWYvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fMaJkY29kZXgZYXNzZXJ0aW9uLmhhc2hlZFVSSS5tYXRjaGN1cmx4XnNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6ZWQyZGFkNzgtYjc0Ny0yZWI4LTFiYzEtNDczMzI2Nzk1ZjFmL2MycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjKiZGNvZGV4GWFzc2VydGlvbi5oYXNoZWRVUkkubWF0Y2hjdXJseF1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOmVkMmRhZDc4LWI3NDctMmViOC0xYmMxLTQ3MzMyNjc5NWYxZi9jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGGiZGNvZGV4I2luZ3JlZGllbnQuY2xhaW1TaWduYXR1cmUudmFsaWRhdGVkY3VybHhkc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTplZDJkYWQ3OC1iNzQ3LTJlYjgtMWJjMS00NzMzMjY3OTVmMWYvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fMaJkY29kZXgYYXNzZXJ0aW9uLmRhdGFIYXNoLm1hdGNoY3VybHhdc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTplZDJkYWQ3OC1iNzQ3LTJlYjgtMWJjMS00NzMzMjY3OTVmMWYvYzJwYS5hc3NlcnRpb25zL2MycGEuaGFzaC5kYXRhbWluZm9ybWF0aW9uYWyAcGluZ3JlZGllbnREZWx0YXOConZpbmdyZWRpZW50QXNzZXJ0aW9uVVJJeGRzZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOmVkMmRhZDc4LWI3NDctMmViOC0xYmMxLTQ3MzMyNjc5NWYxZi9jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzX18xcHZhbGlkYXRpb25EZWx0YXOjZ2ZhaWx1cmWAZ3N1Y2Nlc3OAbWluZm9ybWF0aW9uYWyAonZpbmdyZWRpZW50QXNzZXJ0aW9uVVJJeGFzZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjMwNDQ5YjdhLTNmZTQtNGIwYy02NzcyLTQ5YzcxYTE4OWU4NS9jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzcHZhbGlkYXRpb25EZWx0YXOjZ2ZhaWx1cmWAZ3N1Y2Nlc3OAbWluZm9ybWF0aW9uYWyAbmFjdGl2ZU1hbmlmZXN0omN1cmx4PnNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6ZWQyZGFkNzgtYjc0Ny0yZWI4LTFiYzEtNDczMzI2Nzk1ZjFmZGhhc2hYIA88pq972OvDGWVfwzNRW00CcuV4vrjVSbfllK87YLGYbmNsYWltU2lnbmF0dXJlomN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6ZWQyZGFkNzgtYjc0Ny0yZWI4LTFiYzEtNDczMzI2Nzk1ZjFmL2MycGEuc2lnbmF0dXJlZGhhc2hYIEE0GLOyIlxUSpD0ISnSuZlbnzE2ual5B+g050x3VD9Z/9sAhAADAgIKCgoKCgoKEAoKEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAQMEBAYFBgoGBgoPDQoNDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ3/wAARCAMABWADASIAAhEBAxEB/8QAHQAAAgIDAQEBAAAAAAAAAAAAAwQCBQEGBwAICf/EAFoQAAECAwUEBwUGBAMGBAMBEQECEQADIQQSMUFRBSJhcQYHEzKBkaFCscHR8AgUI1Ji4TNygvFDkqIVJFNjc7IJg7PCNJOj0hYlRFQXGMPiRWR0lLTTJoTE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) center/cover no-repeat fixed;
         display:flex; align-items:flex-end; justify-content:center; }
  .sub { font-family:Georgia,'Times New Roman',serif; font-size:12px;
         letter-spacing:.26em; text-transform:uppercase; color:#c9a25e;
         padding:0 16px 5vh; text-align:center;
         text-shadow:0 1px 8px rgba(0,0,0,.9); }
</style></head>
<body>
  <div class="sub" id="status">__CONTAINER__ is waking up</div>

<script>
  // The artwork is the page; this script is the machinery — keep it when the
  // design changes. Served under the sleeping service's own URL, so reloading
  // IS the health check: the service answers for itself once it's up.
  const target = __TARGET__;
  const ownOrigin = __OWN_ORIGIN__;
  const RETRY_MS = 5000;
  const MAX_TRIES = 48;              // 4 minutes, then stop and say so
  const el = document.getElementById("status");
  let tries = 0;

  function gaveUp() {
    el.textContent = "still starting after "
      + Math.round(MAX_TRIES * RETRY_MS / 60000) + " min — reload to keep waiting";
  }

  // Served under the sleeping service's own hostname: the retry IS the
  // service answering for itself, so just ask for this URL again.
  function retryHere() {
    if (++tries > MAX_TRIES) return gaveUp();
    el.textContent = "__CONTAINER__ is waking up — " + tries + " / " + MAX_TRIES;
    setTimeout(() => location.reload(), RETRY_MS);
  }

  // On locator's own origin the registry is same-origin and the caller is
  // already authenticated, so watch the record flip and follow the target.
  async function poll() {
    if (++tries > MAX_TRIES) return gaveUp();
    try {
      const r = await fetch("/services/__CONTAINER__");
      if (r.ok) {
        const svc = await r.json();
        if (svc.status === "ONLINE") {
          el.textContent = "awake — redirecting…";
          if (target) { location.href = target; return; }
          el.textContent = "awake ✓";
          return;
        }
      }
    } catch (e) {}
    el.textContent = "__CONTAINER__ is waking up — " + tries + " / " + MAX_TRIES;
    setTimeout(poll, RETRY_MS);
  }

  if (ownOrigin) { poll(); } else { retryHere(); }
</script></body></html>"""

@app.route("/wake/<container>", methods=["GET"])
def wake_page(container):
    """Click-to-wake: queue the start command and show a page that comes back
    once the service is up.

    Accepts a COMMA-SEPARATED list ("reech,reech-oauth") so one request wakes a
    service together with the dependencies it calls directly -- ones reached
    over the docker network or tailnet rather than through Traefik, so no HTTP
    request ever passes through them and nothing in the request path can wake
    them on its own. (The LLM backend is llama.cpp under systemd on unit7 and
    is never idle-stopped, so nothing needs waking for it.)

    The FIRST name is the primary: it is what gets displayed, waited on, and
    redirected to. The rest are started silently.

    HOW THE PAGE CHECKS BACK, and why it depends on who asked. Served through
    a Traefik errors middleware, this HTML is returned as the body of the
    sleeping service's OWN response — the browser's address bar still reads
    https://forge.prime-quality.online/. A relative fetch("/services/forge")
    from there does not reach locator at all; it goes back to forge's router,
    which is the thing that is down. That is a second break, independent of the
    clearance one: the old poll could not have worked from a foreign host even
    with a token. So in that case the page simply RE-REQUESTS the original URL
    — no cross-origin call, no CORS, no credentials, and the retry is the real
    service answering for itself. Only when the visitor is on locator's own
    origin (the dashboard) does it poll /services/<name> and follow `target`,
    which is where that endpoint is same-origin and the caller is already
    authenticated above CUSTOMER.
    """
    names = [n.strip() for n in str(container).split(",") if n.strip()]
    if names:
        container = names[0]
    # Gate the primary BEFORE queueing anything, so a name nobody opted in
    # cannot be started by an anonymous caller as a side effect.
    if not _may_wake(container):
        return Response(f"'{container}' is not publicly wakeable",
                        status=403, mimetype="text/plain")
    # Explicit extras from the URL, plus whatever locator.yml says travels with
    # this container. The policy list is the one that should grow over time —
    # a caller naming its own dependencies has to be updated everywhere it is
    # written down, which is the failure this whole change is undoing.
    extras = list(names[1:])
    for dep in _wake_companions(container):
        if dep not in extras:
            extras.append(dep)
    for extra in extras:
        if not _may_wake(extra):
            continue
        extra_unit = _find_container_unit(extra)
        # A dependency that is unknown to the registry must never block the
        # primary from waking - best effort, and the primary still proceeds.
        if extra_unit:
            _queue_command(extra_unit, extra, "start", source="wake")
    unit = _find_container_unit(container)
    if not unit:
        return Response(f"Unknown container '{container}'", status=404)
    _queue_command(unit, container, "start", source="wake")
    # Optional explicit redirect target (?to=...), restricted to our own domains
    target = request.args.get("to", "")
    if target and not WAKE_REDIRECT_RE.match(target):
        target = ""
    if not target:
        with lock:
            _, svc = _find_service_entry(container)
            target = (svc or {}).get("url", "") or ""
    own_origin = _is_locator_origin(request.host)
    host = (request.host or "").split(":")[0]
    if not _WAKE_PUFFBASE_HOST_RE.search(host):
        return Response(_WAKE_REALM_HTML
                        .replace("__CONTAINER__", container)
                        .replace("__TARGET__", json.dumps(target))
                        .replace("__OWN_ORIGIN__",
                                 json.dumps(bool(own_origin))),
                        mimetype="text/html")
    emblem = "data:image/webp;base64,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"
    html = f"""<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Waking up</title>
<style>
  html, body {{ margin:0; height:100%; overflow:hidden; }}
  body {{ background: radial-gradient(120% 90% at 50% 0%, #241040 0%, #12071f 55%, #0a0512 100%);
         display:flex; flex-direction:column; align-items:center; justify-content:center;
         font-family: ui-sans-serif, system-ui, sans-serif; }}
  .stage {{ position:relative; }}
  .emblem {{ width:min(46vw, 300px); display:block; position:relative; z-index:2;
            filter: drop-shadow(0 0 28px rgba(126,34,206,.55)); }}
  /* drips hang off the emblem's lower half — generated in JS. Each is a
     tapered strand + bulb tip that stretches, then detaches and falls. */
  .drips {{ position:absolute; left:8%; right:8%; top:72%; height:0; z-index:1; }}
  .drip {{ position:absolute; top:0; transform-origin:top center; }}
  .drip .strand {{ width:100%; border-radius:0 0 999px 999px;
    background:linear-gradient(#8b3df0 0%, #6d28d9 55%, #4c1d95 100%);
    box-shadow: inset -2px 0 3px rgba(255,255,255,.18), inset 2px 0 4px rgba(10,4,20,.5); }}
  .drip .tip {{ position:absolute; left:50%; bottom:-4px; transform:translateX(-50%);
    border-radius:50%;
    background:radial-gradient(circle at 35% 30%, #a855f7, #5b21b6 70%); }}
  @keyframes stretch {{ 0%,100% {{ transform:scaleY(.82); }} 50% {{ transform:scaleY(1.06); }} }}
  @keyframes drop {{
    0%   {{ transform:translateY(0) scale(1);   opacity:1; }}
    70%  {{ transform:translateY(0) scale(1);   opacity:1; }}
    100% {{ transform:translateY(46vh) scale(.6); opacity:0; }}
  }}
  .drip.falling {{ animation: drop 1.4s cubic-bezier(.55,0,.9,.4) forwards; }}
  .sub {{ margin-top:11vh; font-size:12px; letter-spacing:.3em; text-transform:uppercase;
         color:#b6f34c; text-align:center; padding:0 18px;
         text-shadow:0 0 14px rgba(182,243,76,.35); }}
  .hint {{ margin-top:10px; font-size:10px; letter-spacing:.18em; text-transform:uppercase;
           color:#6d5b93; text-align:center; }}
</style></head>
<body>
  <div class="stage">
    <img class="emblem" alt="PuffBase" src="{emblem}">
    <div class="drips" id="drips"></div>
  </div>
  <div class="sub" id="status">{container} is starting on {unit}</div>
  <div class="hint">the slime is warming back up — hold tight</div>
<script>
  const dripsEl = document.getElementById("drips");
  const N = 16;
  const strands = [];
  for (let i = 0; i < N; i++) {{
    const w = 6 + Math.random() * 18;
    const len = 22 + Math.random() * 120;
    const d = document.createElement("div");
    d.className = "drip";
    d.style.left = (Math.random() * 100) + "%";
    d.style.width = w + "px";
    d.style.marginLeft = (-w / 2) + "px";
    const strand = document.createElement("div");
    strand.className = "strand";
    strand.style.height = len + "px";
    strand.style.animation = `stretch ${{2.4 + Math.random() * 2.8}}s ease-in-out ${{Math.random() * 2}}s infinite`;
    const tip = document.createElement("div");
    tip.className = "tip";
    const ts = w * (1.5 + Math.random() * .7);
    tip.style.width = ts + "px";
    tip.style.height = ts + "px";
    strand.appendChild(tip);
    d.appendChild(strand);
    dripsEl.appendChild(d);
    strands.push(d);
  }}
  setInterval(() => {{
    const d = strands[Math.floor(Math.random() * strands.length)];
    if (d.classList.contains("falling")) return;
    d.classList.add("falling");
    setTimeout(() => {{
      d.classList.remove("falling");
      const w = 6 + Math.random() * 18;
      const len = 22 + Math.random() * 120;
      d.style.left = Math.random() * 100 + "%";
      d.style.width = w + "px";
      d.style.marginLeft = (-w / 2) + "px";
      const s = d.firstChild;
      s.style.height = len + "px";
      const t = s.firstChild;
      const ts = w * (1.5 + Math.random() * .7);
      t.style.width = ts + "px";
      t.style.height = ts + "px";
    }}, 1500);
  }}, 2400);
</script>
<script>
  const target = {json.dumps(target)};
  const ownOrigin = {json.dumps(bool(own_origin))};
  const RETRY_MS = 5000;
  const MAX_TRIES = 48;              // 4 minutes, then stop and say so
  const el = document.getElementById("status");
  let tries = 0;

  function gaveUp() {{
    el.textContent = "still starting after "
      + Math.round(MAX_TRIES * RETRY_MS / 60000) + " min — reload to keep waiting";
  }}

  // Served under the sleeping service's own hostname: the retry IS the
  // service answering for itself, so just ask for this URL again.
  function retryHere() {{
    if (++tries > MAX_TRIES) return gaveUp();
    el.textContent = "waiting for {container} — retry " + tries + " of " + MAX_TRIES;
    setTimeout(() => location.reload(), RETRY_MS);
  }}

  // On locator's own origin the registry is same-origin and the caller is
  // already authenticated, so watch the record flip and follow the target.
  async function poll() {{
    if (++tries > MAX_TRIES) return gaveUp();
    try {{
      const r = await fetch("/services/{container}");
      if (r.ok) {{
        const svc = await r.json();
        if (svc.status === "ONLINE") {{
          el.textContent = "awake — redirecting…";
          if (target) {{ location.href = target; return; }}
          el.textContent = "awake ✓";
          return;
        }}
      }}
    }} catch (e) {{}}
    el.textContent = "waiting for {container} — check " + tries + " of " + MAX_TRIES;
    setTimeout(poll, RETRY_MS);
  }}

  if (ownOrigin) {{ poll(); }} else {{ retryHere(); }}
</script></body></html>"""
    return Response(html, mimetype="text/html")


def idle_reaper():
    """Queues stop commands for containers idle past their timeout."""
    while True:
        time.sleep(IDLE_CHECK_INTERVAL)
        now = datetime.now(timezone.utc)
        try:
            with _idle_lock:
                snapshot = {k: dict(v) for k, v in _idle_state.items()}
            for (unit, name), st in snapshot.items():
                # Skip stale entries — that unit's lokey hasn't reported recently
                if (now - st["last_report"]).total_seconds() > IDLE_CHECK_INTERVAL * 5:
                    continue
                idle_for = (now - st["last_active"]).total_seconds()
                if idle_for < st["timeout"]:
                    continue
                print(f"💤 IDLE: '{name}' on {unit} quiet {int(idle_for / 60)}m "
                      f"(limit {int(st['timeout'] / 60)}m) — queueing stop")
                _queue_command(unit, name, "stop", source="idle")
        except Exception as e:
            print(f"⚠️ Error in idle reaper: {e}")


# ── CERT EXPIRY TRACKING ────────────────────────────────────────────────────
# Lokeys check the TLS cert of every hostname their unit routes and report
# here. Traefik handles renewal itself; this surfaces silent failures.

CERT_WARN_DAYS = int(os.environ.get("CERT_WARN_DAYS", 21))
_cert_state: dict = {}   # unit -> {"reported_at": iso, "certs": [...]}
_cert_lock = threading.Lock()

# Cert state is the ONLY input to renewals.py's mTLS inventory, and lokey only
# pushes it every CERT_CHECK_TICKS (~6h). Held purely in memory, every locator
# restart blanked it and the hourly credential renewer then saw zero mesh
# leaves for up to six hours -- which is how unit8-mesh reached 2 days from
# expiry under a rule that is supposed to reissue at 7. Persist it like the
# registry and the schedule.
CERT_STATE_FILE = os.path.join(DATA_DIR, "cert_state.json")
# A report older than this is not trustworthy enough to renew from; the unit
# has almost certainly changed since. Dropped on load rather than aged.
CERT_STATE_MAX_AGE_DAYS = 7


def persist_cert_state():
    """Write _cert_state to disk so the renewal inventory survives a restart."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with _cert_lock:
            snapshot = json.dumps(_cert_state, indent=2)
        tmp = CERT_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            f.write(snapshot)
        os.replace(tmp, CERT_STATE_FILE)
    except Exception as e:
        print(f"WARN Failed to persist cert state: {e}")


def load_cert_state():
    """Reload cert state on startup, ageing days_left by the time we were down.

    days_left is a snapshot taken when the unit reported, so a stale entry
    overstates the remaining life by exactly the time since reported_at. Ageing
    it here keeps the 7-day renewal decision honest instead of resetting the
    clock on every restart. Entries too old to trust are dropped, and the next
    lokey report replaces them wholesale anyway.
    """
    if not os.path.exists(CERT_STATE_FILE):
        return
    try:
        with open(CERT_STATE_FILE) as f:
            saved = json.load(f)
        now = datetime.now(timezone.utc)
        loaded = aged = 0
        with _cert_lock:
            for unit, info in (saved or {}).items():
                try:
                    reported = datetime.fromisoformat(info["reported_at"])
                except (TypeError, ValueError, KeyError):
                    continue
                days_down = (now - reported).total_seconds() / 86400.0
                if days_down > CERT_STATE_MAX_AGE_DAYS:
                    continue
                certs = []
                for c in info.get("certs") or []:
                    c = dict(c)
                    if isinstance(c.get("days_left"), (int, float)):
                        c["days_left"] = int(c["days_left"] - days_down)
                        aged += 1
                    certs.append(c)
                _cert_state[unit] = {"reported_at": info["reported_at"], "certs": certs}
                loaded += 1
        if loaded:
            print(f"cert state restored: {loaded} unit(s), {aged} cert(s) aged forward")
    except Exception as e:
        print(f"WARN Failed to load cert state: {e}")


@app.route("/api/certs/report", methods=["POST"])
def certs_report():
    data = request.get_json(silent=True) or {}
    unit = data.get("unit")
    if not unit:
        return jsonify({"error": "unit required"}), 400
    certs = data.get("certs", [])
    with _cert_lock:
        _cert_state[unit] = {
            "reported_at": datetime.now(timezone.utc).isoformat(),
            "certs": certs,
        }
    persist_cert_state()
    for c in certs:
        if c.get("error") or (c.get("days_left") is not None and c["days_left"] < CERT_WARN_DAYS):
            print(f"🔐 CERT WARNING [{unit}] {c.get('host')}: "
                  f"{c.get('error') or str(c.get('days_left')) + ' days left'}")
    return jsonify({"ok": True, "received": len(certs)})


@app.route("/api/certs/issue", methods=["POST"])
def certs_issue():
    """Mint an internal mTLS leaf from the fleet PKI. Admin key required.

    This is the issue-side counterpart to /api/secrets/resolve: lokey (or a
    node bootstrapping its edge) posts a role + CN and gets back a freshly
    signed cert+key, so the broker token that can talk to OpenBao's PKI lives
    ONLY here — no node ever holds it, exactly as with the KV broker.

    Body:
      {"role": "haproxy-client", "common_name": "haproxy.unit4.fleet",
       "alt_names": ["..."], "ip_sans": ["..."], "ttl": "168h",
       "bundle": true}

    `bundle` (default true) also returns `pem_chain` = cert + issuing CA and
    `pem_haproxy` = private key + cert + CA in the single-file order HAProxy's
    `crt` directive wants, so the caller writes one file instead of stitching
    three. The private key is returned exactly once, here, over the tailnet-only
    admin channel; it is never logged or stored on this side.
    """
    denied = _require_admin_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    role = (data.get("role") or "").strip()
    cn = (data.get("common_name") or "").strip()
    if not role or not cn:
        return jsonify({"error": "body needs 'role' and 'common_name'"}), 400
    try:
        issued = bao.issue_cert(
            role, cn,
            alt_names=data.get("alt_names"),
            ip_sans=data.get("ip_sans"),
            ttl=data.get("ttl"),
        )
    except bao.BaoError as e:
        emit_event("certs", action="issue_failed", role=role, cn=cn, error=str(e))
        return jsonify({"error": str(e), "role": role}), 502

    cert = issued.get("certificate", "")
    key = issued.get("private_key", "")
    ca = issued.get("issuing_ca", "")
    out = {
        "certificate": cert,
        "private_key": key,
        "issuing_ca": ca,
        "ca_chain": issued.get("ca_chain", []),
        "serial_number": issued.get("serial_number"),
        "expiration": issued.get("expiration"),
    }
    if data.get("bundle", True):
        def _nl(s):  # PKI omits the trailing newline; concatenation needs it
            return s if s.endswith("\n") else s + "\n"
        out["pem_chain"] = _nl(cert) + _nl(ca)
        out["pem_haproxy"] = _nl(key) + _nl(cert) + _nl(ca)
    emit_event("certs", action="issued", role=role, cn=cn,
               serial=out["serial_number"])
    return jsonify(out)


@app.route("/api/renewals", methods=["GET"])
def renewals_status():
    """Every credential the fleet tracks an expiry for, and what is due.

    Read-only and unauthenticated on purpose: it carries expiry dates and
    names, never a secret value — the same shape as /api/certs/status.
    """
    return jsonify(renewals.snapshot())


@app.route("/api/certs/status", methods=["GET"])
def certs_status():
    """All reported certs plus the flagged subset (expiring soon or broken)."""
    with _cert_lock:
        units = {u: dict(v) for u, v in _cert_state.items()}
    expiring = []
    for unit, info in units.items():
        for c in info.get("certs", []):
            if c.get("error") or (c.get("days_left") is not None and c["days_left"] < CERT_WARN_DAYS):
                expiring.append({**c, "unit": unit})
    expiring.sort(key=lambda c: (c.get("days_left") is None, c.get("days_left") or 0))
    return jsonify({
        "warn_days": CERT_WARN_DAYS,
        "expiring":  expiring,
        "units":     units,
    })


# ── TRAEFIK ACTIVE DISCOVERY ────────────────────────────────────────────────

def active_discovery_scanner():
    """Background thread that scans nodes' Traefik APIs (including unit 2/4)."""
    while True:
        now = datetime.now(timezone.utc).isoformat()
        changed = False
        
        with lock:
            # We want to scan all known node IPs (Internal and OpenVPN), plus any
            # node that only has a stored traefik_api URL and no ip on file — e.g.
            # seeded infra nodes (mac_mini, secondary_vps_unit2) that never call
            # /register themselves, so nothing else ever refreshes their liveness
            # and they were previously stuck ONLINE forever.
            nodes_to_scan = []
            for node_name, node_info in registry["nodes"].items():
                endpoints = []
                has_ip = False
                for ip in (node_info.get("ip"), node_info.get("openvpn_ip")):
                    if ip and ip != 'unknown' and 'pending' not in ip:
                        has_ip = True
                        for port in [80, 8080, 443]:
                            endpoints.append(f"http://{ip}:{port}" if port != 443 else f"https://{ip}")
                if node_info.get("traefik_api"):
                    endpoints.append(node_info["traefik_api"])

                # Only nodes with NO ip/openvpn_ip (i.e. no /register heartbeat
                # path of their own — the mac_mini/secondary_vps_unit2 case) get
                # their node-level status driven by this scan. Nodes that do have
                # an ip self-register via POST /register already (see the "Update
                # the node as ONLINE whenever any service heartbeats" block above)
                # — letting a failed Traefik probe override THAT status caused
                # lokey-registered nodes with no Traefik running (e.g. unit9,
                # which uses Caddy) to flap ONLINE/OFFLINE against their own
                # legitimate heartbeats. Traefik discovery still runs for them
                # (to find containers), it just can't flip their own status.
                if endpoints:
                    nodes_to_scan.append((node_name, endpoints, not has_ip))

        for node_name, endpoints, owns_node_status in nodes_to_scan:
            reached = False
            for traefik_url in endpoints:
                # A stored traefik_api already ends in .../api; ip-based guesses don't.
                routers_url = f"{traefik_url}/http/routers" if traefik_url.rstrip('/').endswith('/api') \
                    else f"{traefik_url}/api/http/routers"
                try:
                    resp = requests.get(routers_url, timeout=3)
                    if resp.status_code != 200: continue
                    reached = True

                    routers = resp.json()
                    for router in routers:
                        if router.get("provider") == "internal" or router.get("name", "").endswith("@internal"):
                            continue
                            
                        name = router.get("name", "").split("@")[0]
                        rule = router.get("rule", "")
                        status = router.get("status", "unknown").upper()
                        
                        match = re.search(r"Host\(`([^`]+)`\)", rule)
                        domain = f"https://{match.group(1)}" if match else ""
                        
                        with lock:
                            # Use existing or create new entry
                            svc = registry["services"].get(name, {})
                            resolved_status = status if status in ["ONLINE", "OFFLINE"] else "ONLINE"
                            updated_svc = {
                                "name": name,
                                "category": svc.get("category", "docker containers"),
                                "url": svc.get("url") or domain,
                                "internal": svc.get("internal", ""),
                                "hosts": list(set(svc.get("hosts", []) + [node_name])),
                                "status": resolved_status,
                                "last_heartbeat": now,
                                "registered_at": svc.get("registered_at", now),
                                "metadata": {**(svc.get("metadata", {})), "discovered_via": f"traefik_{node_name}"}
                            }
                            # Preserve the offline_since clock — never reset it on a re-discovery
                            # unless the service just came back ONLINE (then clear it)
                            if resolved_status == "OFFLINE":
                                updated_svc["offline_since"] = svc.get("offline_since", now)
                            # ONLINE: offline_since intentionally omitted (clock resets on recovery)
                            registry["services"][name] = updated_svc
                            changed = True
                    break # Success on this node/IP
                except Exception:
                    continue

            # The Traefik check IS this node's heartbeat for nodes that have no
            # other way to report in (nothing else ever touches their last_seen).
            # A failed scan this cycle means no heartbeat — mark it OFFLINE now
            # rather than leaving it ONLINE forever, same as service heartbeats.
            if owns_node_status:
                with lock:
                    node = registry["nodes"].get(node_name)
                    if node:
                        if reached:
                            node["status"] = "ONLINE"
                            node["last_seen"] = now
                            changed = True
                        elif node.get("status") == "ONLINE":
                            # Traefik being unreachable says Traefik is down, not
                            # that the machine is. Demoting straight to OFFLINE
                            # here was the same wrong inference the lokey path
                            # made. Park it as AGENT_DOWN and leave last_seen
                            # stale so the reaper's reachability probe makes the
                            # real call on the next pass.
                            node["status"] = NODE_STATUS_AGENT_DOWN
                            node["last_seen"] = node.get("last_seen") or now
                            changed = True
                            print(f"⚠️  NODE AGENT DOWN: {node_name} (traefik unreachable)")

        if changed:
            persist_registry()

        time.sleep(SCANNER_INTERVAL)



# ── WEBSITE PINGER ───────────────────────────────────────────────────────────

# Hosts fronted by Sablier, which starts their container on demand and stops it
# again when idle. Polling one of these IS traffic: the uptime check wakes the
# container, Sablier expires the session, the next check wakes it again, and the
# service never actually sleeps. Monitoring has to leave them alone to work.
ON_DEMAND_HOSTS = {
    h.strip().lower()
    for h in os.environ.get(
        "ON_DEMAND_HOSTS",
        "pgadmin.theofficialblacksheepco.com,a0.theofficialblacksheepco.online"
    ).split(",")
    if h.strip()
}


def _is_on_demand_url(url):
    """True when this URL points at a Sablier-managed host — do not poll it."""
    from urllib.parse import urlparse
    try:
        host = urlparse(str(url or "")).hostname or ""
    except Exception:
        return False
    return host.lower() in ON_DEMAND_HOSTS


def website_pinger():
    """Discovers websites from Docker Traefik labels, registers them using container status."""
    if not docker_client:
        return
    while True:
        now = datetime.now(timezone.utc).isoformat()
        changed = False
        try:
            running = {c.name for c in docker_client.containers.list()}
            all_ctrs = docker_client.containers.list(all=True)
            _unit = os.environ.get("UNIT_NAME", "unknown")
            import re as _re
            for ctr in all_ctrs:
                for k, v in ctr.labels.items():
                    if not k.endswith(".rule"):
                        continue
                    hosts = _re.findall(r"Host\(`([^`]+)`\)", v)
                    for host in hosts:
                        url = "https://" + host
                        skey = "web_" + host.replace(".", "_").replace("-", "_")
                        status = "ONLINE" if ctr.name in running else "OFFLINE"
                        with lock:
                            ex = registry["services"].get(skey, {})
                            entry = {
                                "name": host,
                                "category": "websites",
                                "url": url,
                                "host": _unit,
                                "hosts": [_unit],
                                "status": status,
                                "last_heartbeat": now if status == "ONLINE" else ex.get("last_heartbeat", ""),
                                "registered_at": ex.get("registered_at", now),
                                "metadata": {"container": ctr.name},
                            }
                            if status == "OFFLINE":
                                # Preserve existing clock; start it only if not already running
                                entry["offline_since"] = ex.get("offline_since", now)
                            # ONLINE: offline_since intentionally omitted (resets clock on recovery)
                            registry["services"][skey] = entry
                            changed = True
        except Exception as e:
            print("website_pinger error: " + str(e))
        if changed:
            persist_registry()
        time.sleep(60)


# ── URL STATUS CHECKER ───────────────────────────────────────────────────────

URL_CHECK_INTERVAL = int(os.environ.get("URL_CHECK_INTERVAL", 60))

def url_status_checker():
    """Health-checks 'websites' and 'serverless' entries by their public URL.

    Unlike website_pinger this needs no Docker socket, so it runs on the Fly.io
    primary too. Offline sites stay in the registry as OFFLINE; the heartbeat
    reaper purges them only after RETENTION_DAYS (90d) of inactivity.
    """
    while True:
        with lock:
            targets = [(sid, svc.get("url")) for sid, svc in registry["services"].items()
                       if svc.get("category") in ("websites", "serverless")
                       and str(svc.get("url", "")).startswith("http")
                       and not _is_on_demand_url(svc.get("url"))]

        changed = False
        for sid, url in targets:
            try:
                r = requests.get(url, timeout=10, allow_redirects=True)
                up = r.status_code < 500
            except Exception:
                up = False
            now = datetime.now(timezone.utc).isoformat()
            with lock:
                svc = registry["services"].get(sid)
                if not svc:
                    continue
                if up:
                    svc["status"] = "ONLINE"
                    svc["last_heartbeat"] = now
                    svc.pop("offline_since", None)
                    changed = True
                else:
                    if svc.get("status") != "OFFLINE":
                        svc["status"] = "OFFLINE"
                        changed = True
                    # Start the 90-day retention clock once; never reset it while down
                    if not svc.get("offline_since"):
                        svc["offline_since"] = now
                        changed = True

        if changed:
            persist_registry()
        time.sleep(URL_CHECK_INTERVAL)


# ── STARTUP ─────────────────────────────────────────────────────────────────

_workers_lock = threading.Lock()
_workers_started = False


def _credential_renewer():
    """The fleet's 7-days-before-expiry rule, over every credential we track.

    Reads the live cert reports through a getter rather than a snapshot so the
    thread always evaluates what the units reported most recently, and queues
    node-local work through the ordinary exec queue — which means every
    renewal shows up in the command history like any other job.
    """
    def _cert_state_getter():
        with _cert_lock:
            return {u: dict(v) for u, v in _cert_state.items()}

    renewals.worker(_cert_state_getter, bao, _queue_exec_command)


def start_background_workers():
    """Start every background thread, exactly once.

    There used to be two hand-maintained copies of this list — one in main()
    (the `python locator.py` path) and one in the `else:` branch taken when a
    WSGI server imports the module. Production runs
    `gunicorn ... locator:app`, so only the second ever executed, and any
    worker added to main() alone silently never ran. That is precisely how
    enforce_unit_placement came to be started but dead, and the same drift had
    already cost this file its Postgres schema creation once before (see the
    init_schema note below). One list, called from both paths.

    Safe at import time because the container runs --workers 1; with several
    worker processes each would start its own copy of every thread.
    """
    global _workers_started
    with _workers_lock:
        if _workers_started:
            return
        _workers_started = True

    # The command queue is in-memory, so anything a previous process left open
    # can never complete. Close those rows now rather than leaving runs that
    # read as "still going" forever. Done here, not in main()/the WSGI branch,
    # because both call this function — which is the one place the two startup
    # paths cannot drift apart.
    try:
        with command_lock:
            live_ids = list(command_queue.keys())
        for row in db.close_orphaned_runs(keep_ids=live_ids):
            print(f"⌛ Closed orphaned run {row['id']} ({row.get('label') or 'exec'} on {row['unit']}) "
                  "— locator restarted while it was in flight")
    except Exception as e:
        print(f"⚠️  Failed to close orphaned command runs: {e}")

    workers = [
        _log_forwarder,             # forward logs to beast-telemetry / live-logger
        heartbeat_reaper,
        local_docker_scanner,
        duplicate_killer,
        active_discovery_scanner,
        website_pinger,
        url_status_checker,         # websites + serverless, no Docker needed
        _self_election,             # secondaries stop themselves if primary is up
        enforce_unit_placement,     # locator.yml "units:" placement
        secret_sweeper,             # finds plaintext credentials in the store
        bao_token_renewer,          # a periodic OpenBao token dies silently
        traccar_feeder,             # lokey's GPS fixes into Traccar
        script_scheduler,           # recurring exec jobs from /api/schedule
        exec_run_reaper,            # ages out exec jobs that never reported back
        _credential_renewer,        # reissues every expiring credential 7 days out
    ]
    if BALANCE_ENABLED:
        workers.append(load_balancer)
    if IDLE_ENABLED:
        workers.append(idle_reaper)
    if GIT_AUTO_PUSH:
        workers.append(_git_push_worker)

    for fn in workers:
        threading.Thread(target=fn, daemon=True, name=fn.__name__).start()
    print(f"🧵 background workers started: {', '.join(f.__name__ for f in workers)}")


def main():
    print("=" * 55)
    print("  🔦 THE LOCATOR — Universal Service Registry")
    print("=" * 55)
    print(f"  Port:              {PORT}")
    print(f"  Heartbeat timeout: {HEARTBEAT_TIMEOUT}s")
    print(f"  Reaper interval:   {REAPER_INTERVAL}s")
    print(f"  Data directory:    {DATA_DIR}")
    print(f"  Load balancer:     {'ENABLED' if BALANCE_ENABLED else 'DISABLED'}")
    print(f"  Idle auto-stop:    {'ENABLED' if IDLE_ENABLED else 'DISABLED'}"
          + (f" ({IDLE_DEFAULT_TIMEOUT // 60}m default, label {IDLE_LABEL_ENABLE}=true)" if IDLE_ENABLED else ""))
    if BALANCE_ENABLED:
        print(f"    High threshold:  {BALANCE_HIGH}%")
        print(f"    Low threshold:   {BALANCE_LOW}%")
        print(f"    Diff threshold:  {BALANCE_DIFF}%")
        print(f"    Check interval:  {BALANCE_INTERVAL}s")
        print(f"    Cooldown:        {BALANCE_COOLDOWN}s")
    print("=" * 55)

    db.init_schema()
    load_seed()
    persist_registry()
    load_schedule()
    load_cert_state()

    start_background_workers()

    beast_log("🔦 LOCATOR online — registry loaded, telemetry forwarder active")
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()
else:
    # When imported by Gunicorn or other WSGI servers, initialize the app
    try:
        # Must precede persist_registry(), which writes to these tables.
        # init_schema() previously lived only in main(), i.e. the
        # `python locator.py` path — but production runs gunicorn and takes
        # this branch, so the schema was never created and every snapshot
        # failed with 'relation "nodes" does not exist'. Postgres persistence
        # could not have worked on any gunicorn deployment.
        db.init_schema()
        load_seed()
        persist_registry()
        load_schedule()
        load_cert_state()
        start_background_workers()
        beast_log("🔦 LOCATOR online (Gunicorn) — registry loaded, telemetry forwarder active")
    except Exception as e:
        print(f"ERROR initializing LOCATOR in Gunicorn mode: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()


LLAMA_CPP_ENDPOINT = os.environ.get("LLAMA_CPP_ENDPOINT", "http://100.99.131.20:8080/v1/chat/completions")

def alert_llama_llm(event_kind: str, details: dict):
    """
    Alert the llama.cpp LLM at Tailscale IP 100.99.131.20 on unknown migration errors
    or 3-retry attempt exhaustion.
    """
    try:
        payload = {
            "model": "llama-2.5-coder-14b",
            "messages": [
                {"role": "system", "content": "You are Locator's migration diagnostic and auto-remediation AI agent."},
                {"role": "user", "content": f"RED FLAG MIGRATION ALERT [{event_kind}]: {json.dumps(details, indent=2)}"}
            ]
        }
        res = requests.post(LLAMA_CPP_ENDPOINT, json=payload, timeout=5)
        beast_log(f"🤖 LLM ALERTED ({LLAMA_CPP_ENDPOINT}): HTTP {res.status_code}")
    except Exception as err:
        beast_log(f"⚠️ Could not alert LLM at {LLAMA_CPP_ENDPOINT}: {err}")


def _evaluate_candidate_node(node_id: str, node_info: dict, container_name: str, req_ram_gb: float = 0.5, req_disk_gb: float = 1.0) -> tuple:
    """
    Verbose step-by-step evaluation of candidate node capacity.
    Emits granular DEBUG logs to stdout (live logger) and Web UI event stream long before migration.
    """
    beast_log(f"🔍 DEBUG [EVAL]: Evaluating candidate host '{node_id}' for container '{container_name}'...")
    emit_event("eval_candidate", unit=node_id, container=container_name, message=f"Evaluating candidate node {node_id}")

    if node_info.get("status") != "ONLINE":
        beast_log(f"❌ DEBUG [EVAL]: Host '{node_id}' is NOT ONLINE (Status={node_info.get('status')}) -> REJECTED")
        return False, f"Host {node_id} is not ONLINE"

    # Exact Memory Calculation
    mem_total = _node_ram_total_mb(node_info) or 1024.0
    mem_avail_mb = float(node_info.get("mem_available_mb") or (mem_total * (100.0 - float(node_info.get("mem_percent") or 50.0)) / 100.0))
    avail_ram_gb = round(mem_avail_mb / 1024.0, 2)
    
    # Exact Disk Storage Calculation
    disk_total = float(node_info.get("disk_total_gb") or 10.0)
    disk_free_gb = float(node_info.get("disk_free_gb") or (disk_total * (100.0 - float(node_info.get("disk_percent") or 50.0)) / 100.0))
    disk_free_gb = round(disk_free_gb, 2)

    # CPU Headroom Calculation
    cpu_usage = float(node_info.get("cpu_percent") or 0.0)
    cpu_headroom = round(100.0 - cpu_usage, 2)

    beast_log(f"📊 DEBUG [CAPACITY CHECK] Node '{node_id}': Avail RAM = {avail_ram_gb} GB (Req = {req_ram_gb} GB) | "
              f"Free Disk = {disk_free_gb} GB (Req = {req_disk_gb} GB) | CPU Headroom = {cpu_headroom}%")

    if avail_ram_gb < req_ram_gb:
        msg = f"Insufficient RAM on {node_id}: {avail_ram_gb} GB available < {req_ram_gb} GB required"
        beast_log(f"❌ DEBUG [EVAL]: {msg} -> REJECTED")
        emit_event("eval_fail", unit=node_id, container=container_name, reason=msg)
        return False, msg

    if disk_free_gb < req_disk_gb:
        msg = f"Insufficient Storage on {node_id}: {disk_free_gb} GB free < {req_disk_gb} GB required"
        beast_log(f"❌ DEBUG [EVAL]: {msg} -> REJECTED")
        emit_event("eval_fail", unit=node_id, container=container_name, reason=msg)
        return False, msg

    beast_log(f"✅ DEBUG [EVAL]: Node '{node_id}' PASSED all capacity checks for container '{container_name}'")
    emit_event("eval_pass", unit=node_id, container=container_name, message=f"Node {node_id} passed capacity checks")
    return True, "PASSED"
