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
import bao


def _resolve_env_secrets():
    """Env values may be `bao://mount/path#field` references — resolved here,
    at boot, before db.py and friends read os.environ at import. This is what
    lets the locator's own .env carry pointers instead of secrets: the same
    convention every other unit's lokey enforces on its files.

    A ref that cannot resolve is left in place (fail-closed: a bogus string,
    not a blank password that might sail through a permissive check)."""
    for _name, _val in list(os.environ.items()):
        if not (isinstance(_val, str) and _val.startswith("bao://")):
            continue
        try:
            os.environ[_name] = bao.resolve_ref(_val)
        except Exception as _e:
            print(f"[env-resolve] {_name}: {_e} — ref left unresolved", flush=True)


_resolve_env_secrets()

import db
import clearance
import kc_admin
import renewals
import secretscan
import vaultwarden
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
DISK_CRIT_PERCENT = float(os.environ.get("DISK_CRIT_PERCENT", "95")) # % disk — same emergency treatment; a full disk crashes the whole unit
MIGRATION_FAIL_BACKOFF = int(os.environ.get("MIGRATION_FAIL_BACKOFF", "1800"))  # s before re-trying a service whose last migration FAILED

# Proactive pre-staging: watch nodes trending toward BALANCE_HIGH *before* they
# get there, and validate (not execute) a migration ahead of time so the real
# cutover — if it ends up being needed — has less work left to do. Derived
# from BALANCE_HIGH rather than a second absolute constant, so there's still
# only one number (BALANCE_HIGH) to reason about day to day.
BALANCE_PRESTAGE_ENABLED = os.environ.get("BALANCE_PRESTAGE_ENABLED", "true").lower() == "true"
BALANCE_PRESTAGE_MARGIN  = float(os.environ.get("BALANCE_PRESTAGE_MARGIN", "15"))  # % below BALANCE_HIGH that triggers pre-staging
PRESTAGE_STALE_SECONDS   = int(os.environ.get("PRESTAGE_STALE_SECONDS", "600"))    # re-validate if older than this

_DOCKER_DAEMON_NAME_CACHE = None

def _docker_daemon_name():
    """The Docker daemon's own host name, queried once over the socket.

    Unlike UNIT_NAME this cannot be copied to the wrong machine: a compose
    file or .env travels, the daemon's identity does not. Returns "" when
    the socket is absent (native runs) or the query fails.
    """
    global _DOCKER_DAEMON_NAME_CACHE
    if _DOCKER_DAEMON_NAME_CACHE is not None:
        return _DOCKER_DAEMON_NAME_CACHE
    name = ""
    try:
        if os.path.exists("/var/run/docker.sock"):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect("/var/run/docker.sock")
            s.sendall(b"GET /info HTTP/1.0\r\nHost: localhost\r\n\r\n")
            raw = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                raw += chunk
            s.close()
            name = json.loads(raw.split(b"\r\n\r\n", 1)[1]).get("Name") or ""
    except Exception:
        pass
    _DOCKER_DAEMON_NAME_CACHE = name
    return name


def _daemon_matches(host):
    """True when a registry unit name resolves to THIS Docker host.

    Normalized containment both ways so 'unit7' matches daemon
    'BlackSheepUnit7' and vice versa; unmatched daemon names ('my-vps')
    make the guard inert.
    """
    daemon = _docker_daemon_name()
    if not daemon or not host:
        return False
    d = re.sub(r"[^a-z0-9]", "", daemon.lower())
    h = re.sub(r"[^a-z0-9]", "", str(host).lower())
    # Length floor: '7' would substring-match 'blacksheepunit7' without it.
    return len(h) >= 3 and bool(d) and (h in d or d in h)


def _resolve_unit_name():
    """Real unit identity — discovered from the host, never trusted config.

    UNIT_NAME=unit4 hardcoded in docker-compose.yml travelled with every
    deployment: unit7's standby ran believing it WAS unit4, so its
    election treated the lokey-registered 'locator@unit7' — the locator
    on its own physical host — as a rival and killed it. Twice observed:
    once via a queued stop its own lokey executed ("keeping unit4,
    evicting unit7"), once via _stop_self ("unit7 healthier than unit4").
    Both locators ended up dead.

    Resolution order:
      1. /etc/hostname — the machine's own name on native runs. Inside a
         container it is the container id (hex), which is detected and
         skipped — a container's hostname is not its host's.
      2. The Docker daemon's name — the host's hostname when containerized
         (docker info Name defaults to it), the same truth /etc/hostname
         would have told a native process.
      3. UNIT_NAME env — last-resort override for hosts that name neither
         the machine nor the daemon after their unit.

    A 'unitN' token inside the name wins (the fleet's naming convention);
    a name with no unit token ('my-vps') is only used when env also has
    nothing better to say.
    """
    env_name = (os.environ.get("UNIT_NAME") or "").strip()

    def _unit_token(name):
        m = re.search(r"unit\d+", (name or "").lower())
        return m.group(0) if m else ""

    try:
        host_name = open("/etc/hostname").read().strip()
    except OSError:
        host_name = ""
    container_id = re.fullmatch(r"[0-9a-f]{12,64}", host_name.lower()) is not None
    daemon = _docker_daemon_name()

    sources = []
    if not container_id and host_name:
        sources.append(("hostname", host_name))
    if daemon:
        sources.append(("daemon", daemon))
    for source, name in sources:
        token = _unit_token(name)
        if token:
            if env_name and token != env_name.lower():
                print(f"⚠️  UNIT_NAME={env_name} but {source} is "
                      f"'{name}' — using discovered '{token}'")
            return token

    # No unitN anywhere — env gets its say before raw names, since fleet
    # convention is unitN and a raw 'my-vps' would fork the node's identity
    # away from what its lokey reports.
    if env_name:
        return env_name
    if not container_id and host_name:
        return host_name.lower()
    if daemon:
        return daemon.lower()
    return "unknown"


UNIT_NAME             = _resolve_unit_name()
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
# The compose store snapshot lands on its own branch — the remote is a shared
# repo (compose-stacks) whose main branch is real content, not our dump.
GIT_REMOTE_BRANCH = os.environ.get("GIT_REMOTE_BRANCH", "locator-store")

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
    # A loadbalanced service's replicas ARE the point — cap them at
    # units x instances rather than the singleton/triple rules below, or the
    # dedup pass would evict the very backends the edge is spreading across.
    cfg = _policy_for(container_name)
    if cfg.get("loadbalance"):
        try:
            inst = max(1, int(cfg.get("instances") or 1))
        except (TypeError, ValueError):
            inst = 1
        with lock:
            online = [u for u, i in registry.get("nodes", {}).items()
                      if i.get("status") == "ONLINE"]
        units = _expand_unit_spec(cfg.get("units"), online)
        # No unit fan-out means same-host replicas only, and same host shares
        # the published edge_port — the extras can't serve anyway.
        return max(1, len(units) * inst) if units else 1
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
# Fail backoff: container name -> last failure time. A service that cannot
# migrate (no compose dir on source, target rejects it, ...) used to re-queue
# every balance cycle and burn the node's one-migration-per-cooldown slot
# forever. Stamped at both FAILED transitions.
migration_failed_at: dict = {}
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
    """Units currently reporting an ONLINE locator, ourselves always included.

    Entries hosted on our own Docker daemon are excluded even if they carry
    a foreign unit name: a locator on this physical host IS us (or a local
    duplicate), never a rival to evict. That is the suicide guard for any
    identity confusion _resolve_unit_name cannot repair — e.g. a daemon not
    named after its unit.
    """
    base = _base_name(SELF_CONTAINER_NAME)
    hosts = {UNIT_NAME}
    with lock:
        for svc in registry["services"].values():
            if svc.get("status") != "ONLINE":
                continue
            if _base_name(svc.get("name", "")) != base:
                continue
            host = svc.get("host") or (svc.get("hosts") or [None])[0]
            if host and host != UNIT_NAME and not _daemon_matches(host):
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
            # Identity, safe.directory and credential.helper run EVERY pass —
            # they used to live inside the init branch, so a .git created any
            # other way left every commit failing on missing identity and the
            # store never landed a single commit. The compose store pushes to
            # GIT_REMOTE_BRANCH (a dedicated branch — force-pushing main on a
            # shared repo would clobber its real content).
            for args in (
                ["git", "config", "--global", "--add", "safe.directory", d],
                ["git", "config", "user.email", "locator@blacksheep"],
                ["git", "config", "user.name", "locator"],
                ["git", "config", "credential.helper", "store"],
            ):
                subprocess.run(args, cwd=d, capture_output=True)
            if GIT_REMOTE:
                have = subprocess.run(["git", "remote", "get-url", "origin"],
                                      cwd=d, capture_output=True, text=True)
                if have.returncode != 0:
                    subprocess.run(["git", "remote", "add", "origin", GIT_REMOTE],
                                   cwd=d, capture_output=True)
                elif have.stdout.strip() != GIT_REMOTE:
                    subprocess.run(["git", "remote", "set-url", "origin", GIT_REMOTE],
                                   cwd=d, capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=d, capture_output=True)
            r = subprocess.run(
                ["git", "commit", "-m", f"auto: compose snapshot {datetime.now(timezone.utc).isoformat()}"],
                cwd=d, capture_output=True, text=True
            )
            if "nothing to commit" in (r.stdout or ""):
                return
            if r.returncode != 0:
                print(f"⚠️  git-push: commit failed: {(r.stderr or '')[:200]}")
                return
            if GIT_REMOTE:
                subprocess.run(
                    ["git", "push", "-u", "origin", f"HEAD:{GIT_REMOTE_BRANCH}", "--force"],
                    cwd=d, capture_output=True, timeout=30
                )
                print(f"💾 git-push: compose files pushed → {GIT_REMOTE_BRANCH}")
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


def _edge_upstreams(name, cfg, port):
    """Every live backend for an edge service — the loadbalance:true path.

    _edge_upstream picks ONE host; this collects every ONLINE registry entry
    for the service and emits a server per host so Traefik round-robins them.
    Entries dedupe by host: two replicas on one unit share the published
    edge_port anyway, so the second would just be a duplicate URL.

    OFFLINE entries are already excluded — the heartbeat reaper owns that
    transition, so a unit going dark stops being emitted without any check
    here. With no live replica at all we fall back to _edge_upstream's
    dead/units resolution, which keeps the wake-on-502 path working.

    Caller must hold `lock` (same rule as _edge_upstream).
    """
    cfg = cfg or {}
    lookup = cfg.get("edge_host") or name
    urls = []
    seen_hosts = set()
    for key, svc in registry["services"].items():
        if key.split("@")[0] != lookup and svc.get("name") != lookup:
            continue
        if svc.get("status") != "ONLINE":
            continue
        host = svc.get("host") or ((svc.get("hosts") or [None])[0])
        if not host or host in seen_hosts:
            continue
        ip = _node_probe_addr(registry["nodes"].get(host) or {})
        if not ip:
            continue
        seen_hosts.add(host)
        urls.append({"url": f"http://{ip}:{port}"})
    if not urls:
        urls = [{"url": _edge_upstream(name, cfg, port)}]
    return urls


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
            if cfg.get("loadbalance"):
                lb = {"servers": _edge_upstreams(name, cfg, port)}
            else:
                lb = {"servers": [{"url": _edge_upstream(name, cfg, port)}]}
            if cfg.get("edge_sticky"):
                lb["sticky"] = {"cookie": {"name": re.sub(r"[^A-Za-z0-9_-]", "_", f"lb_{name}")[:32]}}
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
        middlewares = {}
        for svc in registry["services"].values():
            sub, dom = svc.get("subdomain"), svc.get("domain")
            if not sub or not dom:
                continue
            host = svc.get("host") or ((svc.get("hosts") or [None])[0])
            ip = _node_probe_addr(registry["nodes"].get(host or "") or {})
            url = f"http://{ip}:{svc.get('port') or 80}" if ip else EDGE_DEAD_UPSTREAM
            rname = f"deploy-{sub}"
            out[rname] = {"loadBalancer": {"servers": [{"url": url}]}}
            # The router is emitted here, not by the container's labels, so it
            # survives a stopped backend — attach the wake middleware and the
            # deployment gets the same errors→/wake path the file-defined
            # routers hand-write.
            target = svc.get("name") or rname
            wname = f"{rname}-wake"
            middlewares[wname] = {
                "errors": {
                    "status": ["500-599"],
                    # locator-wake is defined by the edge's file provider;
                    # unqualified here it would resolve inside @http and miss.
                    "service": "locator-wake@file",
                    "query": f"/wake/{target}",
                }
            }
            routers[rname] = {
                "rule": f"Host(`{sub}.{dom}`)",
                "entryPoints": ["websecure"],
                "service": rname,
                "middlewares": [wname],
                "tls": {"certResolver": "myresolver"},
            }
    body = {"http": {"services": out}}
    if routers:
        body["http"]["routers"] = routers
    if middlewares:
        body["http"]["middlewares"] = middlewares
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
    cfg = _policy_for(name)
    with lock:
        lb = {"servers": (_edge_upstreams(name, cfg, port) if cfg.get("loadbalance")
                          else [{"url": _edge_upstream(name, cfg, port)}])}
        if cfg.get("edge_sticky"):
            lb["sticky"] = {"cookie": {"name": re.sub(r"[^A-Za-z0-9_-]", "_", f"lb_{name}")[:32]}}
    return jsonify({"http": {"services": {name: {"loadBalancer": lb}}}})


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
    if _is_pinned(new_name):
        return  # infrastructure/stationary — allowed on multiple nodes; a
                # stateful service that got duplicated is a problem for a
                # human, not for an eviction queue that moves compose files
                # and leaves volumes behind.
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


# Auto-issue locator.d stanzas for containers that register with none. Off via
# AUTO_POLICY_FILL=false if the generated files ever get in the way.
AUTO_POLICY_FILL = os.environ.get("AUTO_POLICY_FILL", "true").lower() == "true"
_POLICY_FNAME_SAFE = re.compile(r"[^a-zA-Z0-9_.-]+")


def _autofill_policy_stub(name, host):
    """Write a locator.d stub for a registered container with no stanza.

    lokey registers every running container; one without a stanza used to live
    on implicit defaults — invisible if unrouted, yield-able if routed. The
    stub makes every deployed container a first-class policy entry with
    conservative defaults: never idle-stopped, never drained, not essential —
    until a human tunes it. One-shot: an existing stanza (exact, base-name or
    substring match via _policy_for) or an existing file means a decision was
    already made and nothing is written.
    """
    if not AUTO_POLICY_FILL:
        return
    try:
        if _policy_for(name):
            return
        fname = _POLICY_FNAME_SAFE.sub("-", str(name)).strip("-.") or "unnamed"
        path = os.path.join(LOCATOR_YML_DIR, f"{fname}.yml")
        if os.path.isfile(path):
            return
        m = re.search(r"unit(\d+)", host or "")
        units_line = f'    units: "{m.group(1)}"\n' if m else ""
        body = (
            "Service:\n\n"
            f"  # AUTO-GENERATED {datetime.now(timezone.utc).isoformat()} —\n"
            f"  # '{name}' registered on {host} with no locator.d stanza.\n"
            "  # Conservative defaults: never idle-stopped, never drained,\n"
            "  # not essential. Tune (idle_stop/drain_stop/deployment_type)\n"
            "  # or delete this file to return to implicit defaults.\n"
            f"  {name}:\n"
            "    deployment_type: optional\n"
            "    location_type: stationary\n"
            f"{units_line}"
            "    instances: 1\n"
            "    idle_stop: false\n"
        )
        # 'x' fails rather than clobber if a human stanza landed mid-race.
        with open(path, "x") as f:
            f.write(body)
        print(f"📝 AUTO-POLICY: locator.d/{fname}.yml written for '{name}'@{host}")
    except FileExistsError:
        pass
    except Exception as e:
        print(f"⚠️  auto-policy for '{name}' failed: {e}")


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

        # Health verification tier for docker containers. Green is EARNED:
        # only a docker HEALTHCHECK reporting 'healthy' (metadata.health from
        # lokey/the local scanner) proves the container is well. Anything else
        # that heartbeats while up — no HEALTHCHECK defined, 'starting', or an
        # agent too old to send the field — is alive-but-unproven: the
        # dashboard shows it orange ('unverified'), never green. 'unhealthy'
        # shows red. status stays ONLINE either way — liveness and health are
        # different axes, and idle/wake/traefik logic keys on the former.
        if _category == "docker containers":
            _hm = registry["services"][service_id].get("metadata") or {}
            _dh = str(_hm.get("health") or "").strip().lower()
            registry["services"][service_id]["health"] = _dh or None
            registry["services"][service_id]["health_state"] = (
                {"healthy": "verified", "unhealthy": "unhealthy"}
                .get(_dh, "unverified")
            )

        # Owner-marked public surface: a policy `visibility: public|shared` in
        # locator.d stamps the row every heartbeat, so anonymous readers of
        # /api/registry (e.g. the lokey-android grid, which holds no credential)
        # see exactly the services the owner opted in — and redact() strips
        # host/IPs/ports/telemetry from what they do see. Re-registering wipes
        # record-level keys not written here, which is why the mark lives in
        # policy instead of being PATCHed onto the row.
        _vis = (_policy_for(name).get("visibility") or "").strip().lower()
        if _vis in ("public", "shared"):
            registry["services"][service_id]["visibility"] = _vis

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
            if _vis in ("public", "shared"):
                registry["nodes"][host]["visibility"] = _vis

        # Update the node as ONLINE whenever any service heartbeats from it
        if host != "unknown" and host in registry["nodes"]:
            registry["nodes"][host]["status"] = "ONLINE"
            registry["nodes"][host]["last_seen"] = now
        registry["updated"] = now

    persist_registry()
    if host != "unknown":
        _enforce_dedup(name, host)
    if _svc_type == "container":
        _autofill_policy_stub(name, host)

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
    """Store or replace a compose file. Accepts raw YAML body or JSON {content: '...'}.

    UNIT_KEY route: a unit's lokey files its own compose with X-Lokey-Unit +
    X-Lokey-Key; admin key also passes. A unit key may not overwrite a compose
    for a service registered to a different unit.
    """
    scope, denied = _unit_key_auth()
    if denied:
        return denied
    if scope:
        _, svc = _find_service_entry(name)
        host = (svc or {}).get("host")
        if svc and host and host != scope:
            return jsonify({"error": f"this key belongs to {scope}, not {host}"}), 403

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
    # Per-service policy files — the same list the loader merges.
    try:
        for fname in sorted(os.listdir(LOCATOR_YML_DIR)):
            if not fname.endswith((".yml", ".yaml")) or fname.startswith("."):
                continue
            results.append({
                "label": f"locator.d/{fname}",
                "container": f"locator.d/{fname}",
                "path": os.path.join(LOCATOR_YML_DIR, fname),
            })
    except OSError:
        pass
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

def _policy_file_for(service):
    """Which policy file declares this service, or None.

    A stanza may live in locator.yml or in any locator.d/*.yml file; the
    writer must edit whichever holds it rather than always touching the
    monolith.
    """
    target = service.lower()
    for path in _policy_source_files():
        try:
            with open(path) as fh:
                for raw in fh:
                    s = raw.strip()
                    if s.endswith(":") and s[:-1].strip().lower() == target:
                        return path
        except OSError:
            continue
    return None


def _write_policy_field(service, key, value):
    """Set one key on one service's policy file, in place.

    Done as a line edit rather than a yaml.safe_load/dump round-trip on
    purpose: these files are mostly comments — the quoting trap on `units`,
    why each database is stationary — and a dump would silently delete all
    of it. The stanza is edited in whichever file under locator.d/ (or
    locator.yml) declares it; a service with no file yet gets a new
    locator.d/<name>.yml.
    """
    path = _policy_file_for(service)
    if path is None:
        # Not declared anywhere yet — give it its own locator.d file rather
        # than growing the monolith again.
        safe = re.sub(r"[^a-z0-9_.-]", "_", service.lower())
        path = os.path.join(LOCATOR_YML_DIR, f"{safe}.yml")
        try:
            os.makedirs(LOCATOR_YML_DIR, exist_ok=True)
            with open(path, "w") as fh:
                fh.write(f"# added from the tactical grid "
                         f"{datetime.now():%Y-%m-%d}\n"
                         f"Service:\n"
                         f"  {service}:\n"
                         f"    deployment_type: non-essential\n"
                         f"    location_type: mobile\n"
                         f"    units: \"current_unit\"\n"
                         f"    instances: 1\n"
                         f"    {key}: {value}\n")
        except OSError as e:
            return False, str(e)
        return True, None

    with open(path, "r") as fh:
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
        # _policy_file_for matched a stray line but the block scan disagrees —
        # treat as not-declared and append into THIS file's Service: block.
        if blk_line is None:
            return False, f"{os.path.basename(path)} has no 'Service:' block"

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

        with open(path, "w") as fh:
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

    with open(path, "w") as fh:
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


@app.route("/api/glances", methods=["GET"])
def glances_summary():
    """Combined Glances view — per-unit vitals fanned out over the tailnet.

    Each unit runs `glances -w` bound to its own tailnet IP :61208
    (locator.d/glances-web.yml, WAKE.md). We query the REST API directly so
    this tab needs no edge basicAuth hop; the per-unit "full view" links in
    the node popups still go through glances-unitN.* and its login.
    """
    import concurrent.futures

    with lock:
        targets = {
            name: str(info.get("tailscale_ip") or "").split(",")[0].strip()
            for name, info in registry["nodes"].items()
            if re.fullmatch(r"unit\d+", str(name).lower())
        }
    targets = {k: v for k, v in targets.items() if v}

    def _probe(name, ip):
        out = {"unit": name, "ok": False}
        base = f"http://{ip}:61208/api/4"
        try:
            for ep in ("system", "quicklook", "uptime", "load", "fs"):
                r = requests.get(f"{base}/{ep}", timeout=3)
                r.raise_for_status()
                out[ep] = r.json()
            out["ok"] = True
        except Exception as e:
            out["error"] = str(e)[:140]
        return out

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda kv: _probe(*kv), sorted(targets.items())))

    return jsonify({"units": results})


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
        # The unit's docker ps -a truth (running AND stopped). Per-container
        # service records only refresh while a container runs, so a stopped
        # one and a deleted one both look stale — this list is what tells them
        # apart, and the wake path refuses to queue starts for names absent
        # from it (deleted containers used to fail-and-requeue forever).
        if data.get("containers") is not None:
            node["containers"] = data["containers"]
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

    # Fetch before validating: the pin/stateful re-check below reads
    # mig["container"], so mig must exist first — the previous order raised
    # UnboundLocalError on every claim and the queue could never execute.
    with migration_lock:
        mig = migration_queue.get(mig_id)
        if not mig:
            return jsonify({"error": "not found"}), 404
        if mig["status"] != "PENDING":
            return jsonify({"error": "already claimed", "status": mig["status"]}), 409
        owner = mig.get("unit", mig.get("from_node"))
        if unit != "unknown" and owner and owner != unit:
            return jsonify({"error": "not yours", "owner": owner}), 403

    # Re-validate at claim time: the queue is minutes-to-stale by the time a
    # lokey polls it, and a policy pin or a newly-discovered stateful image in
    # between means "queued" no longer means "should run". ops-pgdb was
    # queued while unregistered-as-stateful and executed on the next poll;
    # this check is where a late correction actually stops the stop.
    with lock:
        _, svc = _find_service_entry(mig.get("container") or "")
        image = ((svc or {}).get("metadata") or {}).get("image", "").lower()
    pinned = _is_pinned(mig.get("container") or "")
    stateful = any(m in image for m in _STATEFUL_IMAGE_MARKERS)

    with migration_lock:
        # Re-check under the lock — another claim could have landed in the
        # gap between the first check and now.
        if mig["status"] != "PENDING":
            return jsonify({"error": "already claimed", "status": mig["status"]}), 409
        if pinned or stateful:
            mig["status"] = "CANCELLED"
            mig["cancelled_at"] = datetime.now(timezone.utc).isoformat()
            mig["cancel_reason"] = "pinned" if pinned else "stateful image"
            print(f"🚫 MIGRATION {mig_id}: cancelled at claim — {mig['cancel_reason']}")
            return jsonify({"error": "cancelled", "reason": mig["cancel_reason"]}), 409
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
            migration_failed_at[container] = datetime.now(timezone.utc)
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
                if not success:
                    migration_failed_at[mig.get("container", "")] = datetime.now(timezone.utc)
                print(f"{'✅' if success else '❌'} MIGRATION {mig_id}: {'DONE' if success else 'FAILED'}")
                # A start-type failure leaves the source stopped — the same
                # hole _verify_migration covers on timeout, but reached faster.
                # suricata/odoo (16:46) died this way: compose up failed on the
                # target, FAILED was recorded, and nothing ever restarted the
                # source. git_pull_only (dedup) is excluded — stopping the
                # duplicate is its whole point.
                if not success and mig.get("type") in MIGRATION_START_TYPES \
                        and mig.get("from_node") and mig.get("from_node") != mig.get("to_node"):
                    _queue_command(mig["from_node"], mig.get("container"), "start",
                                   source="migration-rollback")
                    print(f"↩️  ROLLBACK: queued start of '{mig.get('container')}' "
                          f"back on {mig.get('from_node')} (start-type failure)")
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

    # Per-service backend counts for loadbalanced services — answers "why did
    # my traffic split" without reading /api/traefik.
    policy = load_policy()
    backends = {}
    with lock:
        for name, cfg in policy.items():
            if not cfg.get("loadbalance") or not cfg.get("edge_port"):
                continue
            backends[name] = sorted({
                s.get("host") or (s.get("hosts") or ["?"])[0]
                for k, s in registry["services"].items()
                if (k.split("@")[0] == name or s.get("name") == name)
                and s.get("status") == "ONLINE"
            })

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
        "edge_backends":      backends,
    })


def _routed_containers():
    """Names of containers a public hostname resolves to.

    The web_* registry entries (lokey registers one per Traefik Host() label)
    and user deployments (subdomain+domain) are the two maps that outlive the
    container itself — which is exactly what a wake path needs: the label
    router dies with the container, the request falls through to the edge
    catch-all, and /wake resolves Host back to this name and starts it.

    A container with NO route has no way back up once stopped, so routing is
    the line between 'idle-stoppable by default' and 'needs idle_stop: true'.

    Caller must hold `lock`.
    """
    out = set()
    for key, svc in registry["services"].items():
        if key.startswith("web_"):
            container = (svc.get("metadata") or {}).get("container")
            if container:
                out.add(container.lower())
        elif svc.get("subdomain") and svc.get("domain") and svc.get("name"):
            out.add(svc["name"].lower())
    return out


def _stoppable_containers(unit, for_drain=False):
    """Containers a unit is allowed to stop, keyed by name -> {"timeout": ...}.

    Shared by /api/idle/policy and /api/power/drain. Opt-out, not opt-in:
    every ONLINE container on the unit is eligible unless something says it
    is not — an essential or stationary policy stanza, a name matching
    _PINNED_NAMES, a stateful-looking image, or an explicit `idle_stop: false`.

    for_drain=True additionally admits containers whose policy stanza sets
    `drain_stop: true` — drainable for a power drain WITHOUT becoming a
    routine idle-stop target (glances-web is the case: the owner wants its
    dashboard links live, but it may yield to an LLM job).

    The one positive requirement is a way back up: a container nobody can wake
    (no public_wake stanza, no public route in the registry) is only watched
    when it opted in with `idle_stop: true`, because stopping it is a silent
    outage until a human notices. Explicit `idle_stop: true` is therefore kept
    as 'stop it even though nothing can wake it'.
    """
    out = {}
    with lock:
        routed = _routed_containers()
        for key, svc in registry["services"].items():
            if svc.get("type") != "container":
                continue
            if svc.get("status") != "ONLINE":
                continue
            host = svc.get("host") or ((svc.get("hosts") or [None])[0])
            if unit and host != unit:
                continue
            name = (svc.get("name") or key.split("@")[0]).lower()
            cfg = _policy_for(name)
            if cfg.get("idle_stop") is False or cfg.get("restart_when_stopped"):
                continue
            # _PINNED_NAMES substring — NOT _is_pinned: 'stationary' means
            # never MIGRATE (volumes don't move), but stopping one is safe —
            # the data stays and the wake restarts it on the same host.
            if is_essential(cfg) or any(p in name for p in _PINNED_NAMES):
                continue
            image = ((svc.get("metadata") or {}).get("image") or "").lower()
            if any(m in image for m in _STATEFUL_IMAGE_MARKERS):
                continue
            if not cfg.get("idle_stop") and not (
                    cfg.get("public_wake") or name in routed):
                continue
            out[name] = {"timeout": cfg.get("idle_timeout") or ""}
    # Policy-declared opt-ins that are not (yet) in the registry — the
    # registry pass above only sees ONLINE containers, while a declared
    # service is eligible by name whether or not it has registered yet.
    for name, cfg in load_policy().items():
        if name in out:
            continue
        if not (cfg.get("idle_stop") or (for_drain and cfg.get("drain_stop"))):
            continue
        if cfg.get("restart_when_stopped"):
            continue
        if is_essential(cfg) or any(p in name for p in _PINNED_NAMES):
            continue
        spec = cfg.get("units") or ""
        if unit and spec not in ("", "all", "current_unit"):
            if unit not in _expand_unit_spec(spec, []):
                continue
        out[name] = {"timeout": cfg.get("idle_timeout") or ""}
    return out


@app.route("/api/idle/policy", methods=["GET"])
def idle_policy():
    """Which containers a unit is ALLOWED to idle-stop.

    lokey's NEVER_STOP list is the independent second check on the unit side:
    the locator decides, but the stop runs there.
    """
    unit = (request.args.get("unit") or "").strip().lower()
    if unit and not unit.startswith("unit"):
        unit = "unit" + unit
    return jsonify({
        "unit": unit,
        "containers": _stoppable_containers(unit),
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


# ── POWER DRAIN ─────────────────────────────────────────────────────────────
# Bulk resource gate for compute-bound jobs (e.g. puffbase's crew-builder):
# the caller asks for a drain, the locator queues a stop for every
# policy-stoppable container on the target units, and the caller polls the
# drain until every queued command reports back — that is the "approval to
# continue". After the job, /api/power/restore starts everything that was
# stopped. Wake-on-502 stays live throughout, so a drained service that gets
# real traffic comes back on its own.
POWER_TOKEN  = os.environ.get("POWER_TOKEN", "")
power_drains = {}   # drain_id -> record; records are kept with command history
POWER_DRAIN_RETENTION = 50
# A drain's initiator can die holding it (gate restart loses its drain_id,
# crew crash skips restore). Without an expiry the stopped containers stay
# down forever, so unrestored drains auto-restore past this age.
POWER_DRAIN_TTL_S = int(os.environ.get("POWER_DRAIN_TTL_S", "7200"))


def _expire_old_drains():
    """Auto-restore unrestored drains older than POWER_DRAIN_TTL_S.

    Called lazily from the drain endpoints — no separate worker needed,
    since any poll/restore passes through here.
    """
    now = datetime.now(timezone.utc)
    with command_lock:
        stale = [r["id"] for r in power_drains.values()
                 if not r.get("restored")
                 and (now - datetime.fromisoformat(
                      r["created_at"])).total_seconds() > POWER_DRAIN_TTL_S]
    for sid in stale:
        print(f"🔌 POWER DRAIN {sid} expired after {POWER_DRAIN_TTL_S}s — auto-restoring")
        _do_drain_restore(sid)


def _power_authorized():
    # Unset POWER_TOKEN means tailnet-internal default, same posture as
    # /api/commands/pending. Setting it requires X-Power-Token on both
    # mutating endpoints.
    return not POWER_TOKEN or hmac.compare_digest(
        request.headers.get("X-Power-Token", ""), POWER_TOKEN)


def _normalize_units(raw):
    if isinstance(raw, str):
        raw = [u.strip() for u in raw.split(",") if u.strip()]
    units = []
    for u in raw or []:
        u = str(u).strip().lower()
        if u:
            units.append(u if u.startswith("unit") else f"unit{u}")
    return units


def _drain_holds(unit, name):
    """drain_id of an active (unrestored) power drain covering `name` on `unit`.

    While a drain holds a container, traffic-driven wakes must not resurrect
    it — the room it freed belongs to the LLM job until /api/power/restore.
    """
    name = (name or "").lower()
    with command_lock:
        for rec in power_drains.values():
            if rec.get("restored"):
                continue
            if name in (rec.get("units") or {}).get(unit, []):
                return rec["id"]
    return None


@app.route("/api/power/drain", methods=["POST"])
def power_drain():
    if not _power_authorized():
        return jsonify({"error": "bad power token"}), 403
    data = request.get_json(silent=True) or {}
    units = _normalize_units(data.get("units")) or [_resolve_unit_name()]
    # Names the caller refuses to drain — chiefly LLM consumers: a drain
    # triggered BY an inference request must never stop the container that
    # made the request, or the call kills its own caller mid-flight.
    exclude = {str(n).strip().lower()
               for n in (data.get("exclude") or []) if str(n).strip()}
    drain_id = str(uuid.uuid4())[:8]
    rec = {
        "id": drain_id,
        "reason": str(data.get("reason") or "")[:120],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "units": {},
        "commands": [],
        "restored": False,
    }
    for unit in units:
        names = sorted(n for n in _stoppable_containers(unit, for_drain=True)
                       if n not in exclude)
        rec["units"][unit] = names
        for name in names:
            cmd = _queue_command(unit, name, "stop", source=f"power:{drain_id}")
            rec["commands"].append(cmd["id"])
    with command_lock:
        power_drains[drain_id] = rec
        if len(power_drains) > POWER_DRAIN_RETENTION:
            oldest = sorted(power_drains.values(), key=lambda r: r["created_at"])
            for old in oldest[: len(power_drains) - POWER_DRAIN_RETENTION]:
                power_drains.pop(old["id"], None)
    print(f"🔌 POWER DRAIN {drain_id}: queued {len(rec['commands'])} stops on {units} ({rec['reason']})")
    return jsonify({"drain_id": drain_id, "units": rec["units"], "total": len(rec["commands"])})


@app.route("/api/power/drain/<drain_id>", methods=["GET"])
def power_drain_status(drain_id):
    with command_lock:
        rec = power_drains.get(drain_id)
        cmds = [command_queue.get(cid) for cid in rec["commands"]] if rec else []
    if not rec:
        return jsonify({"error": "unknown drain_id"}), 404
    stopped, failed, waiting = [], [], []
    for c in cmds:
        if not c:
            continue
        if c["status"] == "DONE" and c.get("success"):
            stopped.append(f"{c['unit']}/{c['container']}")
        elif c["status"] in ("DONE", "FAILED"):
            failed.append(f"{c['unit']}/{c['container']}")
        elif c["status"] == "CANCELLED":
            pass  # resolved — neither stopped nor owed a start
        else:
            waiting.append(f"{c['unit']}/{c['container']}")
    return jsonify({
        "drain_id": drain_id,
        "acknowledged": not waiting,
        "stopped": stopped,
        "failed": failed,
        "waiting": waiting,
        "restored": rec["restored"],
    })


@app.route("/api/power/restore", methods=["POST"])
def power_restore():
    if not _power_authorized():
        return jsonify({"error": "bad power token"}), 403
    data = request.get_json(silent=True) or {}
    drain_id = data.get("drain_id")
    with command_lock:
        rec = power_drains.get(drain_id)
        cmds = [command_queue.get(cid) for cid in rec["commands"]] if rec else []
    if not rec:
        return jsonify({"error": "unknown drain_id"}), 404
    if rec["restored"]:
        return jsonify({"drain_id": drain_id, "restored": [], "already": True})
    restarted = _do_drain_restore(drain_id, rec=rec, cmds=cmds)
    return jsonify({"drain_id": drain_id, "restored": restarted})


def _do_drain_restore(drain_id, rec=None, cmds=None):
    """The restore itself, shared by the endpoint and drain expiry.

    Stops still sitting in the queue must never fire after the restore —
    they would land as untracked stops no drain owns (website-backend,
    2026-09-25). A DISPATCHED one may already be in lokey's hands and can
    still run; that is the accepted window."""
    with command_lock:
        rec = rec or power_drains.get(drain_id)
        if rec is None:
            return []
        if cmds is None:
            cmds = [command_queue.get(cid) for cid in rec["commands"]]
        for c in cmds:
            if not c:
                continue
            if c["status"] == "PENDING":
                c["status"] = "CANCELLED"
            elif c["status"] == "DISPATCHED":
                # Already in lokey's hands — it WILL run. Chaining the
                # start to this stop's completion keeps the pair ordered;
                # queuing the start now let the stale stop land last and
                # leave the container down anyway (2026-09-25 live case).
                c["then_start"] = drain_id
        restarted = []
        for c in cmds:
            if c and c["status"] == "DONE" and c.get("success"):
                _queue_command(c["unit"], c["container"], "start",
                               source=f"power-restore:{drain_id}")
                restarted.append(f"{c['unit']}/{c['container']}")
        rec["restored"] = True
    print(f"🔌 POWER RESTORE {drain_id}: queued {len(restarted)} starts")
    return restarted


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
# Per-service policy files, one stanza each, merged over locator.yml's
# contents (which remains valid but is being split out — the single file
# had grown to ~900 lines of interleaved services and nobody could find
# anything in it). Same schema: a top-level "Service:" mapping, or a bare
# mapping of service names.
LOCATOR_YML_DIR = os.path.join(os.path.dirname(LOCATOR_YML), "locator.d")
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
# idle_stop:       opt-in - queue a stop after the container's net traffic has
#                  been quiet for idle_timeout. Never fires on essential
#                  services or the last live replica of a loadbalanced one.
# idle_timeout:    per-service idle window ("15m", "2h", "5400").
# loadbalance:     opt-in - emit EVERY ONLINE replica as a backend in
#                  /api/traefik so edges round-robin across units, instead of
#                  pinning to the first live host. Pairs with a multi-unit
#                  'units:' spec; replicas on the same unit share the published
#                  edge_port and collapse to one backend.
# edge_sticky:     opt-in - add a Traefik sticky cookie so a visitor stays on
#                  whichever backend they first hit. For services whose
#                  replicas hold per-visitor state (ws rooms, sessions).
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


def _policy_source_files():
    """Every file load_policy() merges, in precedence order.

    locator.yml first (legacy single-file policy, still honoured), then the
    per-service files under locator.d/ in sorted order — a name defined in
    two places resolves to the LAST file read, and the collision is logged.
    """
    files = []
    if os.path.isfile(LOCATOR_YML):
        files.append(LOCATOR_YML)
    try:
        for fname in sorted(os.listdir(LOCATOR_YML_DIR)):
            if fname.endswith((".yml", ".yaml")) and not fname.startswith("."):
                files.append(os.path.join(LOCATOR_YML_DIR, fname))
    except OSError:
        pass
    return files


def load_policy():
    """Service policy from locator.yml + locator.d/, keyed by lowercase name.

    This file existed but nothing read it, so services marked
    'location_type: stationary' were migrated anyway — which is how the
    database behind ns1's PowerDNS came to be queued for a move. Reloaded on
    mtime change so edits take effect without a restart.

    Tolerates the original misspellings ('deployement_type',
    'inactivity_timout_minutes') alongside the corrected ones.
    """
    files = _policy_source_files()
    if not files:
        return {}
    try:
        fingerprint = tuple((p, os.path.getmtime(p)) for p in files)
    except OSError:
        return _policy_cache["data"]
    if _policy_cache["mtime"] == fingerprint:
        return _policy_cache["data"]

    import yaml as _yaml
    services = {}
    for path in files:
        try:
            with open(path) as fh:
                doc = _yaml.safe_load(fh) or {}
        except Exception as e:
            print(f"⚠️  {os.path.basename(path)} unreadable: {e}")
            continue
        # Accept "Service:" (as written) or a bare top-level mapping. An
        # explicit but empty Service: means "no services here" — it must NOT
        # fall through to `doc`, which would parse the key itself as a
        # service named "service".
        if "Service" in doc:
            block = doc["Service"]
        elif "services" in doc:
            block = doc["services"]
        else:
            block = doc
        if not isinstance(block, dict):
            continue
        for name, cfg in block.items():
            if not isinstance(cfg, dict):
                continue
            if str(name).lower() in services:
                print(f"⚠️  policy collision: '{name}' defined in both "
                      f"{services[str(name).lower()][0]} and {path} — "
                      f"the latter wins")
            services[str(name).lower()] = (path, cfg)

    parsed = {}
    for name, (_src, cfg) in services.items():
        if not isinstance(cfg, dict):
            continue
        parsed[name] = {
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
                # drain_stop: opt-in like idle_stop but ONLY honored by
                # /api/power/drain — the container yields to a bulk resource
                # drain without becoming a routine idle-stop target. Same
                # whitelisting rule: undeclared here, silently dropped there.
                "drain_stop": bool(cfg.get("drain_stop", False)),
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
                # loadbalance: emit EVERY ONLINE replica as a backend server in
                # /api/traefik instead of just the first live host, so Traefik
                # round-robins across units. Replica liveness comes free from
                # the heartbeat reaper — a dead instance stops heartbeating,
                # goes OFFLINE, and falls out of the emitted list on the edge's
                # next poll. Strictly opt-in like idle_stop.
                "loadbalance": bool(cfg.get("loadbalance", False)),
                # edge_sticky: pin a visitor to whichever backend they first
                # hit via a Traefik sticky cookie. Needed when replicas keep
                # per-connection or in-memory state (ws rooms, sessions) that
                # the other unit knows nothing about.
                "edge_sticky": bool(cfg.get("edge_sticky", False)),
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
                # visibility: "public"|"shared" opts the row into the
                # anonymous-readable surface — register_service stamps it onto
                # the record every heartbeat and clearance.visible() honours it
                # for level-0 callers. Anything else stays internal.
                "visibility": str(cfg.get("visibility", "")).lower(),
            }
    _policy_cache.update({"mtime": fingerprint, "data": parsed})
    print(f"📄 policy loaded — {len(parsed)} service policies "
          f"from {len(files)} file(s)")
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
    # socat publish-sidecars — the '*-pub' naming convention for containers
    # that expose another service onto the tailnet. Pure plumbing: no traffic
    # pattern of their own, so the idle reaper sees a forwarder with no
    # requests and stops it, silently breaking whatever it publishes
    # (locator-tailnet-pub, searchsearcher-oauth-pub — both reaped 2026-09-17
    # while their upstreams were still up).
    "-pub",
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


def _node_runs_containers(node_id, services_snap=None):
    """True when the node's lokey reports as a container service —
    i.e. docker actually exists there.

    A native lokey (Surface Go, the Mac) registers type 'native' and can
    never `docker compose up`, but it still reports near-zero disk — the
    freest-looking target in the fleet. Sending it a container migration
    just burns the source's cooldown on a pull that cannot run. unit5
    was queued repeatedly for exactly this reason.
    """
    services = services_snap if services_snap is not None else registry["services"]
    for svc in services.values():
        if (svc.get("host") == node_id
                and (svc.get("name") or "").lower() == "lokey"
                and svc.get("type") == "container"
                and svc.get("status") == "ONLINE"):
            return True
    return False


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
            elif load <= BALANCE_LOW and _node_runs_containers(node_id, services_snap):
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
                if _best_ip(inf) and _node_runs_containers(nid, services_snap)
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
                if least not in underloaded and _node_runs_containers(least[0], services_snap):
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
            is_diskcrit = (src_info.get("disk_percent") or 0) >= DISK_CRIT_PERCENT
            if is_oom:
                print(f"🚨 BALANCE: OOM emergency on {src_id} mem={src_info.get('mem_percent'):.1f}% — bypassing anti-flap/cooldown")
            elif is_diskcrit:
                print(f"🚨 BALANCE: DISK emergency on {src_id} disk={src_info.get('disk_percent'):.1f}% — bypassing anti-flap/cooldown")
            emergency = is_oom or is_diskcrit

            # Cooldown check (skipped in OOM/disk emergency)
            last_mig = node_last_migrated.get(src_id)
            if not emergency and last_mig and (now - last_mig).total_seconds() < BALANCE_COOLDOWN:
                remaining = int(BALANCE_COOLDOWN - (now - last_mig).total_seconds())
                print(f"⏳ BALANCE: {src_id} in cooldown ({remaining}s remaining)")
                continue

            # Anti-flap: require consecutive overloaded checks (skipped in OOM/disk emergency)
            if not emergency:
                overload_strikes[src_id] = overload_strikes.get(src_id, 0) + 1
                if overload_strikes[src_id] < BALANCE_STRIKES:
                    print(f"⚠️  BALANCE: {src_id} at {src_load:.1f}% — strike {overload_strikes[src_id]}/{BALANCE_STRIKES}, watching")
                    continue

            # Find movable services on this node — container OR native, as long as
            # their declared dependencies (if any) are satisfied somewhere in the
            # registry. Native services used to be hard-excluded here entirely.
            # OOM bypasses cooldown, so without this check the same service
            # gets re-queued every tick while its first migration is still
            # being claimed/executed by the source lokey.
            with migration_lock:
                in_flight = {
                    m.get("container")
                    for m in migration_queue.values()
                    if m.get("status") in ("PENDING", "IN_PROGRESS")
                }
            # A service that keeps failing (no compose dir on source, target
            # rejects it) sits out one backoff window instead of eating this
            # node's one-migration-per-cooldown slot every cycle forever.
            fail_cutoff = now - timedelta(seconds=MIGRATION_FAIL_BACKOFF)
            movable = [
                (svc_id, svc)
                for svc_id, svc in services_snap.items()
                if svc.get("host") == src_id
                and svc.get("status") == "ONLINE"
                and svc.get("type") in ("container", "native")
                and not _is_pinned(svc.get("name"))
                and not svc.get("metadata", {}).get("pinned")
                # A stateful IMAGE means the data stays behind — migration
                # moves the compose file, not the volume. ops-pgdb (postgres:
                # 16-alpine) slipped the name pins because it is spelled
                # "pgdb", and ops-dashboard lost its database live.
                and not any(m in (svc.get("metadata", {}).get("image") or "").lower()
                            for m in _STATEFUL_IMAGE_MARKERS)
                and svc.get("name") not in in_flight
                and (migration_failed_at.get(svc.get("name"))
                     or datetime.min.replace(tzinfo=timezone.utc)) < fail_cutoff
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

                # Health verdict needs the full inspect (list() returns the
                # summary, whose State is a bare string). Per-container guard:
                # one vanishing container must not kill the whole sweep.
                try:
                    container.reload()
                    _cst = container.attrs.get("State") or {}
                    _dh = str((_cst.get("Health") or {}).get("Status") or "").lower()
                except Exception:
                    _cst, _dh = {}, ""
                _health_state = {"healthy": "verified", "unhealthy": "unhealthy"}.get(_dh, "unverified")

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
                            "health": _dh or None,
                            "health_state": _health_state,
                            "last_heartbeat": now,
                            "registered_at": now,
                            "type": "container",
                            "metadata": {
                                "image": container.image.tags[0] if container.image.tags else "unknown",
                                "discovered_via": "local_docker",
                                "health": _dh or None,
                                "state": _cst.get("Status"),
                                "restart_count": container.attrs.get("RestartCount"),
                                "oom_killed": _cst.get("OOMKilled"),
                                "exit_code": _cst.get("ExitCode"),
                            }
                        }
                        changed = True
                    else:
                        registry["services"][service_id]["status"] = "ONLINE"
                        registry["services"][service_id]["health"] = _dh or None
                        registry["services"][service_id]["health_state"] = _health_state
                        registry["services"][service_id]["last_heartbeat"] = now
                        registry["services"][service_id].pop("offline_since", None)
                        _md = registry["services"][service_id].setdefault("metadata", {})
                        _md["health"] = _dh or None
                        _md["state"] = _cst.get("Status")
                        _md["restart_count"] = container.attrs.get("RestartCount")
                        _md["oom_killed"] = _cst.get("OOMKilled")
                        _md["exit_code"] = _cst.get("ExitCode")

            # Mark the local node ONLINE since we can see its containers.
            # Resolved UNIT_NAME, not the env — a stale env value marked a
            # FOREIGN node's last_seen fresh (env said unit4 on a unit7
            # daemon), which made its dead service records outrank live ones.
            _local_unit = UNIT_NAME or "unknown"
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
# RLock, not Lock: _do_drain_restore queues start commands while holding
# this — _queue_command takes it too and a plain Lock would deadlock.
command_lock = threading.RLock()
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

    vaultwarden.mirror(f"units/{unit}/{source}", values,
                       notes=f"ingested from {origin or 'unknown'} on {unit}")
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

    vaultwarden.mirror(f"compose/{name}", values,
                       notes=f"quarantined from compose file {name}")
    queued = _queue_redactions(name, sorted(values), refs, values=values)
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


@app.route("/api/secrets/requeue-redact", methods=["POST"])
def secrets_requeue_redact():
    """Re-emit redact_env for a compose file already quarantined to OpenBao.

    The command queue is in-memory, so a locator restart parks redactions that
    units never collected — their local compose files keep the plaintext.
    This re-queues from the vaulted state: keys from OpenBao, refs rebuilt,
    and the unit-side handler is idempotent (already-indirect lines just get
    their x-bao-secrets refs written). Admin only.
    """
    denied = _require_admin_key()
    if denied:
        return denied
    name = str((request.get_json(silent=True) or {}).get("file") or "").strip()
    if not name:
        return jsonify({"error": "file required"}), 400
    if not _INGEST_NAME_RE.match(name):
        return jsonify({"error": f"invalid file name {name!r}"}), 400
    bao_path = _bao_path_for(name)
    try:
        stored = bao.read_secret(SECRETSCAN_MOUNT, bao_path, use_cache=False)
    except Exception as e:
        return jsonify({"error": f"nothing vaulted for {name}: {e}"}), 404
    keys = sorted(stored)
    refs = {k: f"bao://{SECRETSCAN_MOUNT}/{bao_path}#{k}" for k in keys}
    queued = _queue_redactions(name, keys, refs, values=stored)
    emit_event("secrets", action="redact_requeued", file=name, units=queued)
    return jsonify({"file": name, "keys": keys, "units_queued": queued})


def _queue_redactions(compose_name, keys, refs, values=None):
    """Tell whichever unit runs this container to strip the same lines locally.

    The command carries only key names and bao:// references, never a value —
    /api/commands/pending is unauthenticated.

    Those references must live under the unit's own scope: unit-resolve refuses
    anything outside compose/units/<unit>/, so an admin-scoped compose/<name>
    ref would be written into the file but could never resolve at deploy. When
    `values` is supplied each hosting unit gets its own copy at
    compose/units/<unit>/<name> and refs pointing there; without values we fall
    back to the shared refs (admin-only resolvable — fine for store-side use).
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
    queued = []
    for unit in sorted(units):
        unit_refs = refs
        if values:
            upath = f"{SECRETSCAN_PREFIX}/units/{unit}/{compose_name}"
            try:
                bao.write_secret(SECRETSCAN_MOUNT, upath, values)
                unit_refs = {k: f"bao://{SECRETSCAN_MOUNT}/{upath}#{k}"
                             for k in keys}
            except bao.BaoError as e:
                print(f"🔐 redact {compose_name}: could not stage unit-scoped "
                      f"secrets for {unit} ({e}) — unit skipped, plaintext stays "
                      f"until a queueable copy exists")
                continue
        _queue_command(unit, compose_name, "redact_env", source="secret_sweep",
                       extra={"keys": list(keys), "refs": unit_refs})
        queued.append(unit)
    return queued


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
    # Chained restore: a drain that restored while this stop was already
    # dispatched gets its start queued NOW — after the stop ran, not before.
    if cmd.get("then_start") and cmd["action"] == "stop":
        _queue_command(cmd["unit"], cmd.get("container"), "start",
                       source=f"power-restore:{cmd['then_start']}")
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

    def _on_live_node(key, s):
        # A service record's status is only as fresh as the node reporting it —
        # 'name@unit4' kept claiming ONLINE for hours after unit4 died, so a
        # wake resolved to a unit whose lokey could never execute the start.
        unit = s.get("host") or (s.get("hosts") or [None])[0]
        if not unit and "@" in key:
            unit = key.split("@", 1)[1]
        node = registry["nodes"].get(unit) if unit else None
        return bool(node) and _node_is_fresh(node)

    def rank(item):
        key, s = item
        return (0 if _on_live_node(key, s) else 1,
                0 if s.get("status") == "ONLINE" else 1,
                0 if "@" in key else 1,
                -_hb_epoch(s.get("last_heartbeat")))

    candidates.sort(key=rank)
    return candidates[0]


def _find_container_unit(container):
    """Best-effort: which unit hosts this container?"""
    with _idle_lock:
        for unit, name in _idle_state:
            if name != container:
                continue
            node = registry["nodes"].get(unit) or {}
            if not node or _node_is_fresh(node):
                return unit
            # Stale idle entry from a dead lokey — fall through to the
            # service records, which now prefer live-node entries too.
    with lock:
        key, svc = _find_service_entry(container)
        if svc:
            unit = svc.get("host") or (svc.get("hosts") or [None])[0]
            if not unit and key and "@" in key:
                unit = key.split("@", 1)[1]
            return unit
    return None


def _container_exists_on_unit(unit, container):
    """Is this name in the unit's reported docker ps -a?

    The node's `containers.all` snapshot is the only fleet truth that covers
    STOPPED containers: service records stop heartbeating the moment a
    container exits, so the registry cannot tell "stopped" from "deleted"
    without it. wake_page used to queue a start for anything the stale web_*
    map pointed at, and a deleted container (insight, ebay-endpoint,
    nasa-web — 2026-09-16) failed on every monitor sweep forever.

    A node that has never sent the list (older lokey, non-docker unit) gets
    the benefit of the doubt: absence of the FIELD is not absence of the
    container. Only an explicit list that omits the name is a "gone".
    """
    if not unit:
        return False
    with lock:
        node = registry["nodes"].get(unit) or {}
        listing = (node.get("containers") or {}).get("all")
    if listing is None:
        return True
    names = {e.get("name") for e in listing if isinstance(e, dict)}
    names |= {e for e in listing if isinstance(e, str)}
    return container in names


@app.route("/api/idle/wake/<container>", methods=["POST"])
def idle_wake(container):
    """Queue a start command so the hosting unit's lokey wakes the container."""
    unit = _find_container_unit(container)
    if not unit:
        return jsonify({"error": f"unknown container '{container}'"}), 404
    if not _container_exists_on_unit(unit, container):
        return jsonify({"error": f"'{container}' no longer exists on {unit}"}), 410
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


def _is_publicly_routed(container):
    """True when a public hostname resolves to this container.

    That is what lets an anonymous caller wake it: reaching a wake URL under
    the service's own hostname means the visitor IS the public this route
    exists for. Two maps qualify — a web_* registry entry (label-routed
    container) or a deployment's subdomain+domain claim.
    """
    low = str(container).lower()
    with lock:
        for key, svc in registry["services"].items():
            if key.startswith("web_"):
                if ((svc.get("metadata") or {}).get("container") or "").lower() == low:
                    return True
            elif svc.get("subdomain") and svc.get("domain"):
                if (svc.get("name") or "").lower() == low:
                    return True
    return False


def _may_wake(container):
    """CLIENT and above may wake anything; anonymous only the opted-in.

    locator.yml is checked FIRST and is the real answer — it reloads on mtime
    change, so opting a new service in is a YAML edit rather than a rebuild of
    an image that has the list frozen inside it. PUBLIC_WAKE stays as the
    escape hatch for a container with no policy stanza at all.

    The third leg is routing itself: a container with a public hostname is
    wakeable by construction, because the only requests that can arrive for it
    are the public's own. This is what makes opt-out idle-stop safe — every
    container the policy returns by default has a route back up.
    """
    principal = getattr(g, "principal", None)
    if principal is not None and principal.level >= clearance.CLIENT:
        return True
    if _wake_policy(container).get("public_wake"):
        return True
    if container in PUBLIC_WAKE:
        return True
    return _is_publicly_routed(container)


def _container_for_domain(host):
    """Which container a public hostname should wake, or None.

    Declared wake_triggers in locator.yml answer first; the fallback is the
    registry's web_* map, which every unit's lokey feeds from container
    Traefik labels and which OUTLIVES the container — the whole point of this
    lookup, since the label router is gone precisely when the container is
    down. Declared triggers winning also keeps the deliberate cases right:
    two services sharing a domain stay unambiguous because the policy says
    which one owns it.
    """
    host = (host or "").split(":")[0].strip().lower()
    if not host:
        return None
    for name, cfg in load_policy().items():
        if not cfg.get("public_wake"):
            continue
        for d in (cfg.get("wake_triggers") or {}).get("domain", []):
            if str(d).lower() == host:
                return name
    with lock:
        for key, svc in registry["services"].items():
            if not key.startswith("web_"):
                continue
            url = svc.get("url") or ""
            url_host = url.split("://", 1)[-1].split("/")[0].split(":")[0].lower()
            if url_host != host:
                continue
            container = (svc.get("metadata") or {}).get("container")
            if container:
                return container
    return None


def _wake_companions(container):
    """Dependencies locator.yml says must come up with this container.

    Kept here rather than in each caller so a Traefik file or a link asks for
    ONE name: /wake/reech starts reech's database too, without reech.yml or the
    portal's HTML having to know that the database exists.

    Also follows the oauth naming convention automatically: an edge router
    fronts the service through <name>-oauth2-proxy (or -oauth), and opt-out
    idle-stop can now stop that proxy on its own — waking only the app left
    the front door dead (agent-0 2026-09-16). The reverse holds too: waking
    the proxy also brings up the app behind it.
    """
    deps = [d for d in _wake_policy(container).get("wake_with", [])
            if d and d != container]
    base = re.sub(r"-(oauth2-proxy|oauth)$", "", container)
    candidates = {f"{base}-oauth2-proxy", f"{base}-oauth", base}
    candidates.discard(container)
    with lock:
        known = {svc.get("name") for svc in registry["services"].values()}
    for cand in candidates:
        if cand in known and cand not in deps:
            deps.append(cand)
    return deps


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
        # Declared triggers missed — the registry fallback covers every
        # label-routed container, whose domain→container map exists whether
        # or not anyone wrote a policy stanza for it.
        if "domain" in query:
            container = _container_for_domain(query["domain"])
            if container:
                return jsonify({
                    "matched": query,
                    "container": container,
                    "wake_url": f"/wake/{container}",
                    "wake_with": _wake_companions(container),
                })
        return jsonify({"matched": query, "container": None,
                        "error": "no container declares this trigger"}), 404
    return jsonify({"containers": out, "count": len(out)})


@app.route("/wake", methods=["GET", "POST"])
def wake_by_host():
    """Wake whatever container the requested Host routes to.

    This is what the edge catch-all points at: when a label-routed container
    stops, its router disappears and the request falls through every other
    router to here — so the Host header is the only identifier of what was
    asked for. _may_wake still applies through wake_page, so an anonymous
    hit can only start a container that is genuinely public.
    """
    container = _container_for_domain(request.host)
    if not container:
        return Response("Nothing is registered for this host.",
                        status=404, mimetype="text/plain")
    return wake_page(container)


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
        # Same for one whose name survives only in a stale web_* entry after
        # the container itself was deleted: no start is queued for a name the
        # unit no longer has.
        if extra_unit and _container_exists_on_unit(extra_unit, extra):
            if _drain_holds(extra_unit, extra):
                continue  # held down by an active power drain
            _queue_command(extra_unit, extra, "start", source="wake")
    unit = _find_container_unit(container)
    if not unit:
        return Response(f"Unknown container '{container}'", status=404)
    if not _container_exists_on_unit(unit, container):
        return Response(f"'{container}' no longer exists on {unit}",
                        status=410, mimetype="text/plain")
    held_by = _drain_holds(unit, container)
    if held_by:
        return Response(
            f"'{container}' is held down by power drain {held_by} — "
            f"it comes back when the LLM job finishes.",
            status=409, mimetype="text/plain")
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
    # The branded wake page lives in templates/wake.html (bind-mounted, so the
    # design can be swapped without a rebuild). Keep its <script> block when
    # redesigning — the retry/poll loop is what returns the visitor.
    return render_template("wake.html", container=container, unit=unit,
                           target=target, own_origin=bool(own_origin))


# ── HEALTH VERIFICATION ALERTS ──────────────────────────────────────────────
# Green is earned: only a docker HEALTHCHECK reporting 'healthy' marks a
# container 'verified'. A running container with no confirmation is
# 'unverified' (orange on the grid) and 'unhealthy' is red — both computed at
# register/scan time into svc['health_state']. This worker watches transitions
# and reports them through notifier.notify_all (Matrix → reech) as ONE digest
# per sweep: the first pass after rollout finds ~50 unverified containers at
# once, and fifty separate pings is a denial of service on the operator.
#
# _health_alerted remembers which service_ids were already reported bad and in
# which state, so an unverified→unhealthy change re-alerts (it is a NEW fact)
# while a steady-state unverified stays quiet until it recovers.
_health_alerted: dict = {}   # service_id -> "unverified" | "unhealthy"
_health_alert_lock = threading.Lock()
HEALTH_CHECK_INTERVAL = 300  # seconds between sweeps
# How fresh a service's last_heartbeat must be to trust its health verdict.
# A loaded unit's tick (vitals sweep + command work + 60s sleep) can run
# ~5min — a tighter gate flaps records across the line and the "stale"
# branch below would clear and re-fire the same alerts every sweep.
HEALTH_FRESH_SECONDS = 600


def health_alert_digest():
    """Batched health_state transition alerts via the fleet notifier.

    Read-only: iterates the registry and sends notifications. It queues no
    commands and touches no containers — restart decisions stay in lokey's
    keep_alive(), which is why critical_service_watchdog was removed."""
    time.sleep(45)  # let heartbeats/scans populate health_state first
    while True:
        try:
            new_bad, cleared = [], []
            now = datetime.now(timezone.utc)
            with lock:
                snap = {sid: dict(s) for sid, s in registry["services"].items()}
            with _health_alert_lock:
                for sid, svc in snap.items():
                    if svc.get("category") != "docker containers":
                        continue
                    hs = svc.get("health_state")
                    # Ground truth is what the reporting agent measured at its
                    # docker socket (metadata.state), NOT the registry's
                    # derived ONLINE — which flaps, the exact reason
                    # critical_service_watchdog was removed. Records with no
                    # state report (old agents, seeded rows) fall back to
                    # ONLINE so they still get watched.
                    reported = str((svc.get("metadata") or {}).get("state") or "").lower()
                    running = (reported == "running" if reported
                               else svc.get("status") == "ONLINE")
                    # A stale heartbeat means the agent went quiet, not that
                    # the container is fine — the OFFLINE/reaper path owns
                    # that case, don't double-report it here.
                    try:
                        fresh = (now - datetime.fromisoformat(
                            svc.get("last_heartbeat") or "")).total_seconds() < HEALTH_FRESH_SECONDS
                    except (ValueError, TypeError):
                        fresh = False
                    bad = fresh and running and hs in ("unverified", "unhealthy")
                    prev = _health_alerted.get(sid)
                    if bad and prev != hs:
                        _health_alerted[sid] = hs
                        new_bad.append((sid, hs))
                    elif prev:
                        if fresh and running and hs == "verified":
                            # Confirmed recovery — announce it.
                            del _health_alerted[sid]
                            cleared.append(sid)
                        elif not (fresh and running):
                            # Agent went quiet or the container stopped: that
                            # is silence, not recovery. Drop the alert state
                            # without a notice so a later bad report re-alerts.
                            del _health_alerted[sid]
            if new_bad:
                unh = sorted(s for s, h in new_bad if h == "unhealthy")
                unv = sorted(s for s, h in new_bad if h == "unverified")
                parts = []
                if unh:
                    parts.append("🔴 UNHEALTHY (docker healthcheck failing): "
                                 + ", ".join(unh))
                if unv:
                    parts.append(f"🟠 UNVERIFIED ({len(unv)} running with no "
                                 f"healthcheck confirmation): " + ", ".join(unv))
                notifier.notify_all("LOCATOR HEALTH\n" + "\n".join(parts),
                                    urgent=bool(unh))
            if cleared:
                notifier.notify_all("🟢 LOCATOR HEALTH recovered (now verified): "
                                    + ", ".join(sorted(cleared)))
        except Exception as e:
            print(f"⚠️ health_alert_digest error: {e}")
        time.sleep(HEALTH_CHECK_INTERVAL)


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
                # A loadbalanced service may shed idle replicas — they drop out
                # of the emitted backend list while stopped — but the LAST one
                # carries the wake-on-502 path: stopping it too would leave the
                # emitted dead-upstream pointing nowhere wake can reach.
                if _policy_for(name).get("loadbalance"):
                    with lock:
                        online_replicas = sum(
                            1 for k, s in registry["services"].items()
                            if (k.split("@")[0] == name or s.get("name") == name)
                            and s.get("status") == "ONLINE")
                    if online_replicas <= 1:
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
            # Raw summaries, not SDK objects: a corrupt container (lists in
            # /containers/json but 404s on inspect — one exists on unit4) made
            # every lazy attribute fetch throw, killing the whole sweep each
            # tick. The low-level call returns plain dicts; nothing inspects.
            all_ctrs = docker_client.api.containers(all=True)
            running = {s["Names"][0].lstrip("/") for s in all_ctrs
                       if s.get("State") == "running" and s.get("Names")}
            _unit = UNIT_NAME or "unknown"
            import re as _re
            for ctr in all_ctrs:
                cname = (ctr.get("Names") or [""])[0].lstrip("/")
                for k, v in (ctr.get("Labels") or {}).items():
                    if not k.endswith(".rule"):
                        continue
                    hosts = _re.findall(r"Host\(`([^`]+)`\)", v)
                    for host in hosts:
                        url = "https://" + host
                        skey = "web_" + host.replace(".", "_").replace("-", "_")
                        status = "ONLINE" if cname in running else "OFFLINE"
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
                                "metadata": {"container": cname},
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
            targets = [(sid, svc.get("url"), (svc.get("metadata") or {}).get("container"))
                       for sid, svc in registry["services"].items()
                       if svc.get("category") in ("websites", "serverless")
                       and str(svc.get("url", "")).startswith("http")
                       and not _is_on_demand_url(svc.get("url"))]
            # Containers the locator itself put to sleep. They leave
            # _idle_state the moment they stop (lokey reports running
            # containers only), so without this set the next sweep would poll
            # a stopped service, fall into the catch-all's wake path, and
            # bring it straight back up — a stop/wake thrash every cycle.
            idle_stopped = {(svc.get("name") or "").lower()
                            for svc in registry["services"].values()
                            if (svc.get("metadata") or {}).get("idle_stopped")}
        with _idle_lock:
            watched = {name.lower() for _, name in _idle_state}

        changed = False
        for sid, url, container in targets:
            # The check itself is traffic. Polling a service the idle reaper
            # is timing out resets its clock forever (a GET every 60s vs a
            # 900s timeout — nothing could ever go idle), and polling one
            # already stopped fires the catch-all's wake path and brings it
            # straight back up. ON_DEMAND_HOSTS exists for the same reason;
            # this is the general case. The entry's status keeps tracking
            # the container through lokey registrations instead.
            if container and (container.lower() in watched
                             or container.lower() in idle_stopped):
                continue
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
        health_alert_digest,        # unverified/unhealthy container digests → reech
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
