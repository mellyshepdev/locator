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
  LOCATOR_URL      Registry URL (default: https://tobsco-locator.fly.dev)
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
import queue as _queue_module
import requests
import urllib3
import re
import io
import qrcode
import pandas as pd
from datetime import datetime, timezone
from flask import Flask, request, jsonify, Response, render_template

import notifier
import db

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

# DNS zone status/sync (unit9 runs the PowerDNS primary with a sqlite3
# backend, at ns2.theofficialblacksheepco.online — DNS delegation for the
# .online zone completed 2026-08-07, so this resolves publicly now;
# reached over SSH with the SSH_USER/SSH_KEY above since Locator itself runs
# on Fly, not on the DNS box — see /api/dns/status and /api/dns/sync).
DNS_SSH_HOST = os.environ.get("DNS_SSH_HOST", "ns2.theofficialblacksheepco.online")
DNS_SSH_USER = os.environ.get("DNS_SSH_USER", "root")
DNS_ZONES = [z.strip() for z in os.environ.get(
    "DNS_ZONES",
    "theofficialblacksheepco.com,theofficialblacksheepco.info,"
    "theofficialblacksheepco.online,theofficialblacksheepco.store",
).split(",") if z.strip()]

# Load-balancer config
BALANCE_ENABLED  = os.environ.get("BALANCE_ENABLED", "true").lower() == "true"
BALANCE_HIGH     = float(os.environ.get("BALANCE_HIGH", "70"))   # % — node is overloaded above this
BALANCE_LOW      = float(os.environ.get("BALANCE_LOW",  "30"))   # % — node is a migration target below this
BALANCE_INTERVAL = int(os.environ.get("BALANCE_INTERVAL", "120"))  # seconds between balance checks
BALANCE_COOLDOWN = int(os.environ.get("BALANCE_COOLDOWN", "300"))  # seconds before re-migrating from same node
BALANCE_DIFF     = float(os.environ.get("BALANCE_DIFF", "40"))     # % spread between busiest/least busy to trigger balance
BALANCE_STRIKES  = int(os.environ.get("BALANCE_STRIKES", "2"))      # consecutive overloaded checks before migrating
OOM_THRESHOLD    = float(os.environ.get("OOM_THRESHOLD", "90"))     # % mem — emergency migration, bypasses anti-flap/cooldown

# Proactive pre-staging: watch nodes trending toward BALANCE_HIGH *before* they
# get there, and validate (not execute) a migration ahead of time so the real
# cutover — if it ends up being needed — has less work left to do. Derived
# from BALANCE_HIGH rather than a second absolute constant, so there's still
# only one number (BALANCE_HIGH) to reason about day to day.
BALANCE_PRESTAGE_ENABLED = os.environ.get("BALANCE_PRESTAGE_ENABLED", "true").lower() == "true"
BALANCE_PRESTAGE_MARGIN  = float(os.environ.get("BALANCE_PRESTAGE_MARGIN", "15"))  # % below BALANCE_HIGH that triggers pre-staging
PRESTAGE_STALE_SECONDS   = int(os.environ.get("PRESTAGE_STALE_SECONDS", "600"))    # re-validate if older than this

UNIT_NAME             = os.environ.get("UNIT_NAME", "unknown")
LOCATOR_CANONICAL_URL = os.environ.get("LOCATOR_CANONICAL_URL", "https://locator.theofficialblacksheepco.online")

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

        ip = (
            info.get("tailscale_ip")
            or info.get("openvpn_ip", "").split("-")[0].strip().split()[0]
            or info.get("ip", "").split("-")[0].strip().split()[0]
        )
        if not ip or ip in ("", "unknown"):
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
    """Append an event for the dashboard, trimming to EVENT_LOG_MAX."""
    entry = {
        "type": kind,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **extra,
    }
    with _event_lock:
        _event_log.append(entry)
        if len(_event_log) > EVENT_LOG_MAX:
            del _event_log[:-EVENT_LOG_MAX]
    return entry


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
    """Return the full registry — services + nodes."""
    with lock:
        return jsonify(registry)


@app.route("/services", methods=["GET"])
@app.route("/api/services", methods=["GET"])
def get_services():
    """Return all registered services."""
    with lock:
        return jsonify(registry["services"])


@app.route("/services/<name>", methods=["GET"])
def get_service(name):
    """Lookup a specific service by name (exact key, or container name with @host suffix)."""
    with lock:
        service = registry["services"].get(name)
        if not service:
            _, service = _find_service_entry(name)
    if service:
        return jsonify(service)
    return jsonify({"error": f"Service '{name}' not found"}), 404


def _enforce_dedup(new_name, new_host):
    """
    Cross-node dedup: when a new instance of a non-pinned container registers,
    evict the older running instance on any other node via a git_push_and_stop
    migration. The target's lokey then receives a git_pull_only task once the
    push completes (queued by complete_migration).
    """
    if any(p in new_name.lower() for p in _PINNED_NAMES):
        return  # infrastructure — allowed on multiple nodes

    with lock:
        instances = [
            dict(svc) for svc in registry["services"].values()
            if svc.get("name") == new_name and svc.get("status") == "ONLINE"
            and svc.get("type") == "container"  # never dedup websites/devices/apis
        ]
    hosts = {svc.get("host") for svc in instances if svc.get("host")}
    if len(hosts) <= 1:
        return  # nothing to evict

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
    if not path or not os.path.isfile(path):
        return jsonify({"error": "Not found"}), 404
    try:
        with open(path, "r", errors="replace") as f:
            return jsonify({"path": path, "content": f.read()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/yaml", methods=["POST"])
def save_yaml():
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "No path"}), 400
    data = request.get_json(silent=True)
    if not data or "content" not in data:
        return jsonify({"error": "No content"}), 400
    try:
        with open(path, "w") as f:
            f.write(data["content"])
        beast_log(f"\U0001f4dd YAML saved: {path}")
        return jsonify({"ok": True, "status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/deploy/<name>", methods=["POST"])
def deploy_compose(name):
    """
    Deploy a stored compose file to the most available node (or a pinned one).

    Optional JSON body:
    { "node": "unit2" }  — pin a specific target instead of auto-selecting
    """
    import yaml as _yaml
    import subprocess as _sp

    path = _compose_path(name)
    if not os.path.exists(path):
        return jsonify({"error": f"Compose file '{name}' not found"}), 404

    data = request.get_json(silent=True) or {}
    forced_node = data.get("node")

    if forced_node:
        with lock:
            node_info = registry["nodes"].get(forced_node, {})
        ip = (
            node_info.get("tailscale_ip")
            or node_info.get("openvpn_ip", "").split("-")[0].strip().split()[0]
            or node_info.get("ip", "").split("-")[0].strip().split()[0]
        )
        if not ip or ip in ("", "unknown"):
            return jsonify({"error": f"No reachable IP for node '{forced_node}'"}), 400
        target_node, target_ip = forced_node, ip
    else:
        target_node, target_ip = _best_available_node()
        if not target_node:
            return jsonify({"error": "No online nodes with reachable IPs"}), 503

    remote_dir  = f"/tmp/locator_deploy/{name}"
    remote_file = f"{remote_dir}/docker-compose.yml"
    # Use the SSH config alias (node name) so per-host port/user/key from ~/.ssh/config
    # are respected (e.g. unit1 tunnels through localhost:2222 with its own key).
    # Fall back to explicit user@ip only if no config alias exists.
    ssh_opts   = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
    ssh_target = target_node   # SSH config alias: unit1, unit2, unit3 …

    try:
        _sp.run(
            ["ssh"] + ssh_opts + [ssh_target, f"mkdir -p {remote_dir}"],
            check=True, capture_output=True, timeout=15
        )
        _sp.run(
            ["scp"] + ssh_opts + [path, f"{ssh_target}:{remote_file}"],
            check=True, capture_output=True, timeout=15
        )
        result = _sp.run(
            ["ssh"] + ssh_opts + [ssh_target, f"cd {remote_dir} && docker compose up -d"],
            capture_output=True, text=True, timeout=120
        )

        if result.returncode != 0:
            return jsonify({
                "error": "docker compose up failed",
                "stderr": result.stderr,
                "node": target_node,
            }), 500

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
            "result":  "deployed",
            "name":    name,
            "node":    target_node,
            "ip":      target_ip,
            "output":  result.stdout,
        }), 200

    except _sp.TimeoutExpired:
        return jsonify({"error": "SSH/SCP timed out", "node": target_node}), 504
    except _sp.CalledProcessError as e:
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return jsonify({"error": str(e), "stderr": stderr, "node": target_node}), 500
    except Exception as e:
        return jsonify({"error": str(e), "node": target_node}), 500


@app.route("/nodes", methods=["GET"])
@app.route("/api/nodes", methods=["GET"])
def get_nodes():
    """Return all known nodes."""
    with lock:
        return jsonify(registry["nodes"])


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


@app.route("/api/events", methods=["GET", "POST"])
def api_events():
    """Event feed backing the dashboard's EVENT LOG panel.

    The panel has always fetched this path, but no handler existed — so the log
    sat empty and its companion WebSocket (ws:// on an https page) was blocked
    as mixed content. Polling this endpoint replaces that socket.

    POST lets units report their own events (repo sync results, failed
    updates). Those failures previously only ever reached a container log on
    the unit itself, which is how a decommissioned URL and an 8-commit drift
    went unnoticed for weeks — here they surface on the dashboard instead.
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        message = str(data.get("message", ""))[:500]
        if not message:
            return jsonify({"error": "message required"}), 400
        kind = str(data.get("type", "unit"))[:40]
        unit = str(data.get("unit", ""))[:40]
        entry = record_event(kind, message, unit=unit)
        return jsonify({"result": "recorded", "timestamp": entry["timestamp"]})

    limit = request.args.get("limit", type=int) or EVENT_LOG_MAX
    with _event_lock:
        return jsonify(list(_event_log)[-limit:])


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
        event = {"type": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), **data}
    with _event_stream_lock:
        for q in _event_stream_queues:
            q.put(event)
    return event


@app.route("/api/events", methods=["GET"])
def list_events_route():
    """Return recent events, oldest first (matches what the dashboard expects to append in order)."""
    try:
        return jsonify(db.list_events(200))
    except Exception as e:
        print(f"⚠️  Failed to read events from Postgres: {e}")
        return jsonify([])


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
    """Serve the registry as a downloadable JSON file."""
    with lock:
        data = json.dumps(registry, indent=2)
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
    try:
        devices = _traccar_get("/api/devices").json()
        positions = {p["deviceId"]: p for p in _traccar_get("/api/positions").json()}
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
                    (node_id, dict(node.get("metadata") or {}))
                    for node_id, node in registry["nodes"].items()
                ]

            now_ms = time.time() * 1000
            for node_id, meta in candidates:
                lat, lon = meta.get("latitude"), meta.get("longitude")
                if lat is None or lon is None:
                    continue
                fix_time_ms = meta.get("location_time_ms")
                if fix_time_ms and (now_ms - fix_time_ms) > TRACCAR_FIX_MAX_AGE_S * 1000:
                    continue  # stale fix, phone hasn't moved/reported recently

                unique_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(node_id))
                _traccar_ensure_device(unique_id, node_id)

                params = {
                    "id": unique_id,
                    "lat": lat,
                    "lon": lon,
                    "timestamp": int((fix_time_ms or now_ms) / 1000),
                }
                if meta.get("location_accuracy_m") is not None:
                    params["accuracy"] = meta["location_accuracy_m"]
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
    """Receives user preferences and triggers the actual deployment."""
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
                      "mem_used_gb", "disk_free_gb"):
            if data.get(field) is not None:
                node[field] = data[field]
        if data.get("ip"):
            node["ip"] = data["ip"]
        if data.get("tailscale_ip"):
            node["tailscale_ip"] = data["tailscale_ip"]
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

    with migration_lock:
        if mig_id in migration_queue:
            mig = migration_queue[mig_id]
            mig["status"]       = "DONE" if success else "FAILED"
            mig["completed_at"] = datetime.now(timezone.utc).isoformat()
            print(f"{'✅' if success else '❌'} MIGRATION {mig_id}: {'DONE' if success else 'FAILED'}")
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

    return jsonify({"result": "acknowledged"})



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
        if svc.get("name") in _PINNED_NAMES:
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
                
                if not detected_hosts and category == "docker containers":
                    detected_hosts = ["unit1"]

                item_data = {
                    "name": name,
                    "category": category,
                    "url": str(row.get('publib ip', '')) if pd.notna(row.get('publib ip')) else "",
                    "internal": private_val if pd.notna(row.get('private')) else "",
                    "openvpn": openvpn_val if pd.notna(row.get('openvpn')) else "",
                    "hosts": detected_hosts if detected_hosts else ([name] if category == "devices" else ["unit1"]),
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
                            if "lokey" in name.lower():
                                node_id = svc.get("host", "")
                                if node_id and node_id in registry["nodes"]:
                                    registry["nodes"][node_id]["status"] = "OFFLINE"
                                    print(f"💀 NODE OFFLINE: {node_id}")
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
                if node.get("status") != "ONLINE":
                    continue
                last_seen = node.get("last_seen")
                if not last_seen:
                    continue
                try:
                    last = datetime.fromisoformat(last_seen)
                    if (now - last).total_seconds() > HEARTBEAT_TIMEOUT:
                        node["status"] = "OFFLINE"
                        changed = True
                        print(f"💀 NODE OFFLINE (stale heartbeat): {node_id}")
                except (ValueError, TypeError):
                    pass

        if changed:
            persist_registry()


# ── LOAD BALANCER ────────────────────────────────────────────────────────────

# Containers that must never be migrated or deduped automatically
_PINNED_NAMES = {
    "traefik", "apache", "apache2", "httpd", "varnish", "bind9", "bind",
    "openvpn", "openvpn-client", "headscale", "tailscale", "wireguard-client", "wireguard",
    "powerdns", "pdns", "ns1-auth", "ns1",
    "postgres", "postgresql", "redis", "mysql", "mariadb",
    "php-fpm", "barcode_db",
    "matrix_synapse", "matrix_element", "matrix_sms_bridge",
    "lokey", "lokey-client",
    "wg-easy", "crowdsec", "fail2ban",
}


def _clean_ip(raw):
    """Strip description suffixes like '10.0.0.1- hostname'."""
    if not raw:
        return None
    clean = raw.split("-")[0].strip().split()[0]
    return clean if clean and clean not in ("unknown", "") else None


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
    missing = [d for d in deps if services_snap.get(d, {}).get("status") != "ONLINE"]
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
                    and svc.get("name") not in _PINNED_NAMES
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
                and svc.get("name") not in _PINNED_NAMES
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
            
            for container in containers:
                name = container.name
                if name == "locator": continue
                
                with lock:
                    if name not in registry["services"]:
                        # Register new container discovered locally
                        _local_unit = os.environ.get("UNIT_NAME", "unknown")
                        registry["services"][name] = {
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
                        registry["services"][name]["status"] = "ONLINE"
                        registry["services"][name]["last_heartbeat"] = now
                        registry["services"][name].pop("offline_since", None)

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
    Detects containers running the same image more than once and stops the oldest.
    Skips infrastructure services listed in _PINNED_NAMES.
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
                by_image.setdefault(image_key, []).append(ctr)

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


def enforce_units_all():
    """Background: scan registry for services with 'units: all' and queue deploy commands."""
    time.sleep(30)  # let registry initialize
    while True:
        try:
            online_units = [
                unit_id for unit_id, info in registry.get("nodes", {}).items()
                if info.get("status") == "ONLINE"
            ]
            for svc_id, svc in registry.get("services", {}).items():
                units_spec = (svc.get("metadata") or {}).get("units", "")
                if units_spec == "all" and online_units:
                    for unit in online_units:
                        _queue_command(unit, svc_id, "deploy", source="units_all_enforcement")
        except Exception as e:
            print(f"⚠️  enforce_units_all error: {e}")
        time.sleep(60)


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


def _queue_command(unit, container, action, source="idle"):
    """Queue a container command for a unit's lokey. Deduped on unit+container+action."""
    with command_lock:
        for cmd in command_queue.values():
            if (cmd["unit"] == unit and cmd["container"] == container
                    and cmd["action"] == action and cmd["status"] in ("PENDING", "DISPATCHED")):
                return cmd
        cmd_id = str(uuid.uuid4())[:8]
        cmd = {
            "id": cmd_id, "unit": unit, "container": container, "action": action,
            "source": source, "status": "PENDING",
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "dispatched_at": None, "completed_at": None, "success": None,
        }
        command_queue[cmd_id] = cmd
        done = [c for c in command_queue.values() if c["status"] in ("DONE", "FAILED")]
        if len(done) > COMMAND_RETENTION:
            done.sort(key=lambda c: c["completed_at"] or "")
            for old in done[: len(done) - COMMAND_RETENTION]:
                command_queue.pop(old["id"], None)
        print(f"📨 COMMAND QUEUED: {action} '{container}' on {unit} ({source})")
        return cmd


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
                # Re-serve only if the lokey never reported back (crashed mid-command)
                try:
                    age = (now - datetime.fromisoformat(cmd["dispatched_at"])).total_seconds()
                except (TypeError, ValueError):
                    age = COMMAND_RETRY_SECONDS + 1
                if age <= COMMAND_RETRY_SECONDS:
                    continue
            elif cmd["status"] != "PENDING":
                continue
            cmd["status"] = "DISPATCHED"
            cmd["dispatched_at"] = now.isoformat()
            out.append(dict(cmd))
    return jsonify(out)


@app.route("/api/commands/complete", methods=["POST"])
def commands_complete():
    """Lokey reports command results; stop/start results update the registry."""
    data = request.get_json(silent=True) or {}
    cmd_id  = data.get("id")
    success = bool(data.get("success"))
    now = datetime.now(timezone.utc)
    with command_lock:
        cmd = command_queue.get(cmd_id)
        if not cmd:
            return jsonify({"error": "unknown command"}), 404
        cmd["status"] = "DONE" if success else "FAILED"
        cmd["success"] = success
        cmd["completed_at"] = now.isoformat()
        cmd = dict(cmd)

    print(f"{'✅' if success else '❌'} COMMAND {cmd['action']} '{cmd['container']}' on {cmd['unit']}: {'ok' if success else 'failed'}")

    if success:
        with lock:
            _, svc = _find_service_entry(cmd["container"])
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
                st = _idle_state.get((cmd["unit"], cmd["container"]))
                if st:
                    st["stopped_count"] += 1
    return jsonify({"ok": True})


def _find_service_entry(container):
    """Locate a container's registry entry — keys may be 'name' or 'name@host'.
    Caller must hold `lock`. Returns (key, svc) or (None, None)."""
    svc = registry["services"].get(container)
    if svc:
        return container, svc
    for key, s in registry["services"].items():
        if key.split("@")[0] == container or s.get("name") == container:
            return key, s
    return None, None


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


@app.route("/wake/<container>", methods=["GET"])
def wake_page(container):
    """Click-to-wake: queue the start command and show a page that redirects
    to the service once lokey reports it back ONLINE."""
    unit = _find_container_unit(container)
    if not unit:
        return Response(f"Unknown container '{container}'", status=404)
    _queue_command(unit, container, "start", source="wake")
    # Optional explicit redirect target (?to=...), restricted to our own domains
    target = request.args.get("to", "")
    if target and not re.match(
            r"^https://[a-z0-9.-]+\.theofficialblacksheepco\.(com|info|online|store)(/|$)", target):
        target = ""
    if not target:
        with lock:
            _, svc = _find_service_entry(container)
            target = (svc or {}).get("url", "") or ""
    html = f"""<!doctype html>
<html><head><title>Waking {container}…</title>
<style>
  body {{ background:#0a0e14; color:#e6e6e6; font-family:monospace;
         display:flex; align-items:center; justify-content:center;
         height:100vh; margin:0; }}
  .box {{ text-align:center; }}
  .pulse {{ font-size:3rem; animation:p 1.2s infinite; }}
  @keyframes p {{ 50% {{ opacity:.3; }} }}
</style></head>
<body><div class="box">
  <div class="pulse">💤 → 🟢</div>
  <h2>Waking {container} on {unit}…</h2>
  <p id="status">start command queued — usually under a minute</p>
</div>
<script>
  const target = {json.dumps(target)};
  async function poll() {{
    try {{
      const r = await fetch("/services/{container}");
      if (r.ok) {{
        const svc = await r.json();
        if (svc.status === "ONLINE") {{
          document.getElementById("status").textContent = "awake — redirecting…";
          if (target) {{ location.href = target; return; }}
          document.getElementById("status").textContent = "awake ✓";
          return;
        }}
      }}
    }} catch (e) {{}}
    setTimeout(poll, 5000);
  }}
  poll();
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
    for c in certs:
        if c.get("error") or (c.get("days_left") is not None and c["days_left"] < CERT_WARN_DAYS):
            print(f"🔐 CERT WARNING [{unit}] {c.get('host')}: "
                  f"{c.get('error') or str(c.get('days_left')) + ' days left'}")
    return jsonify({"ok": True, "received": len(certs)})


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
                            node["status"] = "OFFLINE"
                            node["last_seen"] = node.get("last_seen") or now
                            changed = True
                            print(f"💀 NODE OFFLINE (traefik unreachable): {node_name}")

        if changed:
            persist_registry()

        time.sleep(SCANNER_INTERVAL)



# ── WEBSITE PINGER ───────────────────────────────────────────────────────────

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
                       and str(svc.get("url", "")).startswith("http")]

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


# ── CRITICAL SERVICE WATCHDOG ────────────────────────────────────────────────

# Services that must always be running — immediately queued for restart on OFFLINE
_WATCHDOG_SERVICES = {
    "apache",       # welcome site (unit2)
    "lokey",        # lokey agent (all units)
    "lokey-client", # lokey agent alt name
    "locator",      # self (Docker restart=always is primary; this catches lokey-reported gaps)
}
_watchdog_cooldown: dict = {}   # key: (unit, container) → datetime of last restart attempt
WATCHDOG_INTERVAL  = 15         # seconds between watchdog scans
WATCHDOG_COOLDOWN  = 90         # seconds before re-queuing restart for same service
WATCHDOG_MAX_AGE   = 3 * 86400  # ignore services OFFLINE for more than 3 days (stale entries)

def critical_service_watchdog():
    """Immediately queues a start command when a critical service goes OFFLINE."""
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        now = datetime.now(timezone.utc)
        with lock:
            services_snap = {k: dict(v) for k, v in registry["services"].items()}
            nodes_snap    = {k: dict(v) for k, v in registry["nodes"].items()}

        for name, svc in services_snap.items():
            base = name.split("@")[0].lower()
            if not any(w == base for w in _WATCHDOG_SERVICES):
                continue
            if svc.get("status") != "OFFLINE":
                continue
            unit = svc.get("host", "")
            if not unit:
                continue
            # Skip units that are themselves OFFLINE — commands will never be consumed
            if nodes_snap.get(unit, {}).get("status") != "ONLINE":
                continue
            # Skip stale entries — services OFFLINE for more than WATCHDOG_MAX_AGE
            offline_since = svc.get("offline_since")
            if offline_since:
                try:
                    age = (now - datetime.fromisoformat(offline_since)).total_seconds()
                    if age > WATCHDOG_MAX_AGE:
                        continue
                except (TypeError, ValueError):
                    pass
            key = (unit, name)
            last = _watchdog_cooldown.get(key)
            if last and (now - last).total_seconds() < WATCHDOG_COOLDOWN:
                continue
            _watchdog_cooldown[key] = now
            _queue_command(unit, name.split("@")[0], "start", source="watchdog")
            print(f"🚨 WATCHDOG: queued restart for '{name}' on {unit}")


# ── STARTUP ─────────────────────────────────────────────────────────────────

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

    # Forward logs to beast-telemetry / live-logger
    threading.Thread(target=_log_forwarder, daemon=True).start()

    # Start the heartbeat reaper in the background
    reaper = threading.Thread(target=heartbeat_reaper, daemon=True)
    reaper.start()

    # Start the local Docker scanner
    docker_scanner = threading.Thread(target=local_docker_scanner, daemon=True)
    docker_scanner.start()

    # Start the duplicate killer
    killer = threading.Thread(target=duplicate_killer, daemon=True)
    killer.start()

    # Start the active discovery scanner
    scanner = threading.Thread(target=active_discovery_scanner, daemon=True)
    scanner.start()

    # Start the website pinger
    pinger = threading.Thread(target=website_pinger, daemon=True)
    pinger.start()

    # Start the URL status checker (websites + serverless, no Docker needed)
    threading.Thread(target=url_status_checker, daemon=True).start()

    # Start the load balancer
    if BALANCE_ENABLED:
        balancer = threading.Thread(target=load_balancer, daemon=True)
        balancer.start()

    # Start the idle auto-shutdown reaper
    if IDLE_ENABLED:
        threading.Thread(target=idle_reaper, daemon=True).start()

    # Start the compose git-backup worker (single thread, event-driven)
    if GIT_AUTO_PUSH:
        threading.Thread(target=_git_push_worker, daemon=True).start()

    # Self-election: secondaries stop themselves if the canonical primary is up
    threading.Thread(target=_self_election, daemon=True).start()

    # Enforce "units: all" deployments — queue deploy commands for all ONLINE units
    threading.Thread(target=enforce_units_all, daemon=True).start()

    # Critical service watchdog — immediately restarts apache, lokey, locator if OFFLINE
    threading.Thread(target=critical_service_watchdog, daemon=True).start()

    # Feed Lokey's already-collected GPS fixes into Traccar
    threading.Thread(target=traccar_feeder, daemon=True).start()

    beast_log("🔦 LOCATOR online — registry loaded, telemetry forwarder active")
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()
else:
    # When imported by Gunicorn or other WSGI servers, initialize the app
    try:
        load_seed()
        persist_registry()
        # Start background threads
        import threading
        threading.Thread(target=heartbeat_reaper, daemon=True).start()
        threading.Thread(target=local_docker_scanner, daemon=True).start()
        threading.Thread(target=duplicate_killer, daemon=True).start()
        threading.Thread(target=active_discovery_scanner, daemon=True).start()
        threading.Thread(target=website_pinger, daemon=True).start()
        if BALANCE_ENABLED:
            threading.Thread(target=load_balancer, daemon=True).start()
        if IDLE_ENABLED:
            threading.Thread(target=idle_reaper, daemon=True).start()
        if GIT_AUTO_PUSH:
            threading.Thread(target=_git_push_worker, daemon=True).start()
        threading.Thread(target=_self_election, daemon=True).start()
        threading.Thread(target=critical_service_watchdog, daemon=True).start()
        threading.Thread(target=traccar_feeder, daemon=True).start()
        beast_log("🔦 LOCATOR online (Gunicorn) — registry loaded, telemetry forwarder active")
    except Exception as e:
        print(f"ERROR initializing LOCATOR in Gunicorn mode: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()


