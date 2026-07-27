"""
═══════════════════════════════════════════════
  THE LOCATOR — Universal Service Registry
  
  Single source of truth for every service,
  container, API, and daemon in the Beast mesh.
═══════════════════════════════════════════════
"""

import os
import json
import socket
import http.client
import threading
import time
import uuid
import queue as _queue_module
import requests
import re
import pandas as pd
from datetime import datetime, timezone
from flask import Flask, request, jsonify, Response, render_template

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
DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
SEED_FILE = os.environ.get("SEED_FILE", "/app/seed_registry.json")
EXCEL_FILE = "registry.xlsx"

# Load-balancer config
BALANCE_ENABLED  = os.environ.get("BALANCE_ENABLED", "true").lower() == "true"
BALANCE_HIGH     = float(os.environ.get("BALANCE_HIGH", "70"))   # % — node is overloaded above this
BALANCE_LOW      = float(os.environ.get("BALANCE_LOW",  "30"))   # % — node is a migration target below this
BALANCE_INTERVAL = int(os.environ.get("BALANCE_INTERVAL", "120"))  # seconds between balance checks
BALANCE_COOLDOWN = int(os.environ.get("BALANCE_COOLDOWN", "300"))  # seconds before re-migrating from same node
BALANCE_DIFF     = float(os.environ.get("BALANCE_DIFF", "40"))     # % spread between busiest/least busy to trigger balance
BALANCE_STRIKES  = int(os.environ.get("BALANCE_STRIKES", "2"))      # consecutive overloaded checks before migrating
OOM_THRESHOLD    = float(os.environ.get("OOM_THRESHOLD", "90"))     # % mem — emergency migration, bypasses anti-flap/cooldown

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
TRIPLE_ALLOWED = {"traefik", "apache", "lokey", "openvpn", "wireguard", "headscale", "tailscale", "bind"}

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

def enforce_instance_limits(container_name: str):
    """Stop the oldest running containers that exceed the limit for this service type."""
    if not docker_client:
        return
    base  = _base_name(container_name)
    limit = _max_instances(container_name)
    try:
        running = docker_client.containers.list()
        peers = [c for c in running if _base_name(c.name) == base and c.name != container_name]
        peers.sort(key=lambda c: c.attrs.get('State', {}).get('StartedAt', ''))
        while len(peers) >= limit:
            oldest = peers.pop(0)
            print(f"\u26a1 LIMIT ({limit}) exceeded for '{base}': stopping oldest \u2192 {oldest.name}")
            oldest.stop(timeout=10)
    except Exception as e:
        print(f"\u26a0\ufe0f Instance limit enforcement error: {e}")

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
    with migrations_lock:
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
        with migrations_lock:
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

def get_container_project_dir(container_name: str):
    """Return the docker-compose project.working_dir label for a container (running or stopped)."""
    if not docker_client:
        return None
    try:
        c = docker_client.containers.get(container_name)
        return c.labels.get("com.docker.compose.project.working_dir")
    except Exception:
        try:
            results = docker_client.containers.list(all=True, filters={"name": container_name})
            if results:
                return results[0].labels.get("com.docker.compose.project.working_dir")
        except Exception:
            pass
    return None

def git_pull_in_dir(project_dir: str):
    """Run git pull in a host-mounted project directory (best-effort)."""
    if not project_dir or not os.path.isdir(project_dir):
        return
    try:
        result = subprocess.run(
            ["git", "-C", project_dir, "pull"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print(f"\U0001f4e5 git pull OK: {project_dir}")
        else:
            print(f"\u26a0\ufe0f git pull warning ({project_dir}): {result.stderr.strip()}")
    except Exception as e:
        print(f"\u26a0\ufe0f git pull skipped ({project_dir}): {e}")

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


def _self_election():
    """
    Dedup election: only one locator should ever run across all units.
    On startup, ping the canonical URL. If another instance answers from a
    different unit, compare started_at times and stop whichever is oldest.
    The newer instance wins and stops the older one via lokey command.
    """
    if not LOCATOR_CANONICAL_URL:
        return
    time.sleep(20)  # let ourselves fully initialise first
    for attempt in range(3):
        try:
            r = requests.get(f"{LOCATOR_CANONICAL_URL}/health", timeout=5, verify=False)
            if r.status_code == 200:
                data = r.json()
                remote_unit = data.get("unit_name", "")
                if not remote_unit or remote_unit == UNIT_NAME:
                    # Same unit — no duplicate, nothing to do
                    return
                # A different unit has a locator running — dedup by start time
                remote_started_raw = data.get("started_at")
                try:
                    remote_started = datetime.fromisoformat(remote_started_raw)
                except Exception:
                    remote_started = None

                if remote_started and _STARTED_AT > remote_started:
                    # We are newer — stop the older remote instance
                    print(f"🗳️  Duplicate locator on '{remote_unit}' started {remote_started_raw} (older than us) — evicting it")
                    _queue_command(remote_unit, SELF_CONTAINER_NAME, "stop", source="dedup")
                else:
                    # We are older (or can't compare) — stop self, let the newer one win
                    print(f"🗳️  Newer locator running on '{remote_unit}' — stopping self on {UNIT_NAME}")
                    _stop_self()
                return
        except Exception as e:
            print(f"🗳️  Election attempt {attempt+1}/3: canonical unreachable ({e})")
        time.sleep(10)
    print("🗳️  Canonical not reachable after 3 attempts — staying active as sole instance")


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

        _svc_type = data.get("type", existing.get("type", "container"))
        _default_cat = _infer_category(_svc_type, data.get("url", existing.get("url", "")))
        registry["services"][service_id] = {
            "name": name,
            "category": data.get("category", existing.get("category", _default_cat)),
            "url": data.get("url", existing.get("url", "")),
            "internal": data.get("internal", existing.get("internal", "")),
            "host": host,
            "hosts": data.get("hosts", [host]),
            "port": data.get("port", existing.get("port", None)),
            "type": _svc_type,
            "status": "ONLINE",
            "last_heartbeat": now,
            "registered_at": existing.get("registered_at", now),
            "metadata": data.get("metadata", existing.get("metadata", {}))
        }
        # Update the node as ONLINE whenever any service heartbeats from it
        if host != "unknown" and host in registry["nodes"]:
            registry["nodes"][host]["status"] = "ONLINE"
            registry["nodes"][host]["last_seen"] = now
        registry["updated"] = now

    persist_registry()
    if host != "unknown":
        _enforce_dedup(name, host)
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



@app.route("/api/toggle", methods=["POST"])
def toggle_container():
    """Start or stop a Docker container via the Locator UI."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    name   = data.get("name", "").strip()
    action = data.get("action", "").strip()
    if not name or action not in ("start", "stop"):
        return jsonify({"error": "Provide 'name' and 'action' (start|stop)"}), 400
    if not docker_client:
        return jsonify({"error": "Docker socket unavailable"}), 503
    project_dir = get_container_project_dir(name)
    try:
        if action == "start":
            git_pull_in_dir(project_dir)
            enforce_instance_limits(name)
            try:
                container = docker_client.containers.get(name)
                container.start()
                msg = "started"
            except docker.errors.NotFound:
                if project_dir:
                    result = subprocess.run(
                        ["docker", "compose", "up", "-d"],
                        cwd=project_dir, capture_output=True, text=True, timeout=120
                    )
                    if result.returncode != 0:
                        return jsonify({"error": result.stderr.strip()}), 500
                    msg = "created_and_started"
                else:
                    return jsonify({"error": f"Container '{name}' not found and no compose dir known"}), 404
            now = datetime.now(timezone.utc).isoformat()
            with lock:
                for svc in registry["services"].values():
                    if svc.get("name", "").lower() == name.lower():
                        svc["status"] = "ONLINE"
                        svc["last_heartbeat"] = now
            persist_registry()
            print(f"\u25b6\ufe0f  TOGGLE: {name} \u2192 ONLINE")
            return jsonify({"result": msg, "container": name, "status": "ONLINE"})
        else:
            container = docker_client.containers.get(name)
            container.stop(timeout=15)
            git_pull_in_dir(project_dir)
            now = datetime.now(timezone.utc).isoformat()
            with lock:
                for svc in registry["services"].values():
                    if svc.get("name", "").lower() == name.lower():
                        svc["status"] = "OFFLINE"
                        svc["last_heartbeat"] = now
            persist_registry()
            print(f"\u23f9\ufe0f  TOGGLE: {name} \u2192 OFFLINE")
            return jsonify({"result": "stopped", "container": name, "status": "OFFLINE"})
    except docker.errors.NotFound:
        return jsonify({"error": f"Container '{name}' not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    """Return all docker-compose files discovered via live Docker container labels."""
    seen = set()
    results = []
    if docker_client:
        try:
            for c in docker_client.containers.list(all=True):
                proj_dir = c.labels.get("com.docker.compose.project.working_dir")
                if not proj_dir or proj_dir in seen:
                    continue
                seen.add(proj_dir)
                for fname in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                    fpath = os.path.join(proj_dir, fname)
                    if os.path.isfile(fpath):
                        results.append({"label": os.path.basename(proj_dir), "container": c.name, "path": fpath})
                        break
        except Exception as e:
            print(f"\u26a0\ufe0f YAML scan error: {e}")
    results.sort(key=lambda x: x["label"])
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
    return jsonify({"status": "logged"}), 200


@app.route("/api/client-errors", methods=["GET"])
def list_client_errors():
    """Return recently reported browser-side JS errors, newest first."""
    with client_error_lock:
        return jsonify(list(reversed(client_errors)))


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

    return jsonify({"result": "acknowledged"})



@app.route("/api/migrations", methods=["GET"])
def list_migrations():
    """Return all migrations (pending, in_progress, and completed) for dashboard visibility."""
    with migrations_lock:
        return jsonify(list(migration_queue.values()))

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

    return jsonify({
        "enabled":          BALANCE_ENABLED,
        "high_threshold":   BALANCE_HIGH,
        "low_threshold":    BALANCE_LOW,
        "diff_threshold":   BALANCE_DIFF,
        "interval_seconds": BALANCE_INTERVAL,
        "cooldown_seconds": BALANCE_COOLDOWN,
        "node_loads":       node_loads,
        "recent_migrations": recent,
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
    """Write the current registry to disk for file-based consumers."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        filepath = os.path.join(DATA_DIR, "registry.json")
        with lock:
            snapshot = json.dumps(registry, indent=2)
        with open(filepath, "w") as f:
            f.write(snapshot)
    except Exception as e:
        print(f"⚠️  Failed to persist registry: {e}")


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

    # Also try to restore persisted registry (overrides seed with live data)
    persisted_path = os.path.join(DATA_DIR, "registry.json")
    if os.path.exists(persisted_path):
        try:
            with open(persisted_path, "r") as f:
                persisted = json.load(f)
            # Merge persisted data (it takes priority over seed)
            for name, svc in persisted.get("services", {}).items():
                registry["services"][name] = svc
            for node_name, node_info in persisted.get("nodes", {}).items():
                registry["nodes"][node_name] = node_info
            registry["updated"] = persisted.get("updated", registry["updated"])
            print(f"💾 Restored persisted registry: {len(registry['services'])} services")
        except Exception as e:
            print(f"⚠️  Failed to restore persisted registry: {e}")

    ensure_core_services()


def ensure_core_services():
    """Ensures every known node has an entry for Apache, Bind, Traefik, and Lokey-Client."""
    now = datetime.now(timezone.utc).isoformat()
    core_services = ["apache", "bind", "traefik", "lokey-client"]

    with lock:
        nodes = list(registry["nodes"].keys())
        for node_id in nodes:
            for core in core_services:
                already_exists = any(
                    (svc["name"].lower() == core
                     or (core == "bind" and "bind" in svc["name"].lower())
                     or (core == "apache" and "httpd" in svc["name"].lower())
                     or (core == "lokey-client" and "lokey" in svc["name"].lower()))
                    and node_id in svc.get("hosts", [])
                    for svc in registry["services"].values()
                )
                if not already_exists:
                    registry["services"][f"{core}_{node_id}"] = {
                        "name": core,
                        "category": "docker containers",
                        "hosts": [node_id],
                        "status": "OFFLINE",
                        "last_heartbeat": "",
                        "registered_at": now,
                        "metadata": {"discovered_via": "core_enforcement"}
                    }
        registry["updated"] = now
    print(f"🛡️  Core services enforced for {len(nodes)} nodes")


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
            else:
                overload_strikes.pop(node_id, None)  # no longer overloaded

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

            # Find movable containers on this node
            movable = [
                (svc_id, svc)
                for svc_id, svc in services_snap.items()
                if svc.get("host") == src_id
                and svc.get("status") == "ONLINE"
                and svc.get("type") == "container"
                and svc.get("name") not in _PINNED_NAMES
                and not svc.get("metadata", {}).get("pinned")
            ]

            if not movable:
                print(f"⚠️  BALANCE: {src_id} overloaded but no movable containers found")
                continue

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

            # Pick target — first underloaded node that has a usable IP
            tgt_id = tgt_ip = tgt_info = tgt_load = None
            for _tid, _tload, _tinfo in underloaded:
                _tip = _best_ip(_tinfo)
                if _tip:
                    tgt_id, tgt_load, tgt_info, tgt_ip = _tid, _tload, _tinfo, _tip
                    break
            if not tgt_id:
                print(f"⚠️  BALANCE: no reachable target node for {src_id}")
                continue

            # Pick the container: oldest running first (most stable, least disruptive)
            movable.sort(key=lambda x: x[1].get("registered_at", ""))
            svc_id, svc = movable[0]
            container_name = svc["name"]

            src_ip = _best_ip(src_info) or ""
            mig_id = str(uuid.uuid4())[:8]
            with migration_lock:
                migration_queue[mig_id] = {
                    "id":         mig_id,
                    "container":  container_name,
                    "from_node":  src_id,
                    "from_ip":    src_ip,
                    "to_node":    tgt_id,
                    "to_ip":      tgt_ip,
                    "status":     "PENDING",
                    "queued_at":  now.isoformat(),
                    "reason":     f"{src_id} disk {src_load:.1f}% → {tgt_id} disk {tgt_load:.1f}%",
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
            # We want to scan all known node IPs (Internal and OpenVPN)
            nodes_to_scan = []
            for node_name, node_info in registry["nodes"].items():
                ips = [node_info.get("ip")]
                if node_info.get("openvpn_ip"):
                    ips.append(node_info.get("openvpn_ip"))
                
                for ip in ips:
                    if ip and ip != 'unknown' and 'pending' not in ip:
                        nodes_to_scan.append((node_name, ip))
            
        for node_name, ip in nodes_to_scan:
            # Try to hit Traefik API on default ports
            for port in [80, 8080, 443]:
                traefik_url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
                try:
                    resp = requests.get(f"{traefik_url}/api/http/routers", timeout=3)
                    if resp.status_code != 200: continue
                    
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

    # Critical service watchdog — immediately restarts apache, lokey, locator if OFFLINE
    threading.Thread(target=critical_service_watchdog, daemon=True).start()

    beast_log("🔦 LOCATOR online — registry loaded, telemetry forwarder active")
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()


