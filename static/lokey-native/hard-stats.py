import psutil
import time
import os
import re
import subprocess
import requests
import urllib3
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOCATOR_URL = os.getenv("LOCATOR_URL", "https://tobsco-locator.fly.dev")
LOCATOR_HOST_HEADER = os.getenv("LOCATOR_HOST_HEADER", "locator.theofficialblacksheepco.online")
UNIT_NAME   = os.getenv("UNIT_NAME", "unknown_unit")
TICK_RATE   = int(os.getenv("TICK_RATE", "60"))
UNIT_HOST   = os.getenv("UNIT_HOST", "")   # hostname/domain that other units use to SSH here
REMOTE_USER = os.getenv("REMOTE_USER", "swoopg111")
LOKEY_PROJECT_DIR = os.getenv("LOKEY_PROJECT_DIR", f"/home/{REMOTE_USER}/projects/lokey")

# ── Locator failover ─────────────────────────────────────────────────────────
# Opt-in per unit (only units that keep a standby locator checkout should set
# these). If the canonical locator misses LOCATOR_MISS_THRESHOLD consecutive
# heartbeats, this unit brings its own standby locator up. Locator's own
# cross-node dedup (now that "locator" is unpinned) migrates/evicts whichever
# duplicate has the older heartbeat once both are visible in the registry.
LOCATOR_FAILOVER_ENABLED = os.getenv("LOCATOR_FAILOVER_ENABLED", "false").lower() == "true"
LOCATOR_COMPOSE_DIR      = os.getenv("LOCATOR_COMPOSE_DIR", "")
LOCATOR_MISS_THRESHOLD   = int(os.getenv("LOCATOR_MISS_THRESHOLD", "3"))

# ── DDNS config ───────────────────────────────────────────────────────────────
DDNS_ENABLED  = os.getenv("DDNS_ENABLED", "true").lower() == "true"
DDNS_KEY_NAME = "ddns-key"
DDNS_SECRET   = os.getenv("DDNS_SECRET", "")
DDNS_BIND_CONTAINER = os.getenv("DDNS_BIND_CONTAINER", "ns1-auth")
PDNS_API_URL  = os.getenv("PDNS_API_URL", "")
PDNS_API_KEY  = os.getenv("PDNS_API_KEY", "")
# Zones and the A-record names within them that track the unit1 home IP
DDNS_ZONES = {
    "theofficialblacksheepco.com": [
        "@", "ns1", "a0", "a1", "inventory", "wg", "webmail", "images",
        "search", "parts", "login", "auth", "welcome", "api.welcome",
        "terminal", "logs", "traefik",
    ],
    "theofficialblacksheepco.info": [
        "@", "ns1", "db", "mail", "inventory", "scanner", "logs",
        "matrix", "calendar", "webmail", "images",
    ],
}

try:
    import docker as docker_sdk
    _docker_client = docker_sdk.from_env()
except Exception:
    _docker_client = None

def get_system_stats():
    cpu_usage = psutil.cpu_percent(interval=1)

    cpu_temp = None
    try:
        temps = psutil.sensors_temperatures()
        if 'coretemp' in temps:
            cpu_temp = temps['coretemp'][0].current
        elif temps:
            cpu_temp = next(iter(temps.values()))[0].current
    except Exception:
        pass

    mem = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage('/')
        disk_total = round(disk.total / (1024**3), 2)
        disk_used = round(disk.used / (1024**3), 2)
        disk_percent = disk.percent
    except Exception:
        disk_total = disk_used = disk_percent = 0

    return {
        "cpu_usage_percent": cpu_usage,
        "cpu_temp_c": cpu_temp,
        "mem_total_gb": round(mem.total / (1024**3), 2),
        "mem_used_gb": round(mem.used / (1024**3), 2),
        "mem_percent": mem.percent,
        "disk_total_gb": disk_total,
        "disk_used_gb": disk_used,
        "disk_percent": disk_percent,
    }

def extract_traefik_hosts(labels):
    """Return hostnames declared in Traefik Host(...) router rules."""
    hosts = []
    for key, value in labels.items():
        if re.match(r"traefik\.http\.routers\..+\.rule", key):
            hosts += re.findall(r"Host\(`([^`]+)`\)", value)
    return hosts


def _get_container_ram(container):
    """Return (mem_usage_mb, mem_limit_mb, mem_percent) for a running container."""
    try:
        raw = container.stats(stream=False)
        mem = raw.get("memory_stats", {})
        usage = mem.get("usage", 0)
        limit = mem.get("limit", 1)
        cache = mem.get("stats", {}).get("inactive_file", 0)
        rss = max(0, usage - cache)
        return (
            round(rss / (1024 ** 2), 1),
            round(limit / (1024 ** 2), 1),
            round(rss / limit * 100, 1) if limit > 0 else 0.0,
        )
    except Exception:
        return (None, None, None)


def get_docker_containers():
    if not _docker_client:
        return {"running": [], "all": []}
    try:
        running = []
        for c in _docker_client.containers.list():
            mem_usage_mb, mem_limit_mb, mem_percent = _get_container_ram(c)
            compose_dir = c.labels.get("com.docker.compose.project.working_dir")
            networks = list(c.attrs.get("NetworkSettings", {}).get("Networks", {}).keys()) if c.attrs else []
            running.append({
                "name": c.name,
                "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                "labels": c.labels,
                "compose_dir": compose_dir,
                "mem_usage_mb": mem_usage_mb,
                "mem_limit_mb": mem_limit_mb,
                "mem_percent": mem_percent,
                "networks": networks,
            })
        all_containers = [
            {"name": c.name, "status": c.status}
            for c in _docker_client.containers.list(all=True)
        ]
        return {"running": running, "all": all_containers}
    except Exception as e:
        return {"running": [], "all": [], "error": str(e)}

def get_tailscale_ip():
    """Return host's Tailscale IP (100.x.x.x).

    Tries, in order:
      1. `tailscale ip -4` — portable across Linux/macOS/Windows, and the only
         option that works for NATIVE (non-Docker) installs, since those already
         run in the host's own network namespace (no nsenter available/needed —
         nsenter doesn't even exist on macOS, and requires root on Linux).
      2. `nsenter -t 1 -n ip addr show tailscale0` — Docker-only fallback, for
         containers that don't have the `tailscale` CLI itself but do have host
         PID/net namespace access, reading the HOST's tailscale0 interface.
      3. `ip -4 addr show tailscale0` directly — covers native Linux boxes where
         the `tailscale` CLI isn't on PATH but the interface is still visible.
    """
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            ip = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ""
            if ip:
                return ip
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["nsenter", "-t", "1", "-n", "ip", "-4", "addr", "show", "tailscale0"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1].split("/")[0]
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "tailscale0"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1].split("/")[0]
    except Exception:
        pass

    return None


def get_os_info():
    """Return host OS description string.

    Tries /host/etc/os-release first (works when lokey runs inside Docker with
    / mounted at /host).  Falls back to the local /etc/os-release, then
    lsb_release (Linux), then sw_vers (macOS native), then platform.platform().
    """
    for path in ("/host/etc/os-release", "/etc/os-release"):
        try:
            data = {}
            for line in open(path).read().splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip().strip('"')
            pretty = data.get("PRETTY_NAME") or data.get("NAME")
            if pretty:
                return pretty
        except Exception:
            pass
    try:
        r = subprocess.run(["lsb_release", "-d"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.strip().replace("Description:\t", "").replace("Description:", "").strip()
    except Exception:
        pass
    try:
        name = subprocess.run(["sw_vers", "-productName"], capture_output=True, text=True, timeout=5).stdout.strip()
        ver  = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True, timeout=5).stdout.strip()
        if name and ver:
            return f"{name} {ver}"
    except Exception:
        pass
    import platform
    return platform.platform()

_OS_INFO = get_os_info()


def upload_compose(container_name, compose_dir, headers):
    """Upload a container's docker-compose.yml to the locator compose store."""
    if not compose_dir:
        return
    host_path = f"/host{compose_dir}/docker-compose.yml"
    if not os.path.exists(host_path):
        return
    try:
        with open(host_path) as f:
            content = f.read()
        requests.post(
            f"{LOCATOR_URL}/api/compose/{container_name}",
            data=content,
            headers={**headers, "Content-Type": "text/yaml"},
            timeout=5, verify=False,
        )
    except Exception:
        pass


def push_node_metrics(stats):
    """Push cpu/mem/disk/os/tailscale_ip to the locator node registry.

    Tries PATCH /nodes/{id}/metrics first (newer locators).  Falls back to a
    GET-then-merge-then-POST strategy so existing node fields (name, ip, etc.)
    are preserved on older locators that only have POST /nodes.
    """
    headers = {"Host": LOCATOR_HOST_HEADER}
    metrics = {
        "cpu_percent":   stats["cpu_usage_percent"],
        "mem_percent":   stats["mem_percent"],
        "disk_percent":  stats["disk_percent"],
        "disk_total_gb": stats["disk_total_gb"],
        "disk_used_gb":  stats["disk_used_gb"],
        "os":            _OS_INFO,
        "status":        "ONLINE",
        "last_seen":     datetime.now(timezone.utc).isoformat(),
    }
    ts_ip = get_tailscale_ip()
    if ts_ip:
        metrics["tailscale_ip"] = ts_ip
    if UNIT_HOST:
        metrics["hostname"] = UNIT_HOST

    try:
        resp = requests.patch(
            f"{LOCATOR_URL}/nodes/{UNIT_NAME}/metrics",
            json=metrics, headers=headers, timeout=5, verify=False,
        )
        if resp.status_code < 300:
            return
    except Exception:
        pass

    # PATCH unsupported or failed — GET current node, merge, POST back
    try:
        existing = {}
        r = requests.get(f"{LOCATOR_URL}/nodes", headers=headers, timeout=5, verify=False)
        if r.status_code == 200:
            existing = r.json().get(UNIT_NAME, {})
        merged = {**existing, **metrics}
        requests.post(
            f"{LOCATOR_URL}/nodes",
            json={UNIT_NAME: merged}, headers=headers, timeout=5, verify=False,
        )
    except Exception as e:
        print(f"[{UNIT_NAME}] Failed to push node metrics: {e}")

def register_stats():
    stats = get_system_stats()
    containers = get_docker_containers()
    running = containers.get("running", [])

    running_names = [c["name"] if isinstance(c, dict) else c for c in running]
    containers_ram = {
        c["name"]: {"mem_mb": c["mem_usage_mb"], "mem_pct": c["mem_percent"]}
        for c in running
        if isinstance(c, dict) and c.get("mem_usage_mb") is not None
    }
    containers_summary = {
        "running": running_names,
        "all": containers.get("all", []),
        "ram": containers_ram,
    }

    payload = {
        "name": "lokey-client",
        "host": UNIT_NAME,
        "type": "container",
        "status": "ONLINE",
        "metadata": {**stats, "os": _OS_INFO, "containers": containers_summary},
    }

    headers = {"Host": LOCATOR_HOST_HEADER}
    try:
        resp = requests.post(
            f"{LOCATOR_URL}/register", json=payload,
            headers=headers, timeout=5, allow_redirects=True, verify=False
        )
        print(f"[{UNIT_NAME}] Heartbeat sent: {resp.status_code} | disk: {stats['disk_percent']}% | containers: {len(running)}")
    except Exception as e:
        print(f"[{UNIT_NAME}] Failed to reach locator at {LOCATOR_URL}: {e}")

    push_node_metrics(stats)

    for c in running:
        name = c["name"] if isinstance(c, dict) else c
        image = c.get("image", "") if isinstance(c, dict) else ""
        labels = c.get("labels", {}) if isinstance(c, dict) else {}
        compose_dir = c.get("compose_dir") if isinstance(c, dict) else None
        container_payload = {
            "name": name,
            "host": UNIT_NAME,
            "type": "container",
            "category": "docker containers",
            "status": "ONLINE",
            "metadata": {
                "discovered_via": "lokey",
                "image": image,
                "mem_usage_mb": c.get("mem_usage_mb") if isinstance(c, dict) else None,
                "mem_limit_mb": c.get("mem_limit_mb") if isinstance(c, dict) else None,
                "mem_percent": c.get("mem_percent") if isinstance(c, dict) else None,
                "networks": c.get("networks", []) if isinstance(c, dict) else [],
            },
        }
        try:
            requests.post(
                f"{LOCATOR_URL}/register", json=container_payload,
                headers=headers, timeout=5, allow_redirects=True, verify=False
            )
        except Exception:
            pass

        upload_compose(name, compose_dir, headers)

        for host in extract_traefik_hosts(labels):
            url = f"https://{host}"
            key = "web_" + re.sub(r"[^a-z0-9]", "_", host.lower())
            web_payload = {
                "name": key,
                "host": UNIT_NAME,
                "type": "web",
                "category": "web services",
                "status": "ONLINE",
                "url": url,
                "metadata": {"discovered_via": "traefik_labels", "container": name},
            }
            try:
                requests.post(
                    f"{LOCATOR_URL}/register", json=web_payload,
                    headers=headers, timeout=5, allow_redirects=True, verify=False
                )
            except Exception:
                pass

# ── MIGRATION EXECUTOR ───────────────────────────────────────────────────────

def _find_ssh_key():
    """Return the first usable private key in /root/.ssh."""
    ssh_dir = "/root/.ssh"
    for name in ["unit2to4", "id_ed25519", "id_rsa", "4to1", "unit2to1"]:
        path = os.path.join(ssh_dir, name)
        if os.path.exists(path):
            return path
    try:
        for f in os.listdir(ssh_dir):
            if not f.endswith(".pub") and "config" not in f and "known_hosts" not in f:
                return os.path.join(ssh_dir, f)
    except Exception:
        pass
    return None

def _ssh(ip, cmd, timeout=120):
    """Run a command on a remote host via SSH."""
    key = _find_ssh_key()
    ssh_cmd = [
        "ssh",
        "-F", "/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
    ]
    if key:
        ssh_cmd += ["-i", key]
    ssh_cmd += [f"{REMOTE_USER}@{ip}", cmd]
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return result.returncode == 0, result.stdout.strip(), result.stderr.strip()

def _get_compose_dir(container_name):
    """Return the docker-compose project directory for a container."""
    if not _docker_client:
        return None
    try:
        c = _docker_client.containers.get(container_name)
        return c.labels.get("com.docker.compose.project.working_dir")
    except Exception:
        return None

def execute_migration(mig):
    """
    Dispatch a migration based on its type.
      git_push_and_stop  — commit + push this container's project, then stop it here.
      git_pull_and_start — pull (or clone) the project on this node, docker compose up -d.
      git_pull_only      — pull (or clone) to sync state; container already running here.
      (default/legacy)   — rsync project to target, compose up there, compose down here.
    Returns (success: bool, extra: dict) where extra carries data for the locator
    completion report (e.g. project_dir so locator can create the follow-on pull task).
    """
    mig_type = mig.get("type", "rsync")
    if mig_type == "git_push_and_stop":
        return _execute_git_push_and_stop(mig)
    if mig_type == "git_pull_and_start":
        return _execute_git_pull_and_start(mig)
    if mig_type == "git_pull_only":
        return _execute_git_pull_only(mig)
    return _execute_rsync_migration(mig), {}


def _host_dir(project_dir):
    """Return the host-side path for a path that may be container-internal."""
    candidate = f"/host{project_dir}"
    return candidate if os.path.isdir(candidate) else project_dir


def _execute_git_push_and_stop(mig):
    """
    1. git add -A + commit + push the container's compose project.
    2. docker compose down the container on this node.
    Reports project_dir back so locator can create the matching pull task.
    """
    mig_id    = mig["id"]
    name      = mig["container"]
    to_node   = mig.get("to_node", "?")

    print(f"[{UNIT_NAME}] 📤 git_push_and_stop {mig_id}: {name} → {to_node}")

    project_dir = _get_compose_dir(name)
    if not project_dir:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: no compose dir for {name}")
        return False, {}

    host = _host_dir(project_dir)
    git_env = {**os.environ, "GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes"}

    # Stage and commit (may be a no-op if nothing changed — that's fine)
    subprocess.run(["git", "-C", host, "add", "-A"], timeout=30, env=git_env)
    subprocess.run(
        ["git", "-C", host, "commit", "-m", f"[lokey-migrate] export {name}"],
        timeout=30, env=git_env, capture_output=True,
    )

    push = subprocess.run(
        ["git", "-C", host, "push"],
        capture_output=True, text=True, timeout=60, env=git_env,
    )
    is_dedup = mig.get("dedup", False)
    if push.returncode != 0:
        msg = push.stderr.strip()[:200]
        if is_dedup:
            # Dedup goal is just to stop the duplicate — git push is best-effort
            print(f"[{UNIT_NAME}] ⚠️  {mig_id}: git push failed (dedup, continuing to stop): {msg}")
        else:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: git push failed: {msg}")
            return False, {}

    print(f"[{UNIT_NAME}] ✅ {mig_id}: git push done — stopping {name}")

    # Capture remote URL so the target can clone if it doesn't have the repo yet
    remote_result = subprocess.run(
        ["git", "-C", host, "remote", "get-url", "origin"],
        capture_output=True, text=True, timeout=10,
    )
    git_remote = remote_result.stdout.strip() if remote_result.returncode == 0 else ""

    # Stop container
    try:
        if _docker_client:
            c = _docker_client.containers.get(name)
            c.stop(timeout=30)
            subprocess.run(["docker", "compose", "down"], cwd=host, capture_output=True, timeout=60)
    except Exception as e:
        print(f"[{UNIT_NAME}] ⚠️  {mig_id}: stop warning: {e}")

    print(f"[{UNIT_NAME}] ✅ {mig_id}: git_push_and_stop complete — {name} handed off to {to_node}")
    return True, {"project_dir": project_dir, "git_remote": git_remote}


def _execute_git_pull_and_start(mig):
    """
    1. git pull the container's compose project.
    2. docker compose up -d on this node.
    """
    mig_id      = mig["id"]
    name        = mig["container"]
    project_dir = mig.get("project_dir", "")

    print(f"[{UNIT_NAME}] 📥 git_pull_and_start {mig_id}: {name} (dir: {project_dir})")

    if not project_dir:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: no project_dir provided")
        return False, {}

    host = _host_dir(project_dir)
    if not os.path.isdir(host):
        print(f"[{UNIT_NAME}] ❌ {mig_id}: project dir not found: {host}")
        return False, {}

    git_env = {**os.environ, "GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes"}

    if not os.path.isdir(host):
        git_remote = mig.get("git_remote", "")
        if not git_remote:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: dir missing and no git_remote provided")
            return False, {}
        os.makedirs(os.path.dirname(host), exist_ok=True)
        clone = subprocess.run(
            ["git", "clone", git_remote, host],
            capture_output=True, text=True, timeout=120, env=git_env,
        )
        if clone.returncode != 0:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: git clone failed: {clone.stderr.strip()[:200]}")
            return False, {}
        print(f"[{UNIT_NAME}] 📥 {mig_id}: git clone OK → {host}")
    else:
        pull = subprocess.run(
            ["git", "-C", host, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=60, env=git_env,
        )
        if pull.returncode != 0:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: git pull failed: {pull.stderr.strip()[:200]}")
            return False, {}

    result = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd=host, capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: compose up failed: {result.stderr.strip()[:200]}")
        return False, {}

    print(f"[{UNIT_NAME}] ✅ {mig_id}: git_pull_and_start complete — {name} running")
    return True, {}


def _execute_git_pull_only(mig):
    """
    Sync state from the just-evicted node without restarting the container.
    Used after a dedup eviction: the container is already running here; we just
    need to pull the final committed state the old instance pushed before stopping.
    """
    mig_id      = mig["id"]
    name        = mig["container"]
    project_dir = mig.get("project_dir", "")

    print(f"[{UNIT_NAME}] 🔄 git_pull_only {mig_id}: {name} (dir: {project_dir})")

    if not project_dir:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: no project_dir provided")
        return False, {}

    host = _host_dir(project_dir)
    git_env = {**os.environ, "GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes"}

    if not os.path.isdir(host):
        git_remote = mig.get("git_remote", "")
        if not git_remote:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: dir missing and no git_remote provided")
            return False, {}
        os.makedirs(os.path.dirname(host), exist_ok=True)
        clone = subprocess.run(
            ["git", "clone", git_remote, host],
            capture_output=True, text=True, timeout=120, env=git_env,
        )
        if clone.returncode != 0:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: git clone failed: {clone.stderr.strip()[:200]}")
            return False, {}
        print(f"[{UNIT_NAME}] 📥 {mig_id}: git clone OK → {host}")
    else:
        pull = subprocess.run(
            ["git", "-C", host, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=60, env=git_env,
        )
        if pull.returncode != 0:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: git pull failed: {pull.stderr.strip()[:200]}")
            return False, {}

    print(f"[{UNIT_NAME}] ✅ {mig_id}: git_pull_only complete — {name} state synced")
    return True, {}


def _execute_rsync_migration(mig):
    """
    Legacy rsync migration: copy compose project to target, start there, stop here.
    """
    mig_id   = mig["id"]
    name     = mig["container"]
    to_ip    = mig["to_ip"]
    to_node  = mig["to_node"]

    print(f"[{UNIT_NAME}] 📦 rsync migration {mig_id}: {name} → {to_node} ({to_ip})")

    project_dir = _get_compose_dir(name)
    if not project_dir:
        print(f"[{UNIT_NAME}] ❌ Migration {mig_id}: no compose dir for {name}, skipping")
        return False

    ok, _, err = _ssh(to_ip, f"mkdir -p {project_dir}")
    if not ok:
        print(f"[{UNIT_NAME}] ❌ Migration {mig_id}: mkdir failed on {to_node}: {err}")
        return False

    host_project = _host_dir(project_dir)
    try:
        rsync = subprocess.run(
            ["rsync", "-avz", "--delete", "--exclude='.git'",
             f"{host_project}/",
             f"{REMOTE_USER}@{to_ip}:{project_dir}/"],
            capture_output=True, text=True, timeout=300,
        )
        if rsync.returncode != 0:
            print(f"[{UNIT_NAME}] ❌ Migration {mig_id}: rsync failed: {rsync.stderr[:200]}")
            return False
    except Exception as e:
        print(f"[{UNIT_NAME}] ❌ Migration {mig_id}: rsync error: {e}")
        return False

    ok, _, err = _ssh(to_ip, f"cd {project_dir} && docker compose up -d 2>&1", timeout=120)
    if not ok:
        print(f"[{UNIT_NAME}] ❌ Migration {mig_id}: compose up failed on {to_node}: {err}")
        return False
    print(f"[{UNIT_NAME}] ✅ Migration {mig_id}: {name} started on {to_node}")

    try:
        if _docker_client:
            c = _docker_client.containers.get(name)
            c.stop(timeout=30)
            subprocess.run(
                ["docker", "compose", "down"],
                cwd=host_project, capture_output=True, timeout=60,
            )
    except Exception as e:
        print(f"[{UNIT_NAME}] ⚠️  Migration {mig_id}: stop on source failed: {e}")

    print(f"[{UNIT_NAME}] ✅ Migration {mig_id}: complete — {name} moved to {to_node}")
    return True

def check_pending_migrations():
    """Poll the locator for migrations queued from this node and execute them."""
    headers = {"Host": LOCATOR_HOST_HEADER}
    try:
        resp = requests.get(
            f"{LOCATOR_URL}/api/migrations/pending",
            params={"unit": UNIT_NAME},
            headers=headers, timeout=5, verify=False,
        )
        if resp.status_code != 200:
            return
        migrations = resp.json()
    except Exception as e:
        print(f"[{UNIT_NAME}] Failed to poll migrations: {e}")
        return

    for mig in migrations:
        mig_id = mig.get("id")
        if not mig_id:
            continue

        try:
            claim_resp = requests.post(
                f"{LOCATOR_URL}/api/migrations/{mig_id}/claim",
                json={"unit": UNIT_NAME},
                headers=headers, timeout=5, verify=False,
            )
            if claim_resp.status_code != 200:
                continue
        except Exception:
            continue

        result = execute_migration(mig)
        # execute_migration returns (success, extra) for git types, bool for legacy rsync
        if isinstance(result, tuple):
            success, extra = result
        else:
            success, extra = result, {}

        try:
            requests.post(
                f"{LOCATOR_URL}/api/migrations/complete",
                json={"id": mig_id, "success": success, **extra},
                headers=headers, timeout=5, verify=False,
            )
        except Exception:
            pass

# ── LOCATOR FAILOVER ─────────────────────────────────────────────────────────

_locator_miss_streak = 0
_local_locator_started = False


def _local_locator_running():
    if not _docker_client:
        return False
    try:
        return _docker_client.containers.get("locator").status == "running"
    except Exception:
        return False


def _start_local_locator():
    """Bring up this unit's standby locator. Locator's own cross-node dedup
    (locator is no longer in _PINNED_NAMES) migrates/evicts whichever duplicate
    has the older heartbeat once both instances are visible in the registry —
    this function only needs to get *a* locator running, not coordinate."""
    global _local_locator_started
    if _local_locator_running():
        _local_locator_started = True
        return
    host_dir = _host_dir(LOCATOR_COMPOSE_DIR)
    if not os.path.isdir(host_dir):
        print(f"[{UNIT_NAME}] ❌ failover: locator compose dir not found: {host_dir}")
        return
    print(f"[{UNIT_NAME}] 🆘 locator unreachable {LOCATOR_MISS_THRESHOLD}+ ticks — starting local standby")
    result = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd=host_dir, capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ failover: compose up failed: {result.stderr.strip()[:200]}")
        return
    _local_locator_started = True
    print(f"[{UNIT_NAME}] ✅ failover: local locator started on {UNIT_NAME}")


def check_locator_failover():
    """Count consecutive missed canonical-locator health checks; after
    LOCATOR_MISS_THRESHOLD in a row, start this unit's standby locator.
    Resets (and re-arms) as soon as some locator answers /health again."""
    global _locator_miss_streak, _local_locator_started
    if not LOCATOR_FAILOVER_ENABLED or not LOCATOR_COMPOSE_DIR:
        return

    try:
        r = requests.get(
            f"{LOCATOR_URL}/health",
            headers={"Host": LOCATOR_HOST_HEADER}, timeout=5, verify=False,
        )
        alive = r.status_code == 200
    except Exception:
        alive = False

    if alive:
        if _locator_miss_streak:
            print(f"[{UNIT_NAME}] locator reachable again after {_locator_miss_streak} miss(es)")
        _locator_miss_streak = 0
        _local_locator_started = False
        return

    _locator_miss_streak += 1
    print(f"[{UNIT_NAME}] locator miss #{_locator_miss_streak}/{LOCATOR_MISS_THRESHOLD}")
    if _locator_miss_streak >= LOCATOR_MISS_THRESHOLD and not _local_locator_started:
        _start_local_locator()


# ── CERT EXPIRY WATCHDOG ─────────────────────────────────────────────────────
# Traefik auto-renews ~30 days before expiry; this is the safety net that makes
# a silent renewal failure visible. Every CERT_CHECK_TICKS ticks, check the TLS
# cert of every hostname this unit routes (from container Traefik labels) and
# report days-to-expiry to the locator (/api/certs/report).

CERT_CHECK_TICKS = int(os.getenv("CERT_CHECK_TICKS", "360"))  # ~6h at 60s tick


def _check_cert(host):
    """Return cert status for one hostname. Verification failures (self-signed
    default cert, expired, wrong SAN) are exactly what we want to flag."""
    import ssl
    import socket as _socket
    from datetime import datetime, timezone
    ctx = ssl.create_default_context()
    try:
        # Public hostname first; fall back to the local traefik with SNI if
        # the host network can't hairpin to its own public IP.
        last_err = None
        for target in (host, "traefik"):
            try:
                with _socket.create_connection((target, 443), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        cert = ss.getpeercert()
                break
            except (OSError, _socket.gaierror) as e:
                last_err = e
                cert = None
        if cert is None:
            return {"host": host, "days_left": None, "error": f"unreachable: {str(last_err)[:80]}"}
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
        return {"host": host, "days_left": days, "expires": exp.isoformat()}
    except ssl.SSLError as e:
        return {"host": host, "days_left": None,
                "error": f"bad cert: {getattr(e, 'verify_message', None) or str(e)[:80]}"}
    except Exception as e:
        return {"host": host, "days_left": None, "error": str(e)[:120]}


def report_cert_status():
    """Check every Traefik-routed hostname on this unit, report to the locator."""
    if not _docker_client:
        return
    hosts = set()
    try:
        for c in _docker_client.containers.list():
            hosts.update(extract_traefik_hosts(c.labels))
    except Exception as e:
        print(f"[{UNIT_NAME}] cert check: container scan failed: {e}")
        return
    if not hosts:
        return
    results = [_check_cert(h) for h in sorted(hosts)]
    for r in results:
        if r.get("error"):
            print(f"[{UNIT_NAME}] ⚠️  cert {r['host']}: {r['error']}")
        elif r["days_left"] is not None and r["days_left"] < 21:
            print(f"[{UNIT_NAME}] ⚠️  cert {r['host']}: only {r['days_left']} days left")
    try:
        requests.post(
            f"{LOCATOR_URL}/api/certs/report",
            json={"unit": UNIT_NAME, "certs": results},
            headers={"Host": LOCATOR_HOST_HEADER}, timeout=10, verify=False,
        )
        print(f"[{UNIT_NAME}] cert report: {len(results)} host(s) checked")
    except Exception as e:
        print(f"[{UNIT_NAME}] cert report failed: {e}")


# ── IDLE AUTO-SHUTDOWN ───────────────────────────────────────────────────────
# Containers labeled locator.idle.stop=true are watched: each tick we report
# their network counters to the locator, which runs the idle clock and queues
# stop/start commands back to us via /api/commands/pending.

IDLE_LABEL_ENABLE  = "locator.idle.stop"
IDLE_LABEL_TIMEOUT = "locator.idle.timeout"
PINNED_LABEL       = "locator.pinned"

# Core infrastructure this unit will NEVER stop, even if a stop command
# arrives or someone labels it for idle shutdown. Mirrors the locator's
# _PINNED_NAMES. Extend per-container with the label locator.pinned=true.
NEVER_STOP = {
    "locator", "traefik", "apache", "httpd", "varnish", "bind9", "bind",
    "openvpn", "headscale", "tailscale", "wireguard",
    "powerdns", "pdns", "ns1-auth", "ns1",
    "postgres", "redis", "mysql", "mariadb",
    "php-fpm", "barcode_db",
    "matrix_synapse", "matrix_element", "matrix_sms_bridge",
    "lokey",
}


def _is_protected(container):
    """True if this container must never be stopped by automation.

    Substring match so compose-suffixed names stay covered too
    (the-beast-postgres-1, openvpn-client, pdns-db, ...)."""
    name = container.name.lower()
    if any(p in name for p in NEVER_STOP):
        return True
    return str(container.labels.get(PINNED_LABEL, "")).lower() in ("true", "1", "yes", "on")


def report_idle_stats():
    """Report net-byte counters for idle-stop opt-in containers to the locator."""
    if not _docker_client:
        return
    entries = []
    try:
        for c in _docker_client.containers.list():
            if str(c.labels.get(IDLE_LABEL_ENABLE, "")).lower() not in ("true", "1", "yes", "on"):
                continue
            if _is_protected(c):
                continue
            try:
                raw = c.stats(stream=False)
                nets = raw.get("networks") or {}
                net_bytes = sum(n.get("rx_bytes", 0) + n.get("tx_bytes", 0) for n in nets.values())
            except Exception:
                continue
            entries.append({
                "name": c.name,
                "net_bytes": net_bytes,
                "timeout": c.labels.get(IDLE_LABEL_TIMEOUT, ""),
            })
    except Exception as e:
        print(f"[{UNIT_NAME}] idle stats collection failed: {e}")
        return

    # Always report, even an empty list — that's how the locator learns a
    # watched container went away (stopped or unlabeled).
    try:
        requests.post(
            f"{LOCATOR_URL}/api/idle/report",
            json={"unit": UNIT_NAME, "containers": entries},
            headers={"Host": LOCATOR_HOST_HEADER}, timeout=5, verify=False,
        )
        if entries:
            print(f"[{UNIT_NAME}] idle report: {len(entries)} watched container(s)")
    except Exception as e:
        print(f"[{UNIT_NAME}] idle report failed: {e}")


def execute_command(cmd):
    """Run a locator-issued container command (stop / start) on this unit."""
    action = cmd.get("action")
    name   = cmd.get("container")
    if not _docker_client or not name:
        return False
    try:
        c = _docker_client.containers.get(name)
        if action == "stop":
            if _is_protected(c):
                print(f"[{UNIT_NAME}] 🛡️  refusing to stop protected container '{name}'")
                return False
            c.stop(timeout=30)
            print(f"[{UNIT_NAME}] 💤 stopped '{name}' (locator command)")
            return True
        if action == "start":
            c.start()
            print(f"[{UNIT_NAME}] 🟢 started '{name}' (locator command)")
            return True
        print(f"[{UNIT_NAME}] unknown command action: {action}")
        return False
    except Exception as e:
        print(f"[{UNIT_NAME}] command {action} '{name}' failed: {e}")
        return False


def check_pending_commands():
    """Poll the locator for container commands aimed at this unit and run them."""
    headers = {"Host": LOCATOR_HOST_HEADER}
    try:
        resp = requests.get(
            f"{LOCATOR_URL}/api/commands/pending",
            params={"unit": UNIT_NAME},
            headers=headers, timeout=5, verify=False,
        )
        if resp.status_code != 200:
            return
        commands = resp.json()
    except Exception as e:
        print(f"[{UNIT_NAME}] Failed to poll commands: {e}")
        return

    for cmd in commands:
        if not cmd.get("id"):
            continue
        success = execute_command(cmd)
        try:
            requests.post(
                f"{LOCATOR_URL}/api/commands/complete",
                json={"id": cmd["id"], "success": success},
                headers=headers, timeout=5, verify=False,
            )
        except Exception:
            pass


def _get_public_ip():
    """Return current public IPv4, or None on failure."""
    for url in ("https://ifconfig.me", "https://api.ipify.org", "https://icanhazip.com"):
        try:
            r = requests.get(url, timeout=8)
            ip = r.text.strip()
            if ip and "." in ip:
                return ip
        except Exception:
            continue
    return None


def _pdns_update_records(zone: str, names: list, ip: str):
    """Update A-records in PowerDNS for given names in a zone via REST API."""
    rrsets = []
    for name in names:
        fqdn = f"{name}.{zone}." if name != "@" else f"{zone}."
        rrsets.append({
            "name": fqdn,
            "type": "A",
            "ttl": 300,
            "changetype": "REPLACE",
            "records": [{"content": ip, "disabled": False}],
        })
    try:
        resp = requests.patch(
            f"{PDNS_API_URL}/api/v1/servers/localhost/zones/{zone}.",
            headers={"X-API-Key": PDNS_API_KEY, "Content-Type": "application/json"},
            json={"rrsets": rrsets},
            timeout=10,
        )
        if resp.status_code not in (200, 204):
            print(f"[{UNIT_NAME}] pdns update error for {zone}: {resp.status_code} {resp.text[:200]}")
            return False
        return True
    except Exception as e:
        print(f"[{UNIT_NAME}] pdns update exception for {zone}: {e}")
        return False


_last_known_ip_file = "/host/tmp/lokey_ddns_last_ip"

def ddns_ip_watcher():
    """Detect home IP changes and push nsupdate to BIND for all unit1 zones."""
    if not DDNS_ENABLED:
        return

    current_ip = _get_public_ip()
    if not current_ip:
        print(f"[{UNIT_NAME}] DDNS: could not determine public IP")
        return

    try:
        last_ip = open(_last_known_ip_file).read().strip()
    except FileNotFoundError:
        last_ip = ""

    if current_ip == last_ip:
        return

    print(f"[{UNIT_NAME}] DDNS: IP changed {last_ip!r} → {current_ip!r} — updating zones")

    for zone, records in DDNS_ZONES.items():
        if _pdns_update_records(zone, records, current_ip):
            print(f"[{UNIT_NAME}] DDNS: updated {zone} → {current_ip}")

    try:
        open(_last_known_ip_file, "w").write(current_ip)
    except Exception as e:
        print(f"[{UNIT_NAME}] DDNS: could not save IP state: {e}")


def self_update():
    """git pull lokey; if new code detected, rebuild (Docker) or restart (native)."""
    # Docker containers mount the host root at /host; native installs use the path directly.
    host_dir = f"/host{LOKEY_PROJECT_DIR}"
    if not os.path.isdir(host_dir):
        host_dir = LOKEY_PROJECT_DIR
    if not os.path.isdir(host_dir):
        print(f"[{UNIT_NAME}] self_update: project dir not found ({LOKEY_PROJECT_DIR})")
        return

    env = {**os.environ, "GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes"}
    before = subprocess.run(
        ["git", "-C", host_dir, "rev-parse", "HEAD"],
        capture_output=True, text=True
    ).stdout.strip()

    pull = subprocess.run(
        ["git", "-C", host_dir, "pull", "--ff-only"],
        capture_output=True, text=True, env=env, timeout=30
    )
    if pull.returncode != 0:
        print(f"[{UNIT_NAME}] self_update: git pull failed: {pull.stderr.strip()}")
        return

    after = subprocess.run(
        ["git", "-C", host_dir, "rev-parse", "HEAD"],
        capture_output=True, text=True
    ).stdout.strip()

    if before == after:
        return

    print(f"[{UNIT_NAME}] self_update: new code ({before[:7]} → {after[:7]})")

    if os.path.isfile("/.dockerenv"):
        # Inside Docker: rebuild the container image and restart
        print(f"[{UNIT_NAME}] self_update: rebuilding container...")
        subprocess.Popen(
            ["docker", "compose", "-f", f"{host_dir}/docker-compose.yml", "up", "-d", "--build"],
            cwd=host_dir
        )
    else:
        # Native (macOS launchd / systemd): exit and let the supervisor restart us
        import sys
        print(f"[{UNIT_NAME}] self_update: exiting for supervisor restart")
        sys.exit(0)


if __name__ == "__main__":
    print(f"🚀 Lokey-Client starting on {UNIT_NAME}...")
    _dns_tick = 0
    _update_tick = 0
    _cert_tick = 0
    while True:
        register_stats()
        check_locator_failover()
        check_pending_migrations()
        check_pending_commands()
        report_idle_stats()
        if _cert_tick % CERT_CHECK_TICKS == 0:
            report_cert_status()
        _cert_tick += 1
        if UNIT_NAME == "unit2":
            _dns_tick += 1
            if _dns_tick >= 5:
                _dns_tick = 0
                try:
                    from sync_dns_apache import sync as dns_sync
                    dns_sync()
                except Exception as e:
                    print(f"[{UNIT_NAME}] dns-sync error: {e}")
        if UNIT_NAME == "unit1":
            ddns_ip_watcher()
        _update_tick += 1
        if _update_tick >= 5:
            _update_tick = 0
            self_update()
        time.sleep(TICK_RATE)
