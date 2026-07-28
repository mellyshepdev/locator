import os
import re
import time
import json
import docker
import requests
import subprocess
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False
    print("⚠️  psutil not installed — metric reporting disabled (pip install psutil)")

# ── CONFIGURATION ───────────────────────────────────────────────────────────

LOCATOR_URL        = os.environ.get("LOCATOR_URL", "http://locator.network")
UNIT_ID            = os.environ.get("UNIT_ID", "unit1")
BASE_DIR           = os.environ.get("BASE_DIR", "/home/swoopg111/projects")
REGISTRY_FILE      = "registry.json"
SYNC_INTERVAL      = int(os.environ.get("SYNC_INTERVAL", "300"))      # seconds between full syncs
METRICS_INTERVAL   = int(os.environ.get("METRICS_INTERVAL", "60"))    # seconds between metric pushes
MIGRATION_POLL     = int(os.environ.get("MIGRATION_POLL_INTERVAL", "30"))  # seconds between migration polls
COMMAND_POLL       = int(os.environ.get("COMMAND_POLL_INTERVAL", "10"))    # seconds between start/stop command polls

client = docker.from_env()

# ── INSTANCE LIMITS (mirrors locator.py's node-local enforcement) ───────────

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

def enforce_instance_limits(container_name):
    """Stop the oldest running containers on this unit that exceed the limit for this service type."""
    base  = _base_name(container_name)
    limit = _max_instances(container_name)
    try:
        running = client.containers.list()
        peers = [c for c in running if _base_name(c.name) == base and c.name != container_name]
        peers.sort(key=lambda c: c.attrs.get('State', {}).get('StartedAt', ''))
        while len(peers) >= limit:
            oldest = peers.pop(0)
            print(f"⚡ LIMIT ({limit}) exceeded for '{base}': stopping oldest → {oldest.name}")
            oldest.stop(timeout=10)
    except Exception as e:
        print(f"⚠️ Instance limit enforcement error: {e}")

def get_container_project_dir(container_name):
    """Return the docker-compose project.working_dir label for a container (running or stopped)."""
    try:
        c = client.containers.get(container_name)
        return c.labels.get("com.docker.compose.project.working_dir")
    except Exception:
        try:
            results = client.containers.list(all=True, filters={"name": container_name})
            if results:
                return results[0].labels.get("com.docker.compose.project.working_dir")
        except Exception:
            pass
    return None

def git_pull_in_dir(project_dir):
    """Run git pull in a host-mounted project directory (best-effort)."""
    if not project_dir or not os.path.isdir(project_dir):
        return
    try:
        result = subprocess.run(
            ["git", "-C", project_dir, "pull"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print(f"📥 git pull OK: {project_dir}")
        else:
            print(f"⚠️ git pull warning ({project_dir}): {result.stderr.strip()}")
    except Exception as e:
        print(f"⚠️ git pull skipped ({project_dir}): {e}")

# ── SYNC LOGIC ──────────────────────────────────────────────────────────────

def sync_to_locator():
    """Scans local Docker state and pushes it to the central Locator."""
    print(f"📡 Syncing {UNIT_ID} state to Locator...")
    try:
        containers = client.containers.list()
        for c in containers:
            ip = "N/A"
            networks = c.attrs["NetworkSettings"]["Networks"]
            for net_name, net_data in networks.items():
                ip = net_data.get("IPAddress", ip)
                if "vpn" in net_name.lower():
                    break

            payload = {
                "name":     c.name,
                "host":     UNIT_ID,
                "type":     "container",
                "status":   "ONLINE",
                "internal": ip,
                "metadata": {
                    "image":  c.image.tags[0] if c.image.tags else "unknown",
                    "status": c.status,
                },
            }
            resp = requests.post(f"{LOCATOR_URL}/register", json=payload, timeout=5)
            print(f"  ✓ {c.name}: {resp.status_code}")
    except Exception as e:
        print(f"⚠️ Sync failed: {e}")

# ── METRICS REPORTING ────────────────────────────────────────────────────────

def report_metrics():
    """Push live CPU and memory usage to the Locator's metrics endpoint."""
    if not _HAS_PSUTIL:
        return

    try:
        cpu = psutil.cpu_percent(interval=2)
        mem = psutil.virtual_memory().percent

        resp = requests.patch(
            f"{LOCATOR_URL}/nodes/{UNIT_ID}/metrics",
            json={"cpu_percent": cpu, "mem_percent": mem},
            timeout=5,
        )
        if resp.status_code == 200:
            print(f"📊 Metrics pushed: CPU={cpu}%  MEM={mem}%")
        else:
            print(f"⚠️ Metrics push returned {resp.status_code}")
    except Exception as e:
        print(f"⚠️ Metrics push failed: {e}")

# ── MIGRATION LOGIC ─────────────────────────────────────────────────────────

def sync_to_git(container_path):
    """Checks if the directory is a Git repo and pushes updates."""
    git_dir = os.path.join(container_path, ".git")
    if os.path.isdir(git_dir):
        print(f"📦 [GIT] Pushing updates for {container_path}...")
        try:
            subprocess.run(["git", "-C", container_path, "add", "."], check=True)
            subprocess.run(
                ["git", "-C", container_path, "commit", "-m", f"Auto-sync: {time.ctime()}"],
                check=False,
            )
            subprocess.run(["git", "-C", container_path, "push"], check=True)
            return True
        except Exception as e:
            print(f"⚠️ Git sync failed: {e}")
    return False


def migrate_container(container_name, target_unit, target_ip):
    """Moves a container to another unit via Git, SCP, and SSH."""
    print(f"🚀 Migrating {container_name} to {target_unit} ({target_ip})...")
    source_path = os.path.join(BASE_DIR, container_name)

    # 1. Backup to Git
    sync_to_git(source_path)

    # 2. Stop locally
    try:
        container = client.containers.get(container_name)
        container.stop()
        print(f"🛑 Stopped {container_name} locally.")
    except Exception as e:
        print(f"⚠️ Could not stop local container: {e}")
        return False

    # 3. Transfer files
    try:
        print("🚚 Transferring files...")
        subprocess.run(
            ["scp", "-r", source_path, f"swoopg111@{target_ip}:{BASE_DIR}/"],
            check=True,
        )
    except Exception as e:
        print(f"⚠️ File transfer failed: {e}")
        return False

    # 4. Start on remote
    try:
        print("✨ Starting remote instance...")
        remote_cmd = f"ssh swoopg111@{target_ip} 'cd {BASE_DIR}/{container_name} && docker-compose up -d'"
        subprocess.run(remote_cmd, shell=True, check=True)
        print(f"✅ Migration successful: {container_name} is now on {target_unit}")
        return True
    except Exception as e:
        print(f"⚠️ Remote start failed: {e}")
        return False


def check_and_run_migrations():
    """
    Polls the Locator for PENDING migrations assigned to this unit,
    runs them one at a time, and reports completion back.
    """
    try:
        resp = requests.get(
            f"{LOCATOR_URL}/api/migrations/pending",
            params={"unit": UNIT_ID},
            timeout=5,
        )
        if resp.status_code != 200:
            return

        tasks = resp.json()
        if not tasks:
            return

        for task in tasks:
            mig_id         = task["id"]
            container_name = task["container"]
            to_node        = task["to_node"]
            to_ip          = task["to_ip"]

            print(f"📦 Migration {mig_id}: moving '{container_name}' → {to_node} ({to_ip})")
            success = migrate_container(container_name, to_node, to_ip)

            requests.post(
                f"{LOCATOR_URL}/api/migrations/complete",
                json={"id": mig_id, "success": success},
                timeout=5,
            )

    except Exception as e:
        print(f"⚠️ Migration check failed: {e}")

# ── START/STOP COMMANDS ──────────────────────────────────────────────────────
# Locator never touches Docker itself: it queues start/stop commands for this
# unit and this agent (lokey) picks them up, runs them locally, and reports
# back — see /api/container/toggle, /api/idle/wake, /api/shutdown in locator.py.

def execute_command(cmd):
    """Run a single queued start/stop command locally. Returns True on success."""
    name   = cmd["container"]
    action = cmd["action"]
    project_dir = get_container_project_dir(name)
    try:
        if action == "start":
            git_pull_in_dir(project_dir)
            enforce_instance_limits(name)
            try:
                container = client.containers.get(name)
                container.start()
            except docker.errors.NotFound:
                if not project_dir:
                    print(f"⚠️ COMMAND start '{name}': not found and no compose dir known")
                    return False
                result = subprocess.run(
                    ["docker", "compose", "up", "-d"],
                    cwd=project_dir, capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    print(f"⚠️ COMMAND start '{name}': compose up failed: {result.stderr.strip()}")
                    return False
            print(f"▶️  COMMAND: {name} → started")
            return True
        else:
            container = client.containers.get(name)
            container.stop(timeout=15)
            git_pull_in_dir(project_dir)
            print(f"⏹️  COMMAND: {name} → stopped")
            return True
    except docker.errors.NotFound:
        print(f"⚠️ COMMAND {action} '{name}': container not found")
        return False
    except Exception as e:
        print(f"⚠️ COMMAND {action} '{name}' failed: {e}")
        return False


def check_and_run_commands():
    """Polls the Locator for PENDING start/stop commands assigned to this unit,
    runs them, and reports completion back."""
    try:
        resp = requests.get(
            f"{LOCATOR_URL}/api/commands/pending",
            params={"unit": UNIT_ID},
            timeout=5,
        )
        if resp.status_code != 200:
            return

        commands = resp.json()
        for cmd in commands:
            print(f"📨 Command {cmd['id']}: {cmd['action']} '{cmd['container']}'")
            success = execute_command(cmd)
            requests.post(
                f"{LOCATOR_URL}/api/commands/complete",
                json={"id": cmd["id"], "success": success},
                timeout=5,
            )
    except Exception as e:
        print(f"⚠️ Command check failed: {e}")


def command_loop():
    """Polls for pending start/stop commands every COMMAND_POLL seconds."""
    while True:
        time.sleep(COMMAND_POLL)
        check_and_run_commands()

# ── WATCHER ─────────────────────────────────────────────────────────────────

class RegistryHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(REGISTRY_FILE):
            print("📝 Registry change detected. Syncing...")
            sync_to_locator()

# ── BACKGROUND METRIC + MIGRATION LOOP ───────────────────────────────────────

def metrics_loop():
    """Pushes metrics every METRICS_INTERVAL seconds."""
    while True:
        time.sleep(METRICS_INTERVAL)
        report_metrics()


def migration_loop():
    """Polls for pending migrations every MIGRATION_POLL seconds."""
    while True:
        time.sleep(MIGRATION_POLL)
        check_and_run_migrations()

# ── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"🐺 LOCATOR AGENT STARTED ON {UNIT_ID}")
    print(f"   Sync interval:     {SYNC_INTERVAL}s")
    print(f"   Metrics interval:  {METRICS_INTERVAL}s")
    print(f"   Migration poll:    {MIGRATION_POLL}s")
    print(f"   Command poll:      {COMMAND_POLL}s")

    # Initial sync + metrics push
    sync_to_locator()
    report_metrics()

    # Background: metrics reporter
    threading.Thread(target=metrics_loop, daemon=True).start()

    # Background: migration poller
    threading.Thread(target=migration_loop, daemon=True).start()

    # Background: start/stop command poller (Locator → lokey delegation)
    threading.Thread(target=command_loop, daemon=True).start()

    # Watch registry.json for changes
    observer = Observer()
    observer.schedule(RegistryHandler(), path=".", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(SYNC_INTERVAL)
            sync_to_locator()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
