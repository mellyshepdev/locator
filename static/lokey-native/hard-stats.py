import psutil
import time
import os
import re
import shutil
import sys
import signal
import subprocess
import socket
import threading
import requests
import urllib3
import json
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default to the live locator. This fallback used to name a decommissioned
# Fly app, so any native install without an explicit LOCATOR_URL reported into
# the void even while running current code — unit6 did exactly that for ~65
# days. Only docker-compose.yml carried the correct value.
LOCATOR_URL = os.getenv("LOCATOR_URL", "https://locator.theofficialblacksheepco.online")
LOCATOR_HOST_HEADER = os.getenv("LOCATOR_HOST_HEADER", "locator.theofficialblacksheepco.online")
UNIT_NAME   = os.getenv("UNIT_NAME", "unknown_unit")
TICK_RATE   = int(os.getenv("TICK_RATE", "60"))
UNIT_HOST   = os.getenv("UNIT_HOST", "")   # hostname/domain that other units use to SSH here
REMOTE_USER = os.getenv("REMOTE_USER", "swoopg111")
LOKEY_PROJECT_DIR = os.getenv("LOKEY_PROJECT_DIR", f"/home/{REMOTE_USER}/projects/lokey")
# Docker-mode lokey bind-mounts the host root at /host; native installs see the
# real root. Probing for /host/proc keeps this correct either way.
HOST_PREFIX = "/host" if os.path.isdir("/host/proc") else ""

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

# Filesystems worth reporting. Everything else on a modern box is a pseudo or
# virtual filesystem (proc, sysfs, cgroup, tmpfs, squashfs snaps, overlay layers)
# and would bury the real storage in noise.
_REAL_FSTYPES = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs",
    "vfat", "exfat", "ntfs", "ntfs3", "hfsplus", "apfs", "ufs",
}
# Container-internal and system paths that are not user-visible storage.
_SKIP_MOUNT_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker")


def get_mounts():
    """Every real mounted filesystem on this host, with capacity.

    get_system_stats() only ever measured '/', so attached storage was
    invisible — a 100GB volume or a plugged-in SD card never showed up
    anywhere in the registry.

    Reads the HOST's mount table (/host/proc/mounts under Docker). The /host
    bind mount is a slave (master:N in mountinfo), so mounts appearing after
    the container started propagate in and hot-plugged media is picked up
    without restarting anything.

    Deduplicated by source device: bind mounts list the same filesystem several
    times, which would otherwise report '/' repeatedly as separate disks.
    """
    mounts_file = f"{HOST_PREFIX}/proc/mounts" if HOST_PREFIX else "/proc/mounts"
    seen_devices, results = set(), []
    try:
        with open(mounts_file) as fh:
            entries = fh.read().splitlines()
    except Exception:
        return results

    for line in entries:
        parts = line.split()
        if len(parts) < 3:
            continue
        device, mountpoint, fstype = parts[0], parts[1], parts[2]
        if fstype not in _REAL_FSTYPES:
            continue

        # Mountpoints in this file are already expressed in OUR namespace: under
        # Docker the host's "/" appears as "/host" and "/boot/efi" as
        # "/host/boot/efi". So statvfs the path as-is and strip the prefix only
        # for reporting — prefixing again yields "/host/host" and every lookup
        # fails, which silently produced an empty list.
        probe = mountpoint
        if HOST_PREFIX:
            if not (mountpoint == HOST_PREFIX or mountpoint.startswith(HOST_PREFIX + "/")):
                continue  # container-internal mount, not host storage
            mountpoint = mountpoint[len(HOST_PREFIX):] or "/"

        if mountpoint.startswith(_SKIP_MOUNT_PREFIXES):
            continue
        if device in seen_devices:
            continue  # bind mount of a filesystem already counted
        seen_devices.add(device)

        try:
            st = os.statvfs(probe)
        except Exception:
            continue
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total <= 0:
            continue
        used = total - (st.f_bfree * st.f_frsize)
        results.append({
            "device": device,
            "mountpoint": mountpoint,
            "fstype": fstype,
            "total_gb": round(total / (1024**3), 2),
            "used_gb": round(used / (1024**3), 2),
            "free_gb": round(free / (1024**3), 2),
            "percent": round(used / total * 100, 1),
            "removable": _is_removable(device),
        })
    results.sort(key=lambda d: d["mountpoint"])
    return results


def _is_removable(device):
    """True for USB sticks, SD cards and the like.

    Reads the kernel's own 'removable' flag for the parent block device, so an
    SD card reads as removable while a fixed disk does not.
    """
    name = os.path.basename(device)
    if not name.startswith(("sd", "mmcblk", "nvme")):
        return False
    # sda1 -> sda ; mmcblk0p1 -> mmcblk0 ; nvme0n1p1 -> nvme0n1
    base = re.sub(r"(p?\d+)$", "", name) if name.startswith(("mmcblk", "nvme")) else name.rstrip("0123456789")
    try:
        with open(f"{HOST_PREFIX}/sys/block/{base}/removable") as fh:
            return fh.read().strip() == "1"
    except Exception:
        return False


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
        disk_free = round(disk.free / (1024**3), 2)
        disk_percent = disk.percent
    except Exception:
        disk_total = disk_used = disk_free = disk_percent = 0

    return {
        "cpu_usage_percent": cpu_usage,
        "cpu_temp_c": cpu_temp,
        "mem_total_gb": round(mem.total / (1024**3), 2),
        "mem_used_gb": round(mem.used / (1024**3), 2),
        # psutil's "available" — not total-minus-used. It accounts for
        # reclaimable cache/buffers, so it reflects what a new process could
        # actually get, which is the figure placement decisions need.
        "mem_available_mb": round(mem.available / (1024**2), 1),
        "mem_total_mb": round(mem.total / (1024**2), 1),
        "mem_percent": mem.percent,
        "disk_total_gb": disk_total,
        "disk_used_gb": disk_used,
        "disk_free_gb": disk_free,
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

    # Docker-mode: run the HOST's tailscale binary against the HOST's socket.
    # This is the only path that actually works in our containers — the CLI is
    # not installed in the image, nsenter needs `pid: host` (the compose grants
    # privileged but not that), and tailscale0 lives in the host's network
    # namespace so `ip addr` cannot see it either. All three fell through, which
    # is why every containerised unit reported tailscale_ip=None while unit7's
    # native agent reported correctly.
    #
    # Note the socket path is /host/run, NOT /host/var/run: /var/run is a
    # symlink to /run, and through the bind mount it resolves to the
    # CONTAINER's /run rather than the host's. The binary is static Go, so it
    # executes fine from the host filesystem.
    try:
        result = subprocess.run(
            ["/host/usr/bin/tailscale",
             "--socket=/host/run/tailscale/tailscaled.sock", "ip", "-4"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            ip = result.stdout.strip().splitlines()[0].strip()
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

    # macOS / BSD. Every tier above is Linux-only and ALL of them fail there:
    # the `tailscale` CLI lives inside Tailscale.app and is not on a
    # non-interactive PATH, `nsenter` and `ip` do not exist, and the interface
    # is a utun*, never tailscale0. unit3 reported tailscale_ip=None for exactly
    # this reason while sitting on the tailnet at 100.78.95.13 — which left its
    # node record with no probeable address at all and pinned it at OFFLINE in
    # the registry while the machine was up and in daily use.
    #
    # ifconfig exists on macOS and most Linux, and an address inside tailscale's
    # 100.64.0.0/10 CGNAT range is unambiguous — nothing else on these hosts
    # uses it. Range-checked by octet rather than importing ipaddress, to keep
    # this module's import list unchanged.
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line.startswith("inet "):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                candidate = parts[1].split("/")[0]
                octets = candidate.split(".")
                if len(octets) != 4:
                    continue
                try:
                    first, second = int(octets[0]), int(octets[1])
                except ValueError:
                    continue
                if first == 100 and 64 <= second <= 127:
                    return candidate
    except Exception:
        pass

    return None


# ── IP COLLECTION ────────────────────────────────────────────────────────────
# Global IP variables, populated on startup and kept current during heartbeats.
_private_ip = None
_public_ip = None
_tailscale_ip_cached = None


def get_private_ip():
    """Return the host's private IP using socket.

    Opens a socket to a public DNS server to determine the primary outgoing
    interface's IP address (works without root and doesn't actually send packets).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _fetch_public_ip():
    """Fetch public IP via curl with 5s timeout.

    Uses curl directly (as specified) and stores result globally.
    Called from a background thread to avoid blocking the first heartbeat.
    """
    global _public_ip
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "5", "https://ifconfig.me"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            ip = result.stdout.strip()
            if ip and "." in ip:
                _public_ip = ip
                return
    except Exception:
        pass
    _public_ip = None


def _start_public_ip_background_fetch():
    """Launch a daemon thread to fetch public IP without blocking startup."""
    thread = threading.Thread(target=_fetch_public_ip, daemon=True)
    thread.start()


# ── GEOLOCATION ──────────────────────────────────────────────────────────────
# IP-based geolocation for devices without GPS (laptops, desktops).
# Cached globally; updated every heartbeat in background to avoid blocking.
_geolocation = None  # {"lat": float, "lon": float} or None


def _fetch_geolocation_background():
    """Fetch approximate lat/lon from public IP via ip-api.com free tier.

    Runs in background; stores result globally. Works for laptops/desktops
    without GPS hardware.
    """
    global _geolocation, _public_ip
    if not _public_ip:
        return
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "5", f"http://ip-api.com/json/{_public_ip}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if data.get("status") == "success":
                _geolocation = {
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "city": data.get("city"),
                    "country": data.get("country"),
                }
                return
    except Exception:
        pass
    _geolocation = None


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
    # Absolute totals matter as much as percentages: the units range from 1.8GB
    # to 16GB, so "20% free" means ~370MB on one and ~3.2GB on another. Without
    # totals the locator cannot tell whether a node can actually host what it is
    # about to migrate there, and its election has nothing real to rank on.
    metrics = {
        "cpu_percent":       stats["cpu_usage_percent"],
        "mem_percent":       stats["mem_percent"],
        "mem_total_mb":      stats["mem_total_mb"],
        "mem_available_mb":  stats["mem_available_mb"],
        "mem_total_gb":      stats["mem_total_gb"],
        "mem_used_gb":       stats["mem_used_gb"],
        "disk_percent":      stats["disk_percent"],
        "disk_total_gb":     stats["disk_total_gb"],
        "disk_used_gb":      stats["disk_used_gb"],
        "disk_free_gb":      stats["disk_free_gb"],
        # Every real mounted filesystem, not just '/'. Attached volumes and
        # removable media (SD cards, USB) show up here.
        "mounts":            get_mounts(),
        "os":                _OS_INFO,
        "status":            "ONLINE",
        "last_seen":         datetime.now(timezone.utc).isoformat(),
    }
    # This is the copy the NATIVE installs run, so it is the one unit3 (macOS)
    # is executing — and it sent no local address at all. lokey computes one via
    # get_private_ip() and includes it in the /register metadata, so it landed
    # on the SERVICE record and never the node: unit3's 10.68.117.30 sat in
    # lokey-client@unit3.metadata.private_ip while unit3's NODE record carried
    # no address of any kind and was therefore impossible to probe. locator's
    # handler has always read data["ip"]; nothing ever sent it.
    #
    # tailscale_ip compounds it — detection fails on the macOS native install,
    # so unit3 reported None despite being active on the tailnet at
    # 100.78.95.13, leaving it with zero usable addresses.
    #
    # Resolved per heartbeat, not reused from the module-level _private_ip that
    # is computed once at startup and goes stale when the address changes.
    local_ip = get_private_ip()
    if local_ip:
        metrics["ip"] = local_ip
        metrics["private_ip"] = local_ip
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
    _fetch_geolocation_background()  # Update geolocation in background each heartbeat

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

    metadata = {
        **stats,
        "os": _OS_INFO,
        "containers": containers_summary,
        "private_ip": _private_ip,
        "public_ip": _public_ip,
        "tailscale_ip": _tailscale_ip_cached,
    }

    # Add geolocation data if available (for laptops/desktops without GPS)
    if _geolocation:
        metadata.update(_geolocation)

    # This copy is the one NATIVE installs download and run, and it still
    # hardcoded type="container" — so the native build was the loudest source of
    # the wrong answer. unit6 (no docker binary) and unit3 (macOS, no docker on
    # the non-interactive PATH) both landed in the registry as "docker
    # containers" with zero containers running. locator cannot correct it:
    # /register defaults a missing type to "container" and _infer_category()
    # sends anything unrecognised to "docker containers".
    _self_is_container = os.path.isfile("/.dockerenv")
    _host_has_docker   = _ensure_docker() is not None
    payload = {
        "name": "lokey-client",
        "host": UNIT_NAME,
        "type": "container" if _self_is_container else "native",
        # Explicit: _infer_category() maps type=native to "devices", which is
        # for phones and tablets, not a native daemon on a workstation.
        "category": "docker containers" if _self_is_container else "native services",
        "status": "ONLINE",
        "metadata": {
            **metadata,
            # `type` is what this agent runs as; docker_available describes the
            # HOST. A native lokey on a box that does have Docker is a different
            # case from one on a box with none, and collapsing the two is what
            # produced the wrong registry.
            "docker_available": _host_has_docker,
            "runtime": "docker" if _self_is_container else "native",
        },
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

# ── COMPOSE STACKS MONOREPO ──────────────────────────────────────────────────
# One repo holding every container's compose file, rather than expecting each
# container's own project directory to be a git repo with a push remote. Most
# were not — phpmyadmin's lives under server/databases/maria/11.4, a plain
# directory — so every migration died at "No configured push destination".

COMPOSE_STACKS_DIR = os.getenv(
    "COMPOSE_STACKS_DIR", f"/home/{REMOTE_USER}/projects/compose-stacks")
COMPOSE_STACKS_REMOTE = os.getenv(
    "COMPOSE_STACKS_REMOTE",
    "https://gitlab.com/blackshepherddeveloper/compose-stacks.git")


def _ensure_stacks_repo():
    """Clone or refresh the compose-stacks checkout. Returns its path or None.

    Cloning here is what lets a container move to a unit that has never hosted
    it. The old pull_and_start had a clone branch, but it sat behind a
    `not isdir(host)` check that had already returned on the same condition —
    so it was unreachable and migrating to a fresh node always failed.
    """
    host = _host_dir(COMPOSE_STACKS_DIR)
    if os.path.isdir(os.path.join(host, ".git")):
        pull = _git(host, "pull", "--ff-only")
        if pull.returncode != 0:
            print(f"[{UNIT_NAME}] ⚠️  stacks pull failed: {pull.stderr.strip()[:140]}")
        return host

    os.makedirs(os.path.dirname(host), exist_ok=True)
    token = _git_token()
    remote = COMPOSE_STACKS_REMOTE
    if token and remote.startswith("https://") and "@" not in remote:
        remote = remote.replace("https://", f"https://oauth2:{token}@", 1)
    clone = subprocess.run(
        ["git", "clone", remote, host],
        capture_output=True, text=True, timeout=180,
    )
    if clone.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ stacks clone failed: {clone.stderr.strip()[:160]}")
        return None
    print(f"[{UNIT_NAME}] 📥 cloned compose-stacks → {host}")
    return host


def _stack_file(stacks_host, name):
    """Path to a container's compose file inside the stacks repo, if present."""
    for ext in (".yml", ".yaml"):
        candidate = os.path.join(stacks_host, f"{name}{ext}")
        if os.path.isfile(candidate):
            return candidate
    return None


def _find_local_compose_file(project_dir):
    """The compose file inside a container's own project directory."""
    host = _host_dir(project_dir)
    for fname in ("docker-compose.yml", "docker-compose.yaml",
                  "compose.yml", "compose.yaml"):
        candidate = os.path.join(host, fname)
        if os.path.isfile(candidate):
            return candidate
    return None


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
      kind == "native"   — non-container migration, see _execute_native_migration.
      git_push_and_stop  — commit + push this container's project, then stop it here.
      git_pull_and_start — pull (or clone) the project on this node, docker compose up -d.
      git_pull_only      — pull (or clone) to sync state; container already running here.
      (default/legacy)   — rsync project to target, compose up there, compose down here.
    Returns (success: bool, extra: dict) where extra carries data for the locator
    completion report (e.g. project_dir so locator can create the follow-on pull task).
    """
    if mig.get("kind", "container") == "native":
        return _execute_native_migration(mig), {}

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

    # Publish into the shared compose-stacks repo rather than pushing the
    # container's own directory. Those directories are mostly plain folders
    # with no remote, which is why every migration failed here.
    local_compose = _find_local_compose_file(project_dir)
    if not local_compose:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: no compose file under {project_dir}")
        return False, {}

    stacks_host = _ensure_stacks_repo()
    if not stacks_host:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: compose-stacks unavailable")
        return False, {}

    try:
        shutil.copyfile(local_compose, os.path.join(stacks_host, f"{name}.yml"))
    except Exception as e:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: could not stage {name}.yml: {e}")
        return False, {}

    host = stacks_host
    _git(host, "add", "-A")
    _git(host, "commit", "-m", f"[lokey-migrate] {name} leaving {UNIT_NAME} for {to_node}")
    push = _git(host, "push")
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

    # Take the container's compose from the shared stacks repo, cloning it if
    # this unit has never had it. Previously a missing project_dir returned
    # immediately, so a container could only ever move to a node that already
    # hosted it — which is precisely the case a migration is meant to solve.
    stacks_host = _ensure_stacks_repo()
    if stacks_host:
        stack_file = _stack_file(stacks_host, name)
        if stack_file:
            up = subprocess.run(
                ["docker", "compose", "-f", stack_file, "-p", name, "up", "-d"],
                capture_output=True, text=True, timeout=300,
            )
            if up.returncode != 0:
                print(f"[{UNIT_NAME}] ❌ {mig_id}: compose up failed: {up.stderr.strip()[:200]}")
                return False, {}
            print(f"[{UNIT_NAME}] ✅ {mig_id}: started {name} from compose-stacks")
            return True, {"project_dir": COMPOSE_STACKS_DIR, "stack_file": stack_file}
        print(f"[{UNIT_NAME}] ⚠️  {mig_id}: {name} not in compose-stacks — falling back to project dir")

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


# ── NATIVE (non-container) MIGRATION ────────────────────────────────────────
# Moves a systemd-managed service or a bare background process — as opposed
# to a Docker container — to another unit. Which of the two it is gets
# detected live against the actual host state, not assumed from the registry.

def _detect_native_kind(name, metadata):
    """
    Check this host's real state for the named service to decide how to
    migrate it:
      "systemd" — a real, loaded systemd unit with a unit file on disk
                  ("standard app" — properly installed, config-driven).
      "process" — no systemd unit, but a process is actually running
                  ("native background process" — ad hoc, no config file).
      None      — nothing found here to migrate.
    Returns (kind, detail): detail is (unit_name, unit_path) for "systemd",
    or a pid (int) for "process".
    """
    unit_name = metadata.get("systemd_unit") or f"{name}.service"

    if shutil.which("systemctl"):
        show = subprocess.run(
            ["systemctl", "show", unit_name,
             "--property=LoadState,ActiveState,FragmentPath", "--no-pager"],
            capture_output=True, text=True, timeout=10,
        )
        if show.returncode == 0:
            props = dict(
                line.split("=", 1) for line in show.stdout.strip().splitlines() if "=" in line
            )
            if props.get("LoadState") == "loaded" and props.get("FragmentPath"):
                return "systemd", (unit_name, props["FragmentPath"])

    pid_file = metadata.get("pid_file")
    if pid_file and os.path.isfile(pid_file):
        try:
            pid = int(open(pid_file).read().strip())
            os.kill(pid, 0)  # existence check only, no signal sent
            return "process", pid
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            pass

    pgrep = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True, timeout=10)
    if pgrep.returncode == 0:
        # Exclude our own pid — "-f" matches substrings anywhere in the full
        # command line, so a service name that happens to appear in this
        # process's own args (env vars, paths, etc.) would otherwise self-match.
        candidates = [int(p) for p in pgrep.stdout.split() if int(p) != os.getpid()]
        if candidates:
            return "process", candidates[0]

    return None, None


def _parse_unit_file(path):
    """Extract WorkingDirectory= and ExecStart= from a systemd unit file."""
    working_dir, exec_start = None, None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("WorkingDirectory="):
                    working_dir = line.split("=", 1)[1].strip()
                elif line.startswith("ExecStart="):
                    exec_start = line.split("=", 1)[1].strip()
    except Exception:
        pass
    return working_dir, exec_start


def _guess_venv_from_exec(exec_start):
    """If ExecStart runs a <venv>/bin/python[3], return the venv dir."""
    if not exec_start:
        return None
    interpreter = exec_start.split()[0]
    if interpreter.endswith("/bin/python") or interpreter.endswith("/bin/python3"):
        return os.path.dirname(os.path.dirname(interpreter))
    return None


def _rebuild_remote_venv(to_ip, working_dir, venv_path):
    """
    Ship code without the venv (already excluded from rsync by the caller)
    and rebuild it from requirements.txt on the target — safer than copying
    a venv directory across possibly different OS/arch/Python versions.
    """
    if not venv_path:
        return True  # no venv involved
    req_file = os.path.join(working_dir, "requirements.txt")
    if not os.path.isfile(req_file):
        print(f"  ⚠️  no requirements.txt in {working_dir} — target must already have a usable venv")
        return True
    ok, _, err = _ssh(
        to_ip,
        f"python3 -m venv {venv_path} && "
        f"{venv_path}/bin/pip install --quiet -r {working_dir}/requirements.txt",
        timeout=180,
    )
    if not ok:
        print(f"  ❌ remote venv rebuild failed: {err[:200]}")
    return ok


def _rsync_native_project(working_dir, to_ip, venv_path):
    ok, _, err = _ssh(to_ip, f"mkdir -p {working_dir}")
    if not ok:
        print(f"  ❌ mkdir failed on target: {err}")
        return False
    exclude = []
    if venv_path and os.path.dirname(venv_path) == working_dir:
        exclude = ["--exclude", os.path.basename(venv_path)]
    rsync = subprocess.run(
        ["rsync", "-avz", "--delete", *exclude,
         f"{working_dir}/", f"{REMOTE_USER}@{to_ip}:{working_dir}/"],
        capture_output=True, text=True, timeout=300,
    )
    if rsync.returncode != 0:
        print(f"  ❌ rsync failed: {rsync.stderr[:200]}")
        return False
    return True


def _migrate_systemd_service(mig, unit_name, unit_path, metadata):
    """A "standard app": stop it, ship its working dir + rebuilt venv + unit
    file, install and start it on the target via systemctl."""
    mig_id, to_ip, to_node = mig["id"], mig["to_ip"], mig["to_node"]
    print(f"[{UNIT_NAME}] 🧩 native(systemd) migration {mig_id}: {unit_name} → {to_node} ({to_ip})")

    working_dir, exec_start = _parse_unit_file(unit_path)
    working_dir = metadata.get("working_dir") or working_dir
    venv_path   = metadata.get("venv_path") or _guess_venv_from_exec(exec_start)

    if not working_dir:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: no WorkingDirectory in unit and no metadata.working_dir override")
        return False

    stop = subprocess.run(
        ["sudo", "-n", "systemctl", "stop", unit_name],
        capture_output=True, text=True, timeout=30,
    )
    if stop.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: systemctl stop failed (passwordless sudo set up?): {stop.stderr.strip()[:200]}")
        return False

    if not _rsync_native_project(working_dir, to_ip, venv_path):
        return False

    if not _rebuild_remote_venv(to_ip, working_dir, venv_path):
        return False

    scp = subprocess.run(
        ["scp", unit_path, f"{REMOTE_USER}@{to_ip}:/tmp/{unit_name}"],
        capture_output=True, text=True, timeout=30,
    )
    if scp.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: unit file scp failed: {scp.stderr.strip()[:200]}")
        return False

    ok, _, err = _ssh(
        to_ip,
        f"sudo -n cp /tmp/{unit_name} /etc/systemd/system/{unit_name} && "
        f"sudo -n systemctl daemon-reload && sudo -n systemctl enable --now {unit_name}",
        timeout=60,
    )
    if not ok:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: remote systemctl enable failed (passwordless sudo set up on {to_node}?): {err}")
        return False

    ok, out, _ = _ssh(to_ip, f"systemctl is-active {unit_name}", timeout=10)
    if not ok or out.strip() != "active":
        print(f"[{UNIT_NAME}] ⚠️  {mig_id}: started but not reporting active on {to_node} ({out!r})")
        return False

    print(f"[{UNIT_NAME}] ✅ {mig_id}: {unit_name} now active on {to_node}")
    return True


def _migrate_native_process(mig, pid, metadata):
    """A "native background process": no unit file, so working_dir and
    start_cmd must come from registry metadata. Stop, ship, restart via
    nohup on the target."""
    mig_id, to_ip, to_node = mig["id"], mig["to_ip"], mig["to_node"]
    name = mig["container"]
    print(f"[{UNIT_NAME}] 🧩 native(process) migration {mig_id}: {name} (pid {pid}) → {to_node} ({to_ip})")

    working_dir = metadata.get("working_dir")
    start_cmd   = metadata.get("start_cmd")
    venv_path   = metadata.get("venv_path")
    if not working_dir or not start_cmd:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: bare process migration needs metadata.working_dir and metadata.start_cmd")
        return False

    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(10):
            time.sleep(1)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
        else:
            os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception as e:
        print(f"[{UNIT_NAME}] ⚠️  {mig_id}: stop warning: {e}")

    if not _rsync_native_project(working_dir, to_ip, venv_path):
        return False

    if not _rebuild_remote_venv(to_ip, working_dir, venv_path):
        return False

    pid_file = metadata.get("pid_file") or f"{working_dir}/.lokey_native.pid"
    ok, _, err = _ssh(
        to_ip,
        f"cd {working_dir} && nohup {start_cmd} > native.log 2>&1 & echo $! > {pid_file}",
        timeout=30,
    )
    if not ok:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: remote start failed on {to_node}: {err}")
        return False

    print(f"[{UNIT_NAME}] ✅ {mig_id}: {name} started on {to_node}")
    return True


def _execute_native_migration(mig):
    """
    Entry point for kind="native" migrations. Checks whether the named
    service is a real systemd unit ("standard app") or a bare running
    process ("native background process") and migrates it accordingly.
    """
    mig_id   = mig["id"]
    name     = mig["container"]
    metadata = mig.get("metadata") or {}

    kind, detail = _detect_native_kind(name, metadata)
    if kind == "systemd":
        unit_name, unit_path = detail
        return _migrate_systemd_service(mig, unit_name, unit_path, metadata)
    if kind == "process":
        return _migrate_native_process(mig, detail, metadata)

    print(f"[{UNIT_NAME}] ❌ {mig_id}: '{name}' is neither a loaded systemd unit nor a running process here")
    return False


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
    """Mechanism-agnostic: true whether the standby is a docker container or
    a bare native process, since either way it ends up serving :5000."""
    try:
        r = requests.get("http://localhost:5000/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _start_local_locator_docker(host_dir):
    result = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.standby.yml", "up", "-d"],
        cwd=host_dir, capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ failover: compose up failed: {result.stderr.strip()[:200]}")
        return False
    return True


def _start_local_locator_native(host_dir):
    """No Docker on this unit — run locator directly with the same gunicorn
    command the Dockerfile uses. Needs `pip install -r requirements.txt` done
    ahead of time in *this same interpreter* (sys.executable) — invoking via
    `-m gunicorn` instead of the bare `gunicorn` command means it resolves
    through whatever Python is actually running this script, regardless of
    PATH in whatever launched hard-stats.py (LaunchDaemon, systemd, etc)."""
    log_path = os.path.join(host_dir, "locator_standby.log")
    try:
        log_file = open(log_path, "a")
        env = dict(os.environ, UNIT_NAME=UNIT_NAME, LOCATOR_IS_PRIMARY="false",
                   SELF_CONTAINER_NAME="locator",
                   LOCATOR_CANONICAL_URL=LOCATOR_URL)
        subprocess.Popen(
            [sys.executable, "-m", "gunicorn",
             "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8",
             "--worker-class", "gthread", "--timeout", "300", "--keep-alive", "5",
             "--access-logfile", "-", "--error-logfile", "-", "locator:app"],
            cwd=host_dir, env=env, stdout=log_file, stderr=log_file,
            start_new_session=True,
        )
    except Exception as e:
        print(f"[{UNIT_NAME}] ❌ failover: native locator start failed: {e}")
        return False
    return True


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
        print(f"[{UNIT_NAME}] ❌ failover: locator project dir not found: {host_dir}")
        return
    print(f"[{UNIT_NAME}] 🆘 locator unreachable {LOCATOR_MISS_THRESHOLD}+ ticks — starting local standby")
    started = (_start_local_locator_docker(host_dir) if shutil.which("docker")
               else _start_local_locator_native(host_dir))
    if not started:
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


EXEC_TIMEOUT = int(os.environ.get("LOKEY_EXEC_TIMEOUT", 300))
EXEC_OUTPUT_CAP = 20000  # chars kept per stdout/stderr before sending to locator

# Where an 'exec' script actually runs. A bare subprocess here executes INSIDE
# the lokey container — wrong filesystem, wrong user, and almost none of the
# tooling a fleet script needs (the first smoke test returned the container ID
# for `hostname`, `root` for `id -un`, and "uptime: command not found").
# Docker-mode lokey bind-mounts the host root at /host, so re-enter it with
# chroot and drop to the owning user: scripts like `refresh` depend on that
# user's $HOME, ~/.local/bin and crontab, none of which exist for container root.
# Native installs already run on the host as the right user, so they pass through.
EXEC_HOST_USER = os.environ.get("LOKEY_EXEC_USER", "swoopg111")


def _exec_argv(script):
    """Build the argv that runs `script` in the right place for this install mode."""
    if os.path.isdir("/host/proc"):
        return ["chroot", "/host", "/bin/su", "-", EXEC_HOST_USER, "-c", script]
    return ["/bin/bash", "-c", script]


def execute_command(cmd):
    """Run a locator-issued command on this unit. Returns a result dict —
    {success, stdout, stderr, exit_code} — uniformly for every action.

    'exec' runs an arbitrary shell command/script: the locator is the only
    decision-maker about what runs, this just executes whatever it queues
    and reports back. 'stop'/'start' are the older container-toggle actions."""
    action = cmd.get("action")
    result = {"success": False, "stdout": "", "stderr": "", "exit_code": None}

    if action == "exec":
        script = cmd.get("script") or ""
        try:
            proc = subprocess.run(
                _exec_argv(script),
                capture_output=True, text=True, timeout=EXEC_TIMEOUT,
            )
            result["stdout"] = proc.stdout[-EXEC_OUTPUT_CAP:]
            result["stderr"] = proc.stderr[-EXEC_OUTPUT_CAP:]
            result["exit_code"] = proc.returncode
            result["success"] = proc.returncode == 0
            print(f"[{UNIT_NAME}] 🏃 exec '{script[:80]}' → exit {proc.returncode} (locator command)")
        except subprocess.TimeoutExpired:
            result["stderr"] = f"timed out after {EXEC_TIMEOUT}s"
            print(f"[{UNIT_NAME}] exec '{script[:80]}' timed out after {EXEC_TIMEOUT}s")
        except Exception as e:
            result["stderr"] = str(e)
            print(f"[{UNIT_NAME}] exec '{script[:80]}' failed: {e}")
        return result

    name = cmd.get("container")
    if not _docker_client or not name:
        return result
    try:
        c = _docker_client.containers.get(name)
        if action == "stop":
            if _is_protected(c):
                print(f"[{UNIT_NAME}] 🛡️  refusing to stop protected container '{name}'")
                return result
            c.stop(timeout=30)
            print(f"[{UNIT_NAME}] 💤 stopped '{name}' (locator command)")
            result["success"] = True
            return result
        if action == "start":
            c.start()
            print(f"[{UNIT_NAME}] 🟢 started '{name}' (locator command)")
            result["success"] = True
            return result
        print(f"[{UNIT_NAME}] unknown command action: {action}")
        return result
    except Exception as e:
        print(f"[{UNIT_NAME}] command {action} '{name}' failed: {e}")
        result["stderr"] = str(e)
        return result


def check_pending_commands():
    """Poll the locator for commands aimed at this unit and run them."""
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
        result = execute_command(cmd)
        try:
            requests.post(
                f"{LOCATOR_URL}/api/commands/complete",
                json={"id": cmd["id"], **result},
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


# ── REPO SYNC ────────────────────────────────────────────────────────────────
# Fleet-wide repo propagation, taking over the sync half of the standalone
# `refresh` script. That script was installed on unit3 alone and could not fan
# out from there because the host has no jq, so its fan-out hit a silent `skip`
# on every run and nothing ever propagated. lokey already runs on every unit,
# every ~5 minutes, with working git credentials and /host access — so the work
# belongs here, where a failure is also visible instead of silent.

SYNC_REPOS_ENABLED = os.getenv("SYNC_REPOS_ENABLED", "true").lower() == "true"
SYNC_REPOS_ROOT    = os.getenv("SYNC_REPOS_ROOT", "/home/swoopg111/projects")
# Pull-only by default. Pushing would `add -A` and commit whatever happens to
# be dirty in every checkout on every unit — stray .bak files, editor litter,
# half-finished work — and push it. Propagation is the valuable half; enable
# this per-unit once you trust what is sitting in those working trees.
SYNC_REPOS_PUSH    = os.getenv("SYNC_REPOS_PUSH", "false").lower() == "true"
SYNC_REPOS_SKIP    = {s.strip() for s in os.getenv("SYNC_REPOS_SKIP", "").split(",") if s.strip()}


def report_event(kind, message):
    """Surface an event on the locator's dashboard EVENT LOG. Best-effort."""
    try:
        requests.post(
            f"{LOCATOR_URL}/api/events",
            json={"type": kind, "message": message, "unit": UNIT_NAME},
            headers={"Host": LOCATOR_HOST_HEADER}, timeout=5, verify=False,
        )
    except Exception:
        pass


_git_token_cache = None


def _git_token():
    """Reuse the token already embedded in lokey's own remote URL.

    Most checkouts on these units have credential-less https remotes, so every
    pull dies with "could not read Username". Rather than writing a token into
    each repo's config on each unit — scattering the same secret across dozens
    of .git/config files — lift the one lokey already has and hand it to git
    transiently.
    """
    global _git_token_cache
    if _git_token_cache is None:
        _git_token_cache = os.getenv("GIT_TOKEN", "")
        if not _git_token_cache:
            try:
                url = subprocess.run(
                    ["git", "-C", _host_dir(LOKEY_PROJECT_DIR), "remote", "get-url", "origin"],
                    capture_output=True, text=True, timeout=15,
                ).stdout
                match = re.search(r"://[^:/]+:([^@]+)@", url)
                _git_token_cache = match.group(1) if match else ""
            except Exception:
                _git_token_cache = ""
    return _git_token_cache


def _git(cwd, *args, timeout=90):
    """Run git against a host checkout.

    safe.directory is forced because the container runs as root while the
    checkouts are owned by the login user; without it git refuses with
    "dubious ownership" and every sync would fail.
    """
    cmd = ["git", "-c", "safe.directory=*"]
    env = dict(os.environ)
    token = _git_token()
    if token:
        # The helper reads $GIT_TOKEN at run time, so the secret is passed via
        # the environment and never appears in argv (where `ps` would show it).
        cmd += ["-c", "credential.helper=!f(){ echo username=oauth2; echo password=$GIT_TOKEN; }; f"]
        env["GIT_TOKEN"] = token
    cmd += ["-C", cwd, *args]

    # Run as the checkout's owner rather than root. The container is root, so
    # any object it writes lands root-owned inside a user-owned .git — after
    # which the login user (and the autosave cron) fails with "insufficient
    # permission for adding an object to repository database". Syncing a repo
    # should never make it unusable for its owner.
    preexec = _drop_to_owner(cwd)
    if preexec:
        env["HOME"] = "/tmp"  # dropped user may not have a home in this image

    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env=env, preexec_fn=preexec)


def _drop_to_owner(path):
    """preexec_fn that becomes the path's owner, or None if not applicable."""
    try:
        if os.geteuid() != 0:
            return None
        st = os.stat(path)
        if st.st_uid == 0:
            return None
        uid, gid = st.st_uid, st.st_gid
    except Exception:
        return None

    def _switch():
        os.setgid(gid)
        os.setuid(uid)

    return _switch


def _sync_one_repo(path, label):
    """Push local commits, then fast-forward. Returns (changed, error)."""
    if _git(path, "remote", "get-url", "origin").returncode != 0:
        return False, None  # no remote — nothing to sync against, not an error

    before = _git(path, "rev-parse", "HEAD").stdout.strip()

    if SYNC_REPOS_PUSH:
        if _git(path, "status", "--porcelain").stdout.strip():
            _git(path, "add", "-A")
            _git(path, "commit", "-m",
                 f"auto: {UNIT_NAME} {datetime.now(timezone.utc):%Y-%m-%d %H:%M}",
                 "--no-verify")
        # Push before pulling so local work is backed up before any fast-forward.
        ahead = _git(path, "rev-list", "--count", "@{u}..HEAD").stdout.strip()
        if ahead.isdigit() and int(ahead) > 0:
            push = _git(path, "push", "origin", "HEAD")
            if push.returncode != 0:
                return False, f"push failed: {push.stderr.strip()[:120]}"

    pull = _git(path, "pull", "--ff-only")
    if pull.returncode != 0:
        return False, f"pull failed: {pull.stderr.strip()[:120]}"

    after = _git(path, "rev-parse", "HEAD").stdout.strip()
    return (before != after), None


def sync_repos():
    """Sync every git checkout under SYNC_REPOS_ROOT on this unit."""
    if not SYNC_REPOS_ENABLED:
        return
    root = _host_dir(SYNC_REPOS_ROOT)
    if not os.path.isdir(root):
        print(f"[{UNIT_NAME}] repo-sync: root not found ({SYNC_REPOS_ROOT})")
        return

    # lokey's own checkout is left to self_update(), which also rebuilds the
    # container when the code changes; syncing it here too would race that.
    skip = SYNC_REPOS_SKIP | {os.path.basename(LOKEY_PROJECT_DIR.rstrip("/"))}

    changed, failed = [], []
    for name in sorted(os.listdir(root)):
        if name in skip:
            continue
        path = os.path.join(root, name)
        if not os.path.isdir(os.path.join(path, ".git")):
            continue
        try:
            did_change, error = _sync_one_repo(path, name)
        except Exception as e:
            did_change, error = False, f"{type(e).__name__}: {e}"
        if error:
            failed.append(f"{name} ({error})")
            print(f"[{UNIT_NAME}] repo-sync ❌ {name}: {error}")
        elif did_change:
            changed.append(name)
            print(f"[{UNIT_NAME}] repo-sync ⬇️  {name}: updated")

    if changed:
        report_event("repo-sync", f"{UNIT_NAME}: updated {', '.join(changed)}")
    if failed:
        report_event("repo-sync-failed", f"{UNIT_NAME}: {'; '.join(failed)}")


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

    # Collect and cache IPs on startup
    _private_ip = get_private_ip()
    _tailscale_ip_cached = get_tailscale_ip()
    _start_public_ip_background_fetch()  # Non-blocking fetch, result cached globally

    # Log IPs for startup diagnostics
    print(f"[{UNIT_NAME}] private_ip: {_private_ip or 'unavailable'}")
    print(f"[{UNIT_NAME}] tailscale_ip: {_tailscale_ip_cached or 'unavailable'}")
    print(f"[{UNIT_NAME}] public_ip: fetching (non-blocking)...")

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
        if UNIT_NAME == "unit8":
            _dns_tick += 1
            if _dns_tick >= 5:
                _dns_tick = 0
                try:
                    from sync_dns_pdns import sync as pdns_sync
                    pdns_sync(target_ip=_public_ip)
                except Exception as e:
                    print(f"[{UNIT_NAME}] dns-sync error: {e}")
        if UNIT_NAME == "unit1":
            ddns_ip_watcher()
        _update_tick += 1
        if _update_tick >= 5:
            _update_tick = 0
            self_update()
            sync_repos()
        time.sleep(TICK_RATE)
