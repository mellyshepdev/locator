import importlib.util
import psutil
import time
import os
import re
import shlex
import shutil
import sys
import signal
import subprocess
import pwd
import socket
import threading
import requests
import envscan
import unitsecrets
import urllib3
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from types import SimpleNamespace

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default to the live locator. This fallback used to name a decommissioned
# Fly app, so any native install without an explicit LOCATOR_URL reported into
# the void even while running current code — unit6 did exactly that for ~65
# days. Only docker-compose.yml carried the correct value.
# One canonical default for the whole fleet. locator-vpn is a LUA ifportup
# record over tailnet candidates: pdns health-checks :50500 and answers with
# whichever unit actually serves the locator — no hardcoded host, and reaching
# it does not depend on the public edge.
LOCATOR_URL = os.getenv("LOCATOR_URL", "http://locator-vpn.prime-quality.online:50500")
LOCATOR_HOST_HEADER = os.getenv("LOCATOR_HOST_HEADER", "locator-vpn.prime-quality.online")
# Needed only to trade bao:// references for values at /api/secrets/resolve.
# Everything else lokey does stays on the unauthenticated ingest routes.
LOCATOR_ADMIN_KEY = os.getenv("LOCATOR_ADMIN_KEY", "")
# unit7's locator sits on command_lock for tens of seconds under load — a 5s
# read timeout meant agents NEVER got through (commands, metrics, policy all
# timing out). Anything carrying verify=False is a locator HTTP call.
LOCATOR_HTTP_TIMEOUT = int(os.getenv("LOCATOR_HTTP_TIMEOUT", "60"))

# Trade any bao:// reference in this unit's OWN environment for its value
# before a single constant below reads it — DDNS_SECRET, PDNS_API_KEY and the
# rest are then plain values to everything downstream, including the dns-sync
# modules, which hard-stats imports lazily on the tick. A unit whose config
# holds no references makes no call here.
try:
    from bao_env import hydrate_env as _hydrate_env
    _hydrate_env(LOCATOR_URL, LOCATOR_HOST_HEADER, LOCATOR_ADMIN_KEY,
                 os.getenv("UNIT_NAME", "unknown_unit"))
except Exception as _bao_err:      # never let this stop the heartbeat
    print(f"[bao] env hydration skipped ({_bao_err})")

UNIT_NAME   = os.getenv("UNIT_NAME", "unknown_unit")
TICK_RATE   = int(os.getenv("TICK_RATE", "60"))
# Per-container vitals sweep bounds. On a loaded box one docker stats call
# costs ~4-6s; times ~60 containers a serial sweep ran past TICK_RATE and the
# tick backed up for tens of minutes. The pool runs the calls concurrently
# and the deadline keeps one stalled stats read from freezing the report —
# stragglers register without vitals rather than not at all.
VITALS_WORKERS  = int(os.getenv("VITALS_WORKERS", "8"))
VITALS_DEADLINE = int(os.getenv("VITALS_DEADLINE", "90"))
# What `cpu_percent` reports. Per-unit on purpose — set it in a unit's
# docker-compose.override.yml, not here.
#   spot    (default) psutil.cpu_percent(interval=1) — the historical reading.
#   loadavg           5-minute load average / core count.
#
# Why the choice exists: `spot` samples one second in every TICK_RATE (60) and
# reports it as the whole minute. On a small box that quantises badly — on 2
# cores one briefly-busy core reads 50% and both read ~100%, so dockerd churn
# landing inside the window prints a number the machine never sustained.
# Measured on unit7 (2 cores, genuinely idle): 75 consecutive spot samples ran
# 0.5%–43.2% with a mean of 6.0%, while loadavg held flat at 0.29. That swing
# is the gauge, not the load. `loadavg` is kernel-smoothed over 5 minutes and
# divided by core count so small and large units stay comparable.
CPU_METRIC  = os.getenv("CPU_METRIC", "spot").strip().lower()
# Off-net address used only to make the kernel pick an outbound route in
# get_private_ip(). No packet is sent and it is never resolved, so this is a
# routing-table lookup, not a dependency on that host. Overridable anyway.
ROUTE_PROBE_ADDR = os.getenv("ROUTE_PROBE_ADDR", "8.8.8.8")
# Memory-pressure event detection. OOMKilled is a sticky inspect flag that
# clears on container restart, so the only trustworthy signal is the
# False->True transition observed across ticks — we keep the set of names
# currently flagged and report the delta. Spikes are simpler: a container or
# the node itself jumping by DELTA percentage points inside one tick, or
# crossing the high-water mark, files a 'mem_spike'/'node_mem_spike' event in
# the locator's events table via the metrics payload.
MEM_SPIKE_DELTA  = float(os.getenv("MEM_SPIKE_DELTA", "25"))   # pp jump in one tick
MEM_SPIKE_FLOOR  = float(os.getenv("MEM_SPIKE_FLOOR", "80"))   # delta only counts if it lands above this
MEM_SPIKE_CROSS  = float(os.getenv("MEM_SPIKE_CROSS", "90"))   # crossing this always flags
NODE_SPIKE_DELTA = float(os.getenv("NODE_SPIKE_DELTA", "20"))
NODE_CRIT_PCT    = float(os.getenv("NODE_CRIT_PCT", "95"))
_prev_oom      = set()    # container names currently flagged OOMKilled
_prev_mem      = {}       # container name -> mem_percent at last tick
_prev_node_mem = None     # node mem_percent at last tick
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
# Repo cloned when this unit has no locator checkout at failover time — the
# whole point of a standby is coming up on a unit that never hosted locator.
LOCATOR_REPO_URL         = (os.getenv("LOCATOR_REPO_URL")
                            or "https://github.com/mellyshepdev/locator.git")
# Fallback clone target when LOCATOR_COMPOSE_DIR is unset.
LOCATOR_STANDBY_DIR      = (os.getenv("LOCATOR_STANDBY_DIR")
                            or f"/home/{REMOTE_USER}/projects/locator")
# Host port the standby publishes. :5000 is taken on some units (puffbase on
# unit7), so the port is configurable rather than a failover that can never bind.
LOCATOR_STANDBY_PORT     = int(os.getenv("LOCATOR_STANDBY_PORT", "5000"))

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
except Exception as _e:          # the SDK itself is missing — nothing to retry
    docker_sdk = None
    print(f"⚠️  docker SDK unavailable: {type(_e).__name__}: {_e}", flush=True)

_docker_client = None
_docker_client_lock = threading.Lock()
_docker_last_error = None
_docker_last_error_logged = 0.0


def _ensure_docker(retry_seconds=60):
    """The docker client, created on first use and RETRIED after a failure.

    This was a single module-level `from_env()` wrapped in a bare
    `except Exception: _docker_client = None`. Two things made that quietly
    catastrophic: nothing ever retried, and nothing ever logged. If the call
    failed for any reason during container start — a socket not yet usable, a
    daemon mid-restart — the client stayed None for the entire life of the
    process, and every heartbeat afterwards reported `containers: 0` with no
    explanation anywhere.

    unit4 sat in exactly that state with 11 containers running, including the
    locator itself. Since lokey is what puts containers in the registry, the
    locator never appeared in its own registry, `_locator_hosts()` could only
    ever see itself, and the election had nothing to elect between. The whole
    failover path was dead downstream of this one swallowed exception.

    Errors are logged at most once per retry window so a genuinely dead socket
    cannot flood the log.
    """
    global _docker_client, _docker_last_error, _docker_last_error_logged
    if _docker_client is not None:
        return _docker_client
    if docker_sdk is None:
        return None
    with _docker_client_lock:
        if _docker_client is not None:      # another thread won the race
            return _docker_client
        try:
            client = docker_sdk.from_env()
            client.ping()                   # from_env() alone does not connect
            _docker_client = client
            if _docker_last_error:
                print(f"[{UNIT_NAME}] 🐳 docker client recovered", flush=True)
                _docker_last_error = None
            return _docker_client
        except Exception as e:
            _docker_last_error = f"{type(e).__name__}: {e}"
            now = time.time()
            if now - _docker_last_error_logged >= retry_seconds:
                _docker_last_error_logged = now
                print(f"[{UNIT_NAME}] ⚠️  docker client unavailable — "
                      f"containers cannot be reported: {_docker_last_error}",
                      flush=True)
            return None

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


def get_battery():
    """Charge level + AC state, or None on hardware with no battery.

    psutil.sensors_battery() reads /sys/class/power_supply on Linux (the host's
    battery is visible inside our container too), IOKit on macOS and WMI on
    Windows — one call covers every platform lokey runs on. A None result
    means "this box has no battery" (desktops, VMs, servers) and propagates as
    omitted fields rather than a phantom 0%.
    """
    try:
        b = psutil.sensors_battery()
    except Exception:
        return None
    if b is None or b.percent is None:
        return None
    secsleft = b.secsleft
    if not isinstance(secsleft, int) or secsleft < 0:
        # POWER_TIME_UNKNOWN (-1) and POWER_TIME_UNLIMITED (-2, i.e. on AC
        # with a full battery) are not durations — don't report them as such.
        secsleft = None
    return {
        "battery_percent": round(b.percent, 1),
        # The dashboard treats charging as the healthy state: a low battery on
        # the charger is recovering, not alerting.
        "charging": bool(b.power_plugged),
        "battery_secsleft": secsleft,
    }


def get_system_stats():
    cpu_spot = psutil.cpu_percent(interval=1)

    # Both are always computed and always reported, whatever CPU_METRIC picks —
    # so a unit that looks wrong can be compared against the other reading
    # without redeploying it to find out.
    cores = psutil.cpu_count() or 1
    try:
        cpu_load = round(min(100.0, 100.0 * psutil.getloadavg()[1] / cores), 1)
    except (OSError, AttributeError):     # no getloadavg on this platform
        cpu_load = None

    cpu_usage = cpu_load if (CPU_METRIC == "loadavg" and cpu_load is not None) else cpu_spot

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

    stats = {
        "cpu_usage_percent": cpu_usage,
        "cpu_spot_percent": cpu_spot,
        "cpu_loadavg_percent": cpu_load,
        "cpu_cores": cores,
        "cpu_metric": CPU_METRIC,
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
    # Battery rides the same stats dict so it lands in the /register metadata
    # (the lokey service record — feeding locator's low-battery alert edge
    # trigger, which already reads metadata.battery_percent from the Android
    # client) and, via explicit picks in push_node_metrics, on the node record.
    batt = get_battery()
    if batt:
        stats.update(batt)
    return stats

def extract_traefik_hosts(labels):
    """Return hostnames declared in Traefik Host(...) router rules."""
    hosts = []
    for key, value in labels.items():
        if re.match(r"traefik\.http\.routers\..+\.rule", key):
            hosts += re.findall(r"Host\(`([^`]+)`\)", value)
    return hosts


def _get_container_vitals(container):
    """One stats() snapshot → the container's full vitals dict.

    The registry's per-container data sheet wants more than RAM: cpu% (delta
    against the precpu sample docker keeps inside the same payload, so a
    single non-streaming call suffices), net rx/tx, block I/O and pids all
    ride the one stats request we were already making for memory. Missing
    pieces degrade to None rather than dropping the container.
    """
    try:
        raw = container.stats(stream=False)
    except Exception:
        return {"mem_usage_mb": None, "mem_limit_mb": None, "mem_percent": None}
    mem = raw.get("memory_stats", {})
    usage = mem.get("usage", 0)
    limit = mem.get("limit", 1)
    cache = mem.get("stats", {}).get("inactive_file", 0)
    rss = max(0, usage - cache)

    cpu_percent = None
    try:
        cpu_delta = (raw["cpu_stats"]["cpu_usage"]["total_usage"]
                     - raw["precpu_stats"]["cpu_usage"]["total_usage"])
        sys_delta = (raw["cpu_stats"]["system_cpu_usage"]
                     - raw["precpu_stats"]["system_cpu_usage"])
        online_cpus = (raw["cpu_stats"].get("online_cpus")
                       or len(raw["cpu_stats"]["cpu_usage"].get("percpu_usage") or [])
                       or 1)
        if sys_delta > 0 and cpu_delta >= 0:
            cpu_percent = round(cpu_delta / sys_delta * online_cpus * 100, 1)
    except (KeyError, TypeError):
        pass

    rx_bytes = tx_bytes = 0
    for net in (raw.get("networks") or {}).values():
        rx_bytes += net.get("rx_bytes", 0)
        tx_bytes += net.get("tx_bytes", 0)

    blk_read = blk_write = 0
    for entry in (raw.get("blkio_stats", {}).get("io_service_bytes_recursive") or []):
        op = (entry.get("op") or "").lower()
        if op == "read":
            blk_read += entry.get("value", 0)
        elif op == "write":
            blk_write += entry.get("value", 0)

    return {
        "mem_usage_mb": round(rss / (1024 ** 2), 1),
        "mem_limit_mb": round(limit / (1024 ** 2), 1),
        "mem_percent": round(rss / limit * 100, 1) if limit > 0 else 0.0,
        "cpu_percent": cpu_percent,
        "net_rx_bytes": rx_bytes,
        "net_tx_bytes": tx_bytes,
        "blk_read_bytes": blk_read,
        "blk_write_bytes": blk_write,
        "pids": (raw.get("pids_stats") or {}).get("current"),
    }


# Image tag resolution is memoized: compose replicas share an image, and a
# serial images.get() per container is wasted tail latency on a loaded box.
# Failure (image pruned out from under a still-listed container — the old
# unit8 "containers: 0" bug) degrades to the requested Config.Image string.
_image_tags = {}

def _image_tag(client, ref, config_image=None):
    if ref and ref not in _image_tags:
        try:
            img = client.images.get(ref)
            _image_tags[ref] = img.tags[0] if img.tags else img.short_id
        except Exception:
            _image_tags[ref] = None
    return _image_tags.get(ref) or config_image


def _collect_running(c):
    """Full per-container record for the /register payload.

    Runs inside the vitals pool — each call owns its own Container object, so
    the shared client only ever sees ordinary parallel HTTP on the docker
    socket. Everything lazily-inspecting stays behind one guard so a single
    vanished container skips itself instead of aborting the sweep.
    """
    vitals = _get_container_vitals(c)
    # sparse list attrs lack StartedAt/Health — the full inspect has them.
    # Local docker-socket call, cheap per container; a flaky inspect drops
    # just this container's entry, not the tick.
    c.reload()
    a = c.attrs or {}
    c_state = a.get("State") or {}
    # The docker HEALTHCHECK verdict — 'healthy' is the ONLY proof the
    # locator accepts for a green/verified status. Absent here means no
    # HEALTHCHECK defined, which is 'unverified', not failed: the locator
    # makes that distinction, we just report.
    return {
        "name": c.name,
        "image": _image_tag(c.client, a.get("Image") or a.get("ImageID"),
                            (a.get("Config") or {}).get("Image")),
        "labels": c.labels,
        "compose_dir": c.labels.get("com.docker.compose.project.working_dir"),
        "networks": list((a.get("NetworkSettings") or {}).get("Networks") or {}),
        # Runtime mount truth — what is actually attached, not what the compose
        # file declares. The locator's migration preflight reads this to decide
        # whether a service can move (volume data travels or refuses).
        "mounts": [
            {"type": m.get("Type"), "name": m.get("Name"),
             "source": m.get("Source"), "destination": m.get("Destination"),
             "rw": m.get("RW")}
            for m in (a.get("Mounts") or [])
        ],
        "started_at": c_state.get("StartedAt"),
        "health": (c_state.get("Health") or {}).get("Status"),
        "state": c_state.get("Status"),
        "exit_code": c_state.get("ExitCode"),
        "oom_killed": c_state.get("OOMKilled"),
        # RestartCount is a TOP-LEVEL inspect field, not inside State.
        "restart_count": a.get("RestartCount"),
        "finished_at": c_state.get("FinishedAt"),
        **vitals,
    }


def _collect_fallback(c):
    """List-payload-only record for sweep-deadline stragglers — no inspect,
    no stats. Keeps the container visible as running/unverified instead of
    reporting it as gone (which would flap its registry status)."""
    a = getattr(c, "attrs", None) or {}
    names = a.get("Names") or []
    labels = a.get("Labels") or {}
    return {
        "name": names[0].lstrip("/") if names else c.id[:12],
        "image": a.get("Image"),
        "labels": labels,
        "compose_dir": labels.get("com.docker.compose.project.working_dir"),
        "networks": list((a.get("NetworkSettings") or {}).get("Networks") or {}),
        "mounts": [
            {"type": m.get("Type"), "name": m.get("Name"),
             "source": m.get("Source"), "destination": m.get("Destination"),
             "rw": m.get("RW")}
            for m in (a.get("Mounts") or [])
        ],
        "started_at": None,
        "health": None,
        "state": a.get("State"),
    }


# The last completed vitals sweep. report_idle_stats reads net counters from
# it instead of running a second serial stats pass over the watched set.
_last_running = []

def get_docker_containers():
    global _last_running
    _last_running = []
    client = _ensure_docker()
    if not client:
        # _ensure_docker already logged why, rate-limited.
        return {"running": [], "all": [], "error": _docker_last_error or "no docker client"}
    try:
        running = []
        try:
            # sparse=True on purpose. The default list() inspects EVERY
            # container serially to fill attrs — ~60 inspects the pool would
            # then repeat via reload(). Sparse gives the raw `docker ps`
            # payload (Names/Labels/State) which is all the deadline fallback
            # needs; the inspects happen concurrently in the pool instead.
            listed = client.containers.list(sparse=True)
        except Exception as e:
            print(f"[{UNIT_NAME}] ⚠️  container list failed ({type(e).__name__})",
                  flush=True)
            listed = []
        # Parallel sweep. Each stats+inspect costs ~4-6s on a loaded box, so a
        # serial pass ran ~6-10min against a 60s TICK_RATE and the registry
        # starved. The deadline bounds the whole sweep: a container whose
        # stats read stalls (docker holds the cgroup lock under memory
        # pressure — seen on odoo/live-logger) reports without vitals via the
        # fallback instead of freezing every tick behind it.
        pool = ThreadPoolExecutor(max_workers=VITALS_WORKERS,
                                  thread_name_prefix="vitals")
        try:
            futures = {pool.submit(_collect_running, c): c for c in listed}
            try:
                for fut in as_completed(futures, timeout=VITALS_DEADLINE):
                    c = futures[fut]
                    try:
                        running.append(fut.result())
                    except Exception as e:
                        # Per-container guard. containers.list() is a snapshot;
                        # by the time we ask for one container's stats it may
                        # already be gone, and the SDK raises NotFound. That
                        # used to escape the whole for-loop, so a SINGLE
                        # short-lived container vanishing mid-sweep reported
                        # the host as having ZERO containers — which is how
                        # unit4 sat with 11 containers running, the locator
                        # among them, while lokey told the registry it had
                        # none. Skip the casualty, keep the rest.
                        print(f"[{UNIT_NAME}] skipping container {c.id[:12]}: "
                              f"{type(e).__name__}", flush=True)
            except TimeoutError:
                pass
            for fut, c in futures.items():
                if not fut.done():
                    print(f"[{UNIT_NAME}] vitals deadline hit — reporting "
                          f"{c.id[:12]} without vitals", flush=True)
                    running.append(_collect_fallback(c))
        finally:
            pool.shutdown(wait=False)
        # Separate try: the all=True listing is the fragile one. docker-py
        # inspects every container to build these objects, and unit4 has a
        # PHANTOM — an entry docker ps -a shows but docker inspect calls "no
        # such object", left by a container that died badly 42h ago. That one
        # 404 used to abort this whole function, so the running list died with
        # it and the host reported zero containers indefinitely. The full
        # listing is a nice-to-have; the running list is what the registry
        # actually needs, so never let the former take out the latter.
        all_containers = []
        try:
            # Low-level API on purpose. containers.list(all=True) INSPECTS every
            # entry to build model objects, so the phantom described above 404s
            # the entire call and leaves this list empty. client.api.containers
            # returns the raw `docker ps -a` payload with no per-container
            # inspect, so one dead entry costs one dead entry.
            #
            # This mattered more than "a nice-to-have": `all` is the only place
            # a STOPPED container is reported, so while this was failing the
            # registry knew about running containers only — and wake-on-request
            # exists precisely to start containers that are stopped. unit4's
            # welcome-hub sat Exited(0) for 31h serving 502s partly because of
            # this: nothing could tell locator the container was even there.
            for c in client.api.containers(all=True):
                names = c.get("Names") or []
                name = names[0].lstrip("/") if names else (c.get("Id") or "")[:12]
                if not name:
                    continue
                all_containers.append({"name": name, "status": c.get("State", "")})
        except Exception as e:
            print(f"[{UNIT_NAME}] ⚠️  full container listing unavailable "
                  f"({type(e).__name__}) — reporting running containers only",
                  flush=True)
        _last_running = running
        return {"running": running, "all": all_containers}
    except Exception as e:
        # Was swallowed into a returned key nobody read, so a failure here was
        # indistinguishable from a host with no containers. Say it out loud.
        print(f"[{UNIT_NAME}] ⚠️  container enumeration failed: "
              f"{type(e).__name__}: {e}", flush=True)
        return {"running": [], "all": [], "error": str(e)}


# ── POLICY-DRIVEN KEEP-ALIVE ─────────────────────────────────────────────────
# Source of truth is locator.yml, enforced here rather than by the locator's
# critical_service_watchdog(). That watchdog needs the registry to show a
# service OFFLINE *and* its node ONLINE before it queues a start, so it goes
# blind exactly when registration is failing — which is when a stopped
# container most needs restarting. lokey already holds a Docker socket, so it
# can see the same fact one hop earlier and act with no round trip.
KEEPALIVE_LABEL    = "lokey.keepalive"          # per-container override
KEEPALIVE_COOLDOWN = int(os.getenv("KEEPALIVE_COOLDOWN", "300"))
POLICY_CACHE       = os.getenv("LOKEY_POLICY_CACHE", "/var/lib/lokey/policy.json")
_keepalive_last: dict = {}   # container name → epoch of last start attempt


def _policy_cache_path():
    """Cache path on the HOST filesystem, not inside this container.

    A container-local path is wiped by every self_update rebuild, which would
    leave the agent with no policy at exactly the moment it restarts.
    """
    return _host_dir_for_create(POLICY_CACHE)


def fetch_policy():
    """This unit's slice of locator.yml, cached to disk.

    Enforcement always reads the CACHE, never the response, so a locator that
    is unreachable, unregistered or simply gone degrades to "keep enforcing the
    last policy I saw" rather than "stop enforcing". That is the entire reason
    this lives in lokey instead of the locator.
    """
    path = _policy_cache_path()
    try:
        r = requests.get(
            f"{LOCATOR_URL}/api/policy/{UNIT_NAME}",
            headers={"Host": LOCATOR_HOST_HEADER},
            timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                tmp = path + ".tmp"
                with open(tmp, "w") as fh:
                    json.dump(data, fh)
                os.replace(tmp, path)   # atomic: never leave a half-written cache
                return data
        else:
            print(f"[{UNIT_NAME}] policy fetch: HTTP {r.status_code}", flush=True)
    except Exception as e:
        print(f"[{UNIT_NAME}] policy fetch failed ({type(e).__name__}) — "
              f"using cached policy", flush=True)
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return {}


def keep_alive():
    """Start containers this unit's policy says must not stay stopped.

    Opt-in, never blanket. Two systems on this fleet stop containers on
    purpose — Sablier's scale-to-zero and the locator's idle shutdown — and a
    human stopping something to work on it is a third. Only services with
    restart_when_stopped, or a container carrying the override label, are
    touched.

    Does not replace compose's own `restart:` policy; it covers what that
    cannot. `unless-stopped` never returns from a deliberate `docker stop`,
    and `restart: "no"` never returns from anything.
    """
    client = _ensure_docker()
    if not client:
        return
    policy = fetch_policy()
    wanted = {n for n, cfg in policy.items()
              if isinstance(cfg, dict) and cfg.get("restart_when_stopped")}
    try:
        # Raw `docker ps -a` payload — names/labels/state are all the scan
        # needs, and containers.list(all=True) inspects EVERY container
        # serially (~76 calls, minutes on a loaded box). The one container a
        # tick actually restarts gets fetched by id at that point.
        listed = client.api.containers(all=True)
    except Exception as e:
        # Same phantom-container hazard as the heartbeat's all=True listing:
        # one bad inspect must not take out the sweep.
        print(f"[{UNIT_NAME}] keep-alive: listing unavailable "
              f"({type(e).__name__})", flush=True)
        return

    now = time.time()
    for c in listed:
        names = c.get("Names") or []
        name = names[0].lstrip("/") if names else (c.get("Id") or "")[:12] or "?"
        try:
            labelled = ((c.get("Labels") or {}).get(KEEPALIVE_LABEL, "")
                        .strip().lower() in ("true", "1", "yes"))
            if name not in wanted and not labelled:
                continue
            status = c.get("State") or ""
            if status == "running":
                _keepalive_last.pop(name, None)
                continue
            # Cooldown so a container that dies on startup is retried slowly
            # rather than hammered once a tick forever.
            if now - _keepalive_last.get(name, 0) < KEEPALIVE_COOLDOWN:
                continue
            _keepalive_last[name] = now
            client.containers.get(c["Id"]).start()
            print(f"[{UNIT_NAME}] 🔁 keep-alive: started {name} (was {status})", flush=True)
            report_event("keep-alive", f"{UNIT_NAME}: restarted {name} (was {status})")
        except Exception as e:
            print(f"[{UNIT_NAME}] keep-alive error on {name}: "
                  f"{type(e).__name__}: {e}", flush=True)

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
        s.connect((ROUTE_PROBE_ADDR, 80))
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


def _render_compose_from_inspect(container_name):
    """Render a compose file from a live container's inspect data.

    docker run-managed containers have no compose file to upload — their
    config lives only in daemon memory and dies with the container. This
    renders an equivalent service block so the locator's compose store
    covers them too. It goes up as '<name>.rendered.yml', a separate slot
    from '<name>.yml': a render must never clobber the real compose of a
    container whose labels flap.

    Env VALUES are redacted — inspect returns them in plaintext and they can
    be secrets; the unit's .env / OpenBao stays the source of truth.
    """
    try:
        a = _ensure_docker().containers.get(container_name).attrs
    except Exception:
        return None
    cfg = a.get("Config") or {}
    hcfg = a.get("HostConfig") or {}
    nets = (a.get("NetworkSettings") or {}).get("Networks") or {}

    out = [
        "# RENDERED from docker inspect — NOT the deployment source of truth.",
        "# This container is docker run-managed; the snapshot exists so the",
        "# locator compose store covers it. Env values are redacted — the",
        "# unit's .env / OpenBao is the source of truth for secrets.",
        "services:",
        f"  {container_name}:",
        f"    image: {cfg.get('Image') or 'unknown'}",
        f"    container_name: {container_name}",
    ]
    rp = (hcfg.get("RestartPolicy") or {}).get("Name")
    if rp and rp != "no":
        out.append(f"    restart: {rp}")
    if hcfg.get("NetworkMode") == "host":
        out.append("    network_mode: host")
    else:
        pb = hcfg.get("PortBindings") or {}
        if pb:
            out.append("    ports:")
            for cport, binds in pb.items():
                for b in (binds or [{}]):
                    hip, hp = b.get("HostIp") or "", b.get("HostPort") or ""
                    spec = f"{hip}:{hp}:{cport}" if hip else (f"{hp}:{cport}" if hp else cport)
                    out.append(f'      - "{spec}"')
        net_names = [n for n in nets if n not in ("bridge", "host", "none")]
        if net_names:
            out.append("    networks:")
            out += [f"      - {n}" for n in net_names]
    env = [e.split("=", 1)[0] for e in (cfg.get("Env") or [])]
    if env:
        out.append("    environment:  # keys only — values redacted")
        out += [f"      - {k}  # value redacted" for k in env]
    mounts, named = [], []
    for m in a.get("Mounts") or []:
        if m.get("Type") == "bind":
            mounts.append(f"{m['Source']}:{m['Destination']}")
        elif m.get("Type") == "volume":
            mounts.append(f"{m['Name']}:{m['Destination']}")
            named.append(m["Name"])
    if mounts:
        out.append("    volumes:")
        out += [f'      - "{v}"' for v in mounts]
    for k, v in (("entrypoint", cfg.get("Entrypoint")), ("command", cfg.get("Cmd"))):
        if v:
            out.append(f"    {k}: {json.dumps(v)}")
    if hcfg.get("Privileged"):
        out.append("    privileged: true")
    if named:
        out.append("volumes:")
        out += [f"  {n}:" for n in sorted(set(named))]
    return "\n".join(out) + "\n"


def upload_compose(container_name, compose_dir, headers):
    """Upload a container's docker-compose.yml to the locator compose store.

    The store endpoint is clearance-gated: it accepts this unit's key
    (preferred — scoped to this unit's own services) or the admin key.
    The bare Host header the caller passes is heartbeat-auth, not write-auth.

    Label-less (docker run-managed) containers have no compose file on disk —
    for those we upload an inspect-rendered snapshot to '<name>.rendered.yml'
    instead of silently leaving them out of the store entirely.
    """
    rendered = False
    host_path = f"/host{compose_dir}/docker-compose.yml" if compose_dir else None
    if not host_path or not os.path.exists(host_path):
        content = _render_compose_from_inspect(container_name)
        if content is None:
            return
        rendered = True
        store_key = f"{container_name}.rendered"
    else:
        store_key = container_name
        try:
            with open(host_path) as f:
                content = f.read()
        except Exception:
            return
    if LOKEY_UNIT_KEY:
        auth = _unit_key_headers()
    elif LOCATOR_ADMIN_KEY:
        auth = {"Host": LOCATOR_HOST_HEADER,
                "X-Locator-Admin-Key": LOCATOR_ADMIN_KEY}
    else:
        return
    try:
        requests.post(
            f"{LOCATOR_URL}/api/compose/{store_key}",
            data=content,
            headers={**auth, "Content-Type": "text/yaml"},
            timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
        )
    except Exception:
        pass


def detect_pressure_events(running, containers_summary, stats):
    """Diff this tick's memory readings against the previous tick and return
    event dicts for the locator's events table.

    - oom_kill: a container's inspect OOMKilled flag flipped on since last
      tick (the flag is sticky-until-restart, so transitions are the truth).
    - mem_spike: a container's mem_percent jumped >= MEM_SPIKE_DELTA pp into
      territory above MEM_SPIKE_FLOOR, or crossed MEM_SPIKE_CROSS from below.
    - node_mem_spike: node mem_percent jumped >= NODE_SPIKE_DELTA pp, or
      crossed NODE_CRIT_PCT.
    """
    global _prev_node_mem
    events = []
    now = datetime.now(timezone.utc).isoformat()
    ram = (containers_summary or {}).get("ram", {}) or {}
    cur_oom = set()
    for c in running or []:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        if not name:
            continue
        if c.get("oom_killed"):
            cur_oom.add(name)
            if name not in _prev_oom:
                events.append({
                    "type": "oom_kill", "service": name,
                    "finished_at": c.get("finished_at"),
                    "restart_count": c.get("restart_count"),
                    "at": now,
                })
        cur = (ram.get(name) or {}).get("mem_pct")
        prev = _prev_mem.get(name)
        if cur is not None:
            if prev is not None:
                delta = cur - prev
                if (delta >= MEM_SPIKE_DELTA and cur >= MEM_SPIKE_FLOOR) \
                        or (prev < MEM_SPIKE_CROSS <= cur):
                    events.append({
                        "type": "mem_spike", "service": name,
                        "from_pct": prev, "to_pct": cur,
                        "delta_pp": round(delta, 1), "at": now,
                    })
            _prev_mem[name] = cur
    _prev_oom.clear()
    _prev_oom.update(cur_oom)

    node_mem = stats.get("mem_percent")
    if node_mem is not None and _prev_node_mem is not None:
        delta = node_mem - _prev_node_mem
        if delta >= NODE_SPIKE_DELTA or (_prev_node_mem < NODE_CRIT_PCT <= node_mem):
            events.append({
                "type": "node_mem_spike",
                "from_pct": _prev_node_mem, "to_pct": node_mem,
                "delta_pp": round(delta, 1), "at": now,
            })
    if node_mem is not None:
        _prev_node_mem = node_mem
    # Drop state for containers that vanished so the tables do not grow
    # unboundedly on churn-heavy boxes.
    live = {c.get("name") for c in running or [] if isinstance(c, dict)}
    for dead in [n for n in _prev_mem if n not in live]:
        del _prev_mem[dead]
    return events


def push_node_metrics(stats, containers_summary=None, events=None):
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
        # Both readings travel with every heartbeat so a unit reporting an
        # implausible cpu_percent can be checked against the other one from the
        # locator side, without shelling into the box. cpu_metric says which of
        # the two cpu_percent is currently carrying.
        "cpu_spot_percent":    stats.get("cpu_spot_percent"),
        "cpu_loadavg_percent": stats.get("cpu_loadavg_percent"),
        "cpu_cores":           stats.get("cpu_cores"),
        "cpu_metric":          stats.get("cpu_metric"),
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
    # Battery lives on the node record too — the dashboard's device rows and
    # Tactical Grid cards read node fields, so laptops/tablets running lokey
    # get the same battery display the Android client gets via its metadata.
    # Sent only when present: a unit with no battery reports nothing rather
    # than erasing nothing with a null.
    if stats.get("battery_percent") is not None:
        metrics["battery_percent"] = stats["battery_percent"]
        metrics["charging"] = bool(stats.get("charging"))
        if stats.get("battery_secsleft") is not None:
            metrics["battery_secsleft"] = stats["battery_secsleft"]
    # The docker ps -a truth for this unit, stored on the NODE record rather
    # than the lokey service record: the per-container registration loop
    # below re-registers lokey itself and overwrites that record's metadata,
    # so the container list sent there never survived a heartbeat. locator's
    # wake path reads this to tell "stopped" from "does not exist" — a wake
    # queued for a deleted container fails on repeat until the entry rots.
    if containers_summary:
        metrics["containers"] = containers_summary
    # Pressure events ride the same PATCH so a locator restart between ticks
    # cannot lose them (they are regenerated only when transitions recur).
    if events:
        metrics["events"] = events
    # Addresses. These are what let locator reach — or even just PROBE — this
    # node, and until now the node record got almost none of them:
    #
    #   * no local IP was sent here AT ALL. lokey computes one (get_private_ip)
    #     and puts it in the /register metadata, so it landed on the SERVICE
    #     record and never on the node — unit3's 10.68.117.30 sat in
    #     lokey-client@unit3.metadata.private_ip while unit3's node record had
    #     no address of any kind. locator's handler has always read data["ip"];
    #     nothing was ever sending it.
    #   * tailscale_ip is sent only when detection succeeds, and it fails on the
    #     macOS native install (unit3 is on the tailnet at 100.78.95.13 and
    #     reported None), so that node was left completely unaddressable and
    #     therefore unprobeable.
    #
    # Recomputed per heartbeat rather than reusing the module-level _private_ip,
    # which is resolved once at startup and goes stale the moment DHCP, a new
    # interface or a network change moves the address.
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
            json=metrics, headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
        )
        if resp.status_code < 300:
            return
    except Exception:
        pass

    # PATCH unsupported or failed — GET current node, merge, POST back
    try:
        existing = {}
        r = requests.get(f"{LOCATOR_URL}/nodes", headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False)
        if r.status_code == 200:
            existing = r.json().get(UNIT_NAME, {})
        merged = {**existing, **metrics}
        requests.post(
            f"{LOCATOR_URL}/nodes",
            json={UNIT_NAME: merged}, headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
        )
    except Exception as e:
        print(f"[{UNIT_NAME}] Failed to push node metrics: {e}")

# Heartbeat acknowledgment. Every /register heartbeat carries a sequence
# number; locator echoes it back in `ack`. Only an echo of THIS tick's seq
# counts as delivered - a timeout, a non-200, a proxy/wake page, or an ack
# for a different seq is a miss, and check_locator_failover() starts a
# locator here after LOCATOR_MISS_THRESHOLD misses in a row.
HEARTBEAT_ACK_TIMEOUT = float(os.getenv("HEARTBEAT_ACK_TIMEOUT", "30"))
_hb_seq = 0
_hb_acked = False
_hb_ack_unit = None
# The last full heartbeat payload, re-sent by the pulse thread. The main tick
# also registers every container one by one against a loaded locator, and was
# measured at ~8 minutes per loop on unit4 - far too slow to notice a dead
# locator. The pulse keeps an acknowledged heartbeat going every
# HEARTBEAT_PULSE_S no matter how long the main tick takes.
_hb_payload = None
_hb_lock = threading.Lock()
# Separate from _hb_lock: starting a standby can take minutes, and holding
# the seq lock that long would stall every heartbeat meanwhile.
_failover_lock = threading.Lock()
HEARTBEAT_PULSE_S = int(os.getenv("HEARTBEAT_PULSE_S", "60"))


def _next_seq():
    global _hb_seq
    with _hb_lock:
        _hb_seq += 1
        return _hb_seq


def _heartbeat_pulse_loop():
    """Re-send the cached lokey heartbeat every HEARTBEAT_PULSE_S, check the
    ack, and feed the result to the failover counter."""
    while True:
        time.sleep(HEARTBEAT_PULSE_S)
        if _hb_payload is None:
            continue
        seq = _next_seq()
        acked = False
        try:
            resp = requests.post(
                f"{LOCATOR_URL}/register", json={**_hb_payload, "seq": seq},
                headers={"Host": LOCATOR_HOST_HEADER}, timeout=HEARTBEAT_ACK_TIMEOUT,
                allow_redirects=True, verify=False,
            )
            acked = _heartbeat_acked(resp, seq)
        except Exception:
            pass
        if not acked:
            print(f"[{UNIT_NAME}] pulse: NO ACK for #{seq}")
        _note_heartbeat(acked)


def _heartbeat_acked(resp, seq):
    """True when resp is locator acknowledging heartbeat `seq`."""
    global _hb_ack_unit
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except ValueError:
        return False
    ack = body.get("ack") if isinstance(body, dict) else None
    if isinstance(ack, dict):
        if ack.get("seq") == seq:
            _hb_ack_unit = ack.get("unit")
            return True
        return False
    # Locator builds from before the ack field still answer "registered";
    # accept that so a mixed fleet doesn't fail over on a version gap.
    return isinstance(body, dict) and body.get("result") == "registered"


MESH_SSH_KEY = os.path.expanduser("~/.ssh/lokey_mesh_ed25519")

def _mesh_pubkey():
    """Ed25519 keypair this unit publishes to the locator for lokey-mesh SSH."""
    try:
        os.makedirs(os.path.dirname(MESH_SSH_KEY), exist_ok=True)
        if not os.path.exists(MESH_SSH_KEY + ".pub"):
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "",
                            "-C", "lokey-mesh@" + UNIT_NAME, "-f", MESH_SSH_KEY],
                           check=True, capture_output=True)
        return open(MESH_SSH_KEY + ".pub").read().strip()
    except Exception as e:
        logging.warning("mesh key: %s", e)
        return None


def _sync_mesh_authorized():
    """Install every unit-published mesh pubkey into authorized_keys so any
    lokey host can ssh to any other."""
    try:
        r = req.get(LOCATOR_URL + "/api/registry", timeout=15, verify=False)
        keys = set()
        for svc in (r.json().get("services") or {}).values():
            k = ((svc.get("metadata") or {}).get("ssh_pubkey") or "").strip()
            if k:
                keys.add(k)
        ak = os.path.expanduser("~/.ssh/authorized_keys")
        have = set()
        if os.path.exists(ak):
            have = set(open(ak).read().splitlines())
        add = [k for k in keys if k not in have]
        if add:
            with open(ak, "a") as f:
                f.write("\n".join(add) + "\n")
            logging.info("mesh ssh: installed %d new pubkey(s)", len(add))
    except Exception as e:
        logging.debug("mesh auth sync: %s", e)


RING_ACK_FILE = os.path.expanduser("~/.config/lokey/ring_ack")

def _last_ring_ack():
    try:
        return open(RING_ACK_FILE).read().strip()
    except Exception:
        return ""

def _ring_wav(path):
    import math, struct, wave
    frames = b"".join(
        struct.pack("<h", int(12000 * math.sin(2 * math.pi * 880 * i / 22050)))
        for i in range(22050))
    with wave.open(path, "w") as w:
        w.setparams((1, 2, 22050, 22050))
        w.writeframes(frames)
    return path

def _ring_for(seconds):
    try:
        import shutil as _sh
        wav = _ring_wav("/tmp/lokey-ring.wav")
        cmds = ([["afplay", wav]] if sys.platform == "darwin" else
                [["paplay", wav], ["aplay", wav], ["ffplay", "-nodisp", "-autoexit", wav]])
        cmd = next((c for c in cmds if _sh.which(c[0])), None)
        end = time.time() + seconds
        while time.time() < end:
            if cmd:
                subprocess.run(cmd, capture_output=True, timeout=15)
            else:
                print("\a", end="", flush=True)
                time.sleep(1)
    except Exception as e:
        print(f"[{UNIT_NAME}] ring playback failed: {e}")

def _handle_ring_commands(resp):
    """Phones get ring via PhoneRinger.kt; desktop lokey handles the same
    locator 'commands' payload here."""
    try:
        cmds = (resp.json() or {}).get("commands") or []
    except Exception:
        return
    for c in cmds:
        if c.get("type") != "ring":
            continue
        try:
            os.makedirs(os.path.dirname(RING_ACK_FILE), exist_ok=True)
            open(RING_ACK_FILE, "w").write(str(c.get("id") or ""))
        except Exception:
            pass
        threading.Thread(target=_ring_for, args=(int(c.get("seconds") or 15),), daemon=True).start()
        print(f"[{UNIT_NAME}] RING received — playing {c.get('seconds')}s")


def register_stats():
    global _hb_acked, _hb_payload
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
    metadata["ssh_pubkey"] = _mesh_pubkey()
    metadata["ringable"] = True
    metadata["ring_ack"] = _last_ring_ack()

    # This was the literal string "container" on every unit, which is how boxes
    # with no Docker at all ended up filed under "docker containers" in the
    # registry: unit6 (Debian/Crostini, no docker binary) and unit3 (macOS, no
    # docker on the non-interactive PATH) both reported type=container with zero
    # containers running. locator cannot correct it either — /register defaults a
    # missing type to "container" and _infer_category() sends anything it does
    # not recognise to "docker containers", so the wrong answer was both the
    # value sent and the fallback.
    #
    # The fact was already in hand: /.dockerenv is how self_update() below
    # decides whether to rebuild or exec-restart, and _ensure_docker() has
    # already run by this point via get_docker_containers(). Report what is
    # actually true instead of asserting one of the two cases.
    _self_is_container = os.path.isfile("/.dockerenv")
    _host_has_docker   = _ensure_docker() is not None
    payload = {
        "name": "lokey",
        "host": UNIT_NAME,
        "type": "container" if _self_is_container else "native",
        # Sent explicitly because locator's _infer_category() maps type=native
        # to "devices", which is for phones and tablets — a native lokey daemon
        # on unit3 or unit6 is not a device, and landing there would just be a
        # different wrong answer. "native services" is the category unit3-native
        # already uses.
        "category": "docker containers" if _self_is_container else "native services",
        "status": "ONLINE",
        "seq": (seq := _next_seq()),
        "metadata": {
            **metadata,
            # Kept distinct from `type`: `type` is what THIS agent runs as,
            # while docker_available describes the HOST. A native lokey on a box
            # that does run Docker (the macOS/launchd install) is a real and
            # different case from a native lokey on a box with no Docker at all,
            # and collapsing them is what produced the wrong registry in the
            # first place.
            "docker_available": _host_has_docker,
            "runtime": "docker" if _self_is_container else "native",
        },
    }

    headers = {"Host": LOCATOR_HOST_HEADER}
    _hb_acked = False
    try:
        # 30s, not 5: a loaded-but-working locator has taken ~9s to answer
        # /register and stalls for tens of seconds on command_lock; a slow ack
        # must not read as a dead locator. Three 30s misses in a row is dead.
        resp = requests.post(
            f"{LOCATOR_URL}/register", json=payload,
            headers=headers, timeout=HEARTBEAT_ACK_TIMEOUT, allow_redirects=True, verify=False
        )
        _hb_acked = _heartbeat_acked(resp, seq)
        _handle_ring_commands(resp)
        ack_note = (f"ack #{seq} from {_hb_ack_unit or '?'}" if _hb_acked
                    else f"NO ACK for #{seq}")
        print(f"[{UNIT_NAME}] Heartbeat sent: {resp.status_code} {ack_note} | disk: {stats['disk_percent']}% | containers: {len(running)}")
    except Exception as e:
        print(f"[{UNIT_NAME}] Failed to reach locator at {LOCATOR_URL}: {e} (NO ACK for #{seq})")
    _hb_payload = {k: v for k, v in payload.items() if k != "seq"}

    _sync_mesh_authorized()
    push_node_metrics(stats, containers_summary,
                      detect_pressure_events(running, containers_summary, stats))

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
                "started_at": c.get("started_at") if isinstance(c, dict) else None,
                # Vitals + docker health verdict. 'health' is the field the
                # locator turns into verified/unverified/unhealthy — absent or
                # None here means the container runs no HEALTHCHECK and can
                # only ever show orange, never green.
                "health": c.get("health") if isinstance(c, dict) else None,
                "state": c.get("state") if isinstance(c, dict) else None,
                # Attached storage as mounted at runtime — feeds the locator's
                # migration preflight (does data travel or does the move refuse).
                "mounts": c.get("mounts", []) if isinstance(c, dict) else [],
                "cpu_percent": c.get("cpu_percent") if isinstance(c, dict) else None,
                "net_rx_bytes": c.get("net_rx_bytes") if isinstance(c, dict) else None,
                "net_tx_bytes": c.get("net_tx_bytes") if isinstance(c, dict) else None,
                "blk_read_bytes": c.get("blk_read_bytes") if isinstance(c, dict) else None,
                "blk_write_bytes": c.get("blk_write_bytes") if isinstance(c, dict) else None,
                "pids": c.get("pids") if isinstance(c, dict) else None,
                "exit_code": c.get("exit_code") if isinstance(c, dict) else None,
                "oom_killed": c.get("oom_killed") if isinstance(c, dict) else None,
                "restart_count": c.get("restart_count") if isinstance(c, dict) else None,
                "finished_at": c.get("finished_at") if isinstance(c, dict) else None,
            },
        }
        try:
            requests.post(
                f"{LOCATOR_URL}/register", json=container_payload,
                headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, allow_redirects=True, verify=False
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
                    headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, allow_redirects=True, verify=False
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
    host = _host_dir_for_create(COMPOSE_STACKS_DIR)
    if os.path.isdir(os.path.join(host, ".git")):
        pull = _git(host, "pull", "--ff-only")
        if pull.returncode != 0:
            print(f"[{UNIT_NAME}] ⚠️  stacks pull failed: {pull.stderr.strip()[:140]}")
        return host

    os.makedirs(os.path.dirname(host), exist_ok=True)
    # Credential via _git()'s helper, never spliced into the URL: a clone
    # records its URL as origin, so the old splice left the token in plaintext
    # in .git/config on every unit that ever cloned the stacks repo.
    clone = _git(os.path.dirname(host), "clone", COMPOSE_STACKS_REMOTE, host, timeout=180)
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
    if not _ensure_docker():
        return None
    try:
        c = _ensure_docker().containers.get(container_name)
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


def _resolve_under_host(path, root=HOST_PREFIX or "/host"):
    """Resolve `path` inside the host mount, re-anchoring ABSOLUTE symlinks.

    os.path.isdir("/host/home/swoopg111") follows that symlink to its absolute
    target "/mnt/omv_storage/swoopg111", which is then interpreted against the
    CONTAINER root, where it does not exist -- the real data is at
    "/host/mnt/omv_storage/...". On unit4, whose home IS such a symlink, that
    made every compose-dir lookup fail: migrations bailed before the stop and
    repo-sync logged "root not found (/home/swoopg111/projects)". Walk the path
    a component at a time and re-anchor each absolute link to the mount root.

    Non-existent tail components are simply appended, so this is also correct
    for a directory that has not been created yet.
    """
    cur = root
    for part in [x for x in path.split("/") if x and x != "."]:
        cur = os.path.join(cur, part)
        for _ in range(16):  # guard against symlink loops
            if not os.path.islink(cur):
                break
            target = os.readlink(cur)
            cur = (os.path.join(root, target.lstrip("/")) if os.path.isabs(target)
                   else os.path.normpath(os.path.join(os.path.dirname(cur), target)))
    return cur


def _host_dir(project_dir):
    """Return the host-side path for a path that may be container-internal."""
    if HOST_PREFIX:
        resolved = _resolve_under_host(project_dir)
        if os.path.isdir(resolved):
            return resolved
    candidate = f"/host{project_dir}"
    return candidate if os.path.isdir(candidate) else project_dir


def _unhost(path):
    """Strip the /host bind-mount prefix — inside `chroot /host` it is wrong."""
    if isinstance(path, str) and path.startswith("/host/"):
        return path[len("/host"):]
    return path


def _docker_argv(args, cwd=None):
    """argv that runs a docker CLI command in the right place for this install mode.

    This container ships the docker SDK but no `docker` binary, so a bare
    subprocess.run(["docker", ...]) raises FileNotFoundError here. In
    _execute_git_pull_and_start that exception escaped the migration loop
    entirely: the task stayed IN_PROGRESS forever, the agent restarted, and the
    locator still reported the migration DONE with the container running nowhere.

    Docker-mode lokey bind-mounts the host root at /host, so re-enter it with
    chroot and use the host's own docker CLI — the same approach _exec_argv
    already takes for exec tasks. Native installs pass straight through.
    Path arguments are un-prefixed too, since /host/... does not resolve inside
    the chroot.
    """
    cmd = " ".join(shlex.quote(_unhost(a)) for a in args)
    if cwd:
        cmd = f"cd {shlex.quote(_unhost(cwd))} && {cmd}"
    if os.path.isdir("/host/proc"):
        return ["chroot", "/host", "/bin/su", "-", EXEC_HOST_USER, "-c", cmd]
    return ["/bin/bash", "-c", cmd]


def _host_dir_for_create(project_dir):
    """Host-side path for a directory that may not exist yet.

    _host_dir() decides by probing os.path.isdir("/host" + path) and falls back
    to the bare path when it is missing. That is right for reading a checkout
    that is already there, and exactly wrong for cloning onto a unit that has
    never hosted the service: /host<path> does not exist *yet*, so the clone
    lands inside the lokey container instead of on the host, the host path is
    never created, and the compose that follows fails against a missing
    directory. Decide on install mode — the same signal _exec_argv uses — not
    on whether the target happens to exist.
    """
    # Symlink-aware for the same reason as _host_dir(): on a unit whose home is
    # an absolute symlink to another filesystem, "/host<path>" is unusable and
    # os.makedirs() on it fails against the missing parent.
    if os.path.isdir("/host/proc"):
        return _resolve_under_host(project_dir)
    return project_dir


def _daemon_path(path):
    """Strip the /host mount prefix — the path as the DOCKER DAEMON sees it.

    _host_dir gives a path this process can read; the daemon cannot use it.
    Compose resolves a relative bind mount (./fluent-bit.conf) against the
    compose file's directory and hands the result straight to the daemon, so
    running compose against /host/home/... would create mounts pointing at a
    literal /host/home/... on the host. File operations use _host_dir; anything
    the daemon will interpret uses this.
    """
    return path[len("/host"):] if path.startswith("/host/") else path


def _compose_on_host(workdir, args="up -d", timeout=300):
    """Run `docker compose` on the host, from workdir.

    There is no docker CLI inside the lokey image — it drives Docker through
    the Python SDK over the mounted socket — so shelling out to "docker" here
    dies with FileNotFoundError. Re-enter the host namespace the same way
    exec does, which also puts compose in the filesystem the daemon shares.
    """
    script = f"cd {shlex.quote(_daemon_path(workdir))} && docker compose {args}"
    # Secrets scrub_env_secrets() moved out of .env come back here. They are
    # handed to compose through a 0600 file on /dev/shm (RAM, never disk) that
    # the script sources and deletes before compose runs, so a value is neither
    # written to disk nor visible in `ps` argv. If they cannot be resolved the
    # compose run is refused: starting with blank credentials is worse than not
    # starting.
    try:
        secret_env = _bao_secrets_for(workdir)
    except Exception as e:
        return subprocess.CompletedProcess(
            ["docker", "compose", args], 78, "", f"x-bao-secrets unresolved: {e}")
    if not secret_env:
        return subprocess.run(_exec_argv(script), capture_output=True, text=True, timeout=timeout)
    shm_host = "/host/dev/shm" if os.path.isdir("/host/proc") else "/dev/shm"
    name = f"lokey-env-{os.getpid()}-{int(time.time() * 1000)}"
    host_file = os.path.join(shm_host, name)
    try:
        fd = os.open(host_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            for k, v in secret_env.items():
                fh.write(f"export {k}={shlex.quote(v)}\n")
        owner = os.stat(_host_dir(workdir))
        os.chown(host_file, owner.st_uid, owner.st_gid)
        run_file = f"/dev/shm/{name}"
        script = (f". {run_file}; rm -f {run_file}; "
                  f"cd {shlex.quote(_daemon_path(workdir))} && docker compose {args}")
        return subprocess.run(_exec_argv(script), capture_output=True, text=True, timeout=timeout)
    finally:
        try:
            os.remove(host_file)
        except FileNotFoundError:
            pass


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
    commit = _git(host, "commit", "-m", f"[lokey-migrate] {name} leaving {UNIT_NAME} for {to_node}")
    is_dedup = mig.get("dedup", False)
    if commit.returncode != 0:
        combined = ((commit.stdout or "") + (commit.stderr or "")).lower()
        # "nothing to commit" is fine and idempotent: the stack file is already
        # published unchanged from an earlier run. Any OTHER failure means the
        # target will find no compose file, so stopping here would strand the
        # service on no node at all.
        if "nothing to commit" not in combined and "no changes added" not in combined:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: git commit failed, NOT stopping "
                  f"{name}: {((commit.stderr or commit.stdout or '').strip())[:200]}")
            return False, {}
    push = _git(host, "push")
    if push.returncode != 0 and "fetch first" in (push.stderr or ""):
        # Another unit pushed between our pull and our push (common when the
        # balancer evacuates several nodes at once). Rebase onto it and retry
        # once rather than failing the whole migration.
        _git(host, "pull", "--rebase")
        push = _git(host, "push")
    if push.returncode != 0:
        msg = push.stderr.strip()[:200]
        if is_dedup:
            # Dedup goal is just to stop the duplicate — git push is best-effort
            print(f"[{UNIT_NAME}] ⚠️  {mig_id}: git push failed (dedup, continuing to stop): {msg}")
        else:
            print(f"[{UNIT_NAME}] ❌ {mig_id}: git push failed: {msg}")
            return False, {}

    # The whole point of the push is that the TARGET can start this container.
    # Confirm the stack file exists in the published commit rather than
    # inferring it from exit codes — that inference is what made this fail
    # silently for weeks.
    published = _git(host, "cat-file", "-e", f"HEAD:{name}.yml")
    if published.returncode != 0 and not is_dedup:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: {name}.yml is not in the pushed commit "
              f"— NOT stopping {name} (target would have nothing to start)")
        return False, {}

    print(f"[{UNIT_NAME}] ✅ {mig_id}: git push done, {name}.yml published — stopping {name}")

    # Capture a remote the target can clone. Prefer the PROJECT's own remote —
    # a stack file with `build: .` is useless without the real sources — and
    # fall back to the stacks remote only when the project dir is untracked.
    git_remote = ""
    for repo_dir in (_host_dir(project_dir), host):
        remote_result = subprocess.run(
            ["git", "-C", repo_dir, "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10,
        )
        if remote_result.returncode == 0 and remote_result.stdout.strip():
            git_remote = remote_result.stdout.strip()
            break

    # Stop container, then compose down on the service's OWN file — running it
    # in the stacks repo hits whatever default file is there (usually none),
    # leaving the stopped container behind and its image pinned in place.
    try:
        if _ensure_docker():
            c = _ensure_docker().containers.get(name)
            c.stop(timeout=30)
        subprocess.run(
            _docker_argv(["docker", "compose", "-f", local_compose, "down"]),
            capture_output=True, timeout=60)
    except Exception as e:
        print(f"[{UNIT_NAME}] ⚠️  {mig_id}: stop warning: {e}")

    # Drop the departed service's images — `compose down` removes the container
    # but leaves every image behind, so a disk-pressure migration freed no disk
    # on the source and the box still marched toward full. rmi is best-effort:
    # an image shared with a service that stayed is in use and refuses, which is
    # exactly the skip we want. Volumes are deliberately untouched — the data
    # survives in case the service migrates back.
    try:
        imgs = subprocess.run(
            _docker_argv(["docker", "compose", "-f", local_compose,
                          "config", "--images"]),
            capture_output=True, text=True, timeout=60)
        if imgs.returncode == 0:
            for img in imgs.stdout.split():
                rmi = subprocess.run(
                    _docker_argv(["docker", "rmi", img]),
                    capture_output=True, text=True, timeout=120)
                if rmi.returncode == 0:
                    print(f"[{UNIT_NAME}] 🧹 {mig_id}: freed image {img}")
    except Exception as e:
        print(f"[{UNIT_NAME}] ⚠️  {mig_id}: image cleanup warning: {e}")

    print(f"[{UNIT_NAME}] ✅ {mig_id}: git_push_and_stop complete — {name} handed off to {to_node}")
    return True, {"project_dir": project_dir, "git_remote": git_remote}


MIGRATION_PULL_TIMEOUT = int(os.getenv("MIGRATION_PULL_TIMEOUT", "1800"))


def _wait_running(name, timeout=45):
    """True once `name` is actually up on this node.

    Nothing used to confirm the target ever started the container: compose
    returning 0 was treated as success, so any target-side failure became a
    silent outage with the locator still reporting DONE.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _ensure_docker():
            try:
                if _ensure_docker().containers.get(name).status == "running":
                    return True
            except Exception:
                pass
        else:
            ps = subprocess.run(
                _docker_argv(["docker", "ps", "--format", "{{.Names}}"]),
                capture_output=True, text=True, timeout=30,
            )
            if name in ps.stdout.split():
                return True
        time.sleep(3)
    return False


def _stack_config(stack_file, name):
    """Resolved compose spec as JSON, else (None, reason).

    Doubles as the prerequisite check: compose refuses to resolve a stack whose
    env_file is absent, so its own error text is the actionable reason this node
    cannot host the service yet — far better than dying inside `up`.
    """
    cfg = subprocess.run(
        _docker_argv(["docker", "compose", "-f", stack_file, "-p", name,
                      "config", "--format", "json"]),
        capture_output=True, text=True, timeout=90,
    )
    if cfg.returncode != 0:
        err = cfg.stderr.strip()
        return None, (err.splitlines()[-1][:220] if err else "compose config failed")
    try:
        return json.loads(cfg.stdout), ""
    except Exception as e:
        return None, f"unparseable compose config: {e}"


def _ensure_external_networks(spec, mig_id):
    """Create every external network the stack expects but this node lacks.

    Migration was git-pull + `compose up` and nothing else, so moving a service
    to a node that had never hosted it died on whatever that node happened to be
    missing. External networks are the common case and are safe to create here.
    """
    declared = (spec or {}).get("networks", {}) or {}
    wanted = [(n or {}).get("name") or k for k, n in declared.items() if (n or {}).get("external")]
    if not wanted:
        return []

    ls = subprocess.run(
        _docker_argv(["docker", "network", "ls", "--format", "{{.Name}}"]),
        capture_output=True, text=True, timeout=30,
    )
    existing = set(ls.stdout.split())
    created = []
    for net in wanted:
        if net in existing:
            continue
        mk = subprocess.run(
            _docker_argv(["docker", "network", "create", net]),
            capture_output=True, text=True, timeout=60,
        )
        if mk.returncode == 0:
            created.append(net)
            print(f"[{UNIT_NAME}] 🌐 {mig_id}: created missing external network '{net}'")
        else:
            print(f"[{UNIT_NAME}] ⚠️  {mig_id}: could not create network '{net}': "
                  f"{mk.stderr.strip()[:120]}")
    return created


def _execute_git_pull_and_start(mig):
    """
    1. git pull the container's compose project.
    2. provision what this node is missing (external networks, images).
    3. docker compose up -d, then verify the container is actually running.
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
            spec, why = _stack_config(stack_file, name)
            if spec is None:
                print(f"[{UNIT_NAME}] ❌ {mig_id}: {name} cannot run here yet — {why}")
                return False, {"blocked_on": why}

            _ensure_external_networks(spec, mig_id)

            # Pull before up: a large image (agent-zero is 12.4GB) outruns the
            # compose-up timeout, which would report a false failure for what is
            # only a slow download.
            pull = subprocess.run(
                _docker_argv(["docker", "compose", "-f", stack_file, "-p", name, "pull"]),
                capture_output=True, text=True, timeout=MIGRATION_PULL_TIMEOUT,
            )
            if pull.returncode != 0:
                print(f"[{UNIT_NAME}] ⚠️  {mig_id}: image pull said: {pull.stderr.strip()[:160]}")

            up = subprocess.run(
                _docker_argv(["docker", "compose", "-f", stack_file, "-p", name, "up", "-d"]),
                capture_output=True, text=True, timeout=300,
            )
            if up.returncode != 0:
                # A stack file that carries `build: .` has no Dockerfile in the
                # stacks repo — forge-relay hit exactly this. Fall through to
                # the project-dir clone path rather than failing the migration.
                print(f"[{UNIT_NAME}] ⚠️  {mig_id}: stack-file compose up failed "
                      f"({up.stderr.strip()[:160]}) — falling back to project dir")
            elif not _wait_running(name):
                print(f"[{UNIT_NAME}] ⚠️  {mig_id}: stack-file up returned 0 but "
                      f"'{name}' is not running — falling back to project dir")
            else:
                print(f"[{UNIT_NAME}] ✅ {mig_id}: started {name} from compose-stacks")
                return True, {"project_dir": COMPOSE_STACKS_DIR, "stack_file": stack_file}
        else:
            print(f"[{UNIT_NAME}] ⚠️  {mig_id}: {name} not in compose-stacks — falling back to project dir")

    if not project_dir:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: no project_dir provided")
        return False, {}

    host = _host_dir(project_dir)
    # Container git has no ~/.gitconfig, so even with a credentials file
    # mounted at /root/.git-credentials it never consults the store —
    # inject the helper via env. Harmless when the file isn't mounted.
    git_env = {**os.environ,
               "GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes",
               "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": "credential.helper",
               "GIT_CONFIG_VALUE_0": "store"}

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
        _docker_argv(["docker", "compose", "up", "-d"], cwd=host),
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ {mig_id}: compose up failed: {result.stderr.strip()[:200]}")
        return False, {}

    print(f"[{UNIT_NAME}] ✅ {mig_id}: git_pull_and_start complete — {name} running")
    return True, {}


BAO_REF_PREFIX = "bao://"
_REDACT_MAP_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*:\s?(?P<value>.*)$")
_REDACT_LIST_RE = re.compile(
    r"^\s*-\s+(?P<key>[A-Za-z_][A-Za-z0-9_.]*)=(?P<value>.*)$")


def _resolve_bao_refs(env_map, service):
    """Trade any bao:// reference in env_map for its value, via the locator.

    The locator is the only holder of the OpenBao token — no unit carries one,
    so a compromised unit cannot read the fleet's secrets, only the ones its
    own services already needed. Deploy commands arrive over the
    unauthenticated /api/commands/pending, which is exactly why they carry the
    reference and not the value.

    Raises on any failure. The caller MUST abort the deploy: a half-resolved
    map seeds a blank into .env, and _merge_env_file never overwrites an
    existing key, so that blank would then be permanent.
    """
    refs = [v for v in env_map.values()
            if isinstance(v, str) and v.startswith(BAO_REF_PREFIX)]
    if not refs:
        return dict(env_map)
    if not LOCATOR_ADMIN_KEY:
        raise RuntimeError(
            f"'{service}' needs OpenBao values but LOCATOR_ADMIN_KEY is not set "
            f"on {UNIT_NAME} — cannot resolve {len(refs)} reference(s)")
    try:
        from bao_env import fetch as _bao_fetch
        table = _bao_fetch(refs, LOCATOR_URL, LOCATOR_HOST_HEADER, LOCATOR_ADMIN_KEY)
    except Exception as e:
        raise RuntimeError(f"resolving secrets for '{service}': {e}")
    out = {}
    for key, value in env_map.items():
        if isinstance(value, str) and value.startswith(BAO_REF_PREFIX):
            got = table.get(value)
            if not got:
                raise RuntimeError(
                    f"locator returned no value for {value} (key {key})")
            out[key] = got
        else:
            out[key] = value
    return out


def _merge_env_file(host, env_map):
    """Ensure .env in a project checkout contains env_map, without clobbering.

    Compose .env files are gitignored almost everywhere, so a fresh clone on a
    unit that has never hosted the service arrives without one and every
    ${VAR} in its compose file resolves to empty. The locator supplies the
    per-unit values (see locator.yml 'env:'); this only materializes them.

    Existing keys are left ALONE — unit8's .env already holds the live-logger
    database URL and credentials that locator has no copy of, so a deploy that
    rewrote the file would take the stack down.
    """
    path = os.path.join(host, ".env")
    existing, order = {}, []
    if os.path.isfile(path):
        with open(path) as fh:
            for line in fh:
                line = line.rstrip("\n")
                order.append(line)
                if "=" in line and not line.lstrip().startswith("#"):
                    existing[line.split("=", 1)[0].strip()] = line
    added = [f"{k}={v}" for k, v in sorted(env_map.items())
             if k and k not in existing]
    if not added:
        return []
    with open(path, "w") as fh:
        fh.write("\n".join([l for l in order if l.strip()] + added) + "\n")
    return [a.split("=", 1)[0] for a in added]


def _execute_redact_env(cmd, result):
    """Strip plaintext credentials out of this unit's real docker-compose.yml.

    Queued by the locator's secret sweeper AFTER it has stored the values in
    OpenBao and read them back. The command carries only key names and bao://
    references — never a value — because /api/commands/pending is served
    without auth.

    Each flagged line becomes KEY: ${KEY}, and the value comes back at compose
    time from the .env the locator fills on the next deploy. The container is
    NOT restarted here: rewriting a file is reversible, bouncing a database
    mid-write is not. The unit reports back and a human (or a deploy) decides
    when it comes up on the new wiring.
    """
    name = cmd.get("container") or ""
    keys = set(cmd.get("keys") or [])
    refs = {k: v for k, v in (cmd.get("refs") or {}).items()
            if isinstance(k, str) and isinstance(v, str) and v.startswith("bao://")}
    if not keys and not refs:
        result["stderr"] = "redact_env: no keys given"
        return result

    compose_dir = _get_compose_dir(name)
    if not compose_dir:
        result["stderr"] = f"redact_env: no compose project dir known for '{name}'"
        print(f"[{UNIT_NAME}] 🔐 redact '{name}' skipped — {result['stderr']}")
        return result
    # _host_dir_for_create already decides on install mode (docker lokey sees
    # the host at /host, a native install does not).
    path = os.path.join(_host_dir_for_create(compose_dir), "docker-compose.yml")
    if not os.path.isfile(path):
        result["stderr"] = f"redact_env: {path} not found"
        return result

    with open(path, errors="replace") as fh:
        text = fh.read()

    lines = text.splitlines()
    changed, already = [], []
    for i, line in enumerate(lines):
        m = _REDACT_MAP_RE.match(line)
        form = "map"
        if not m:
            m = _REDACT_LIST_RE.match(line)
            form = "list"
        if not m:
            continue
        key = m.group("key")
        if key not in keys:
            continue
        value = m.group("value").strip()
        if value.startswith("${") or value.startswith("$") or not value:
            already.append(key)
            continue
        indent = line[:len(line) - len(line.lstrip())]
        lines[i] = (f"{indent}- {key}=${{{key}}}" if form == "list"
                    else f"{indent}{key}: ${{{key}}}")
        changed.append(key)

    # The command's refs must land in this file's x-bao-secrets block — without
    # them ${KEY} has nothing to resolve from on the next deploy. This runs even
    # when no line needed rewriting: an earlier redact may have left the file
    # indirect but reference-less, which reads as 'already' above.
    new_text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    if refs:
        new_text = unitsecrets.write_bao_block(new_text, refs)

    if new_text == text:
        result["success"] = True
        result["stdout"] = (f"nothing to redact in {path}"
                            + (f" (already indirect: {sorted(set(already))})" if already else ""))
        print(f"[{UNIT_NAME}] 🔐 redact '{name}': {result['stdout']}")
        return result

    backup = f"{path}.bak-preredact-{int(time.time())}"
    try:
        with open(backup, "w") as fh:
            fh.write(text)
        with open(path, "w") as fh:
            fh.write(new_text)
    except OSError as e:
        result["stderr"] = f"redact_env: {e}"
        print(f"[{UNIT_NAME}] 🔐 redact '{name}' failed: {e}")
        return result

    refs_written = sorted(set(refs) - set(unitsecrets.read_bao_block(text)))
    result["success"] = True
    result["exit_code"] = 0
    result["stdout"] = (f"redacted {sorted(set(changed))} from {path}; "
                        f"backup {backup}; recorded {refs_written or 'existing'} "
                        f"x-bao-secrets refs; values resolve via the locator on "
                        f"the next deploy")
    print(f"[{UNIT_NAME}] 🔐 redacted {sorted(set(changed))} from {path} "
          f"(backup {os.path.basename(backup)})")
    return result


def _execute_deploy(cmd, result):
    """Bring a service up on this unit, cloning its project if it isn't here.

    Queued by the locator from locator.yml's 'units:' placement, so the target
    is routinely a unit that has never hosted the service. That is precisely
    the case _execute_git_pull_and_start cannot handle: its clone branch sits
    behind a `not isdir(host)` test that has already returned on the same
    condition, making the branch unreachable.

    Same order of preference as the migration path — the shared compose-stacks
    repo first, then the service's own project checkout.
    """
    name        = cmd.get("container") or ""
    project_dir = cmd.get("project_dir") or ""
    git_remote  = cmd.get("git_remote") or ""
    env_map     = cmd.get("env") or {}

    if not name:
        result["stderr"] = "deploy: no container name given"
        return result

    # An explicit project_dir wins over compose-stacks. The stacks repo holds
    # ONE yaml per service, which cannot carry a stack that needs sibling files
    # — fluent-bit bind-mounts four configs plus a per-unit inputs file, and
    # from compose-stacks those relative paths resolve to a directory holding
    # only the yaml, so every deploy failed with exit 1. locator.yml naming a
    # project_dir is the more specific instruction; honour it first.
    stacks_host = None if project_dir else _ensure_stacks_repo()
    if stacks_host:
        stack_file = _stack_file(stacks_host, name)
        if stack_file:
            up = _compose_on_host(
                os.path.dirname(stack_file),
                f"-f {shlex.quote(_daemon_path(stack_file))} -p {shlex.quote(name)} up -d",
            )
            result["stdout"]    = up.stdout[-EXEC_OUTPUT_CAP:]
            result["stderr"]    = up.stderr[-EXEC_OUTPUT_CAP:]
            result["exit_code"] = up.returncode
            result["success"]   = up.returncode == 0
            mark = "✅" if result["success"] else "❌"
            print(f"[{UNIT_NAME}] {mark} deploy '{name}' from compose-stacks → exit {up.returncode}")
            return result

    if not project_dir:
        result["stderr"] = f"deploy: '{name}' not in compose-stacks and no project_dir supplied"
        print(f"[{UNIT_NAME}] ❌ {result['stderr']}")
        return result

    host = _host_dir_for_create(project_dir)
    if not os.path.isdir(host):
        if not git_remote:
            result["stderr"] = f"deploy: {host} missing and no git_remote supplied"
            print(f"[{UNIT_NAME}] ❌ {result['stderr']}")
            return result
        os.makedirs(os.path.dirname(host), exist_ok=True)
        # Credential via _git()'s helper; see _ensure_stacks_repo for why the
        # token is never spliced into the URL.
        clone = _git(os.path.dirname(host), "clone", git_remote, host, timeout=180)
        if clone.returncode != 0:
            result["stderr"]    = f"git clone failed: {clone.stderr.strip()[:300]}"
            result["exit_code"] = clone.returncode
            print(f"[{UNIT_NAME}] ❌ deploy '{name}': {result['stderr']}")
            return result
        print(f"[{UNIT_NAME}] 📥 deploy '{name}': cloned → {host}")
    else:
        pull = _git(host, "pull", "--ff-only")
        if pull.returncode != 0:
            print(f"[{UNIT_NAME}] ⚠️  deploy '{name}': pull failed, using checkout as-is "
                  f"({pull.stderr.strip()[:140]})")

    env_map = {**env_map,
               "UNIT_NAME":  env_map.get("UNIT_NAME")  or UNIT_NAME,
               "TAILNET_IP": env_map.get("TAILNET_IP") or get_tailscale_ip() or ""}
    try:
        env_map = _resolve_bao_refs(env_map, name)
    except Exception as e:
        result["stderr"]    = f"secrets unresolved: {e}"
        result["exit_code"] = 78          # EX_CONFIG
        result["success"]   = False
        print(f"[{UNIT_NAME}] 🔒 deploy '{name}' aborted — {e}")
        return result
    added = _merge_env_file(host, env_map)
    if added:
        print(f"[{UNIT_NAME}] 📝 deploy '{name}': seeded .env keys {added}")

    up = _compose_on_host(host)
    result["stdout"]    = up.stdout[-EXEC_OUTPUT_CAP:]
    result["stderr"]    = up.stderr[-EXEC_OUTPUT_CAP:]
    result["exit_code"] = up.returncode
    result["success"]   = up.returncode == 0
    mark = "✅" if result["success"] else "❌"
    print(f"[{UNIT_NAME}] {mark} deploy '{name}' ({host}) → exit {up.returncode}")
    return result


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
    # Container git has no ~/.gitconfig, so even with a credentials file
    # mounted at /root/.git-credentials it never consults the store —
    # inject the helper via env. Harmless when the file isn't mounted.
    git_env = {**os.environ,
               "GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no -o BatchMode=yes",
               "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": "credential.helper",
               "GIT_CONFIG_VALUE_0": "store"}

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
        if _ensure_docker():
            c = _ensure_docker().containers.get(name)
            c.stop(timeout=30)
            subprocess.run(
                _docker_argv(["docker", "compose", "down"], cwd=host_project),
                capture_output=True, timeout=60,
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


def _claimed_by_us(mig_id, headers):
    """True when the locator recorded `mig_id` as claimed by this unit —
    covers the claim-ack-lost case where we own the task but never saw the 200."""
    # /api/migrations is clearance-gated — send the admin key when we have it.
    h = dict(headers)
    if LOCATOR_ADMIN_KEY:
        h["X-Locator-Admin-Key"] = LOCATOR_ADMIN_KEY
    try:
        r = requests.get(f"{LOCATOR_URL}/api/migrations", headers=h,
                         timeout=LOCATOR_HTTP_TIMEOUT, verify=False)
        if r.status_code != 200:
            return False
        for m in r.json():
            if m.get("id") == mig_id:
                return (m.get("status") == "IN_PROGRESS"
                        and m.get("claimed_by") == UNIT_NAME)
    except Exception:
        pass
    return False


def check_pending_migrations():
    """Poll the locator for migrations queued from this node and execute them."""
    headers = {"Host": LOCATOR_HOST_HEADER}
    try:
        resp = requests.get(
            f"{LOCATOR_URL}/api/migrations/pending",
            params={"unit": UNIT_NAME},
            headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
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
                headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
            )
            if claim_resp.status_code != 200:
                continue
        except Exception:
            # The claim can land server-side while the response is lost to a
            # timeout — a slow locator (unit7 under load) does exactly this.
            # Skipping here strands the task IN_PROGRESS with no executor, so
            # check the record: if it says WE claimed it, executing is our job.
            if not _claimed_by_us(mig_id, headers):
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
                headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
            )
        except Exception:
            pass

# ── LOCATOR FAILOVER ─────────────────────────────────────────────────────────

_locator_miss_streak = 0
_local_locator_started = False


def _local_locator_running():
    """Mechanism-agnostic: true whether the standby is a docker container or
    a bare native process, since either way it ends up serving :5000."""
    # localhost inside the lokey container is the container itself, not the
    # host, so probe the address the standby actually publishes on.
    bind = os.getenv("LOCATOR_STANDBY_BIND", "")
    probe = bind if bind and bind != "0.0.0.0" else (_tailscale_ip_cached or "localhost")
    try:
        r = requests.get(f"http://{probe}:{LOCATOR_STANDBY_PORT}/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _write_locator_env(host):
    """Materialise .env for the standby compose. UNIT_NAME is required by
    docker-compose.standby.yml (`?Set UNIT_NAME in .env`), so without this a
    fresh clone cannot `compose up` at all. DATABASE_URL lets the standby keep
    serving the canonical registry instead of starting empty; take it from
    LOCATOR_DATABASE_URL (falling back to DATABASE_URL) so no credentials are
    written into this file."""
    db_url = os.getenv("LOCATOR_DATABASE_URL") or os.getenv("DATABASE_URL", "")
    defaults = [
        ("UNIT_NAME", UNIT_NAME),
        ("DATABASE_URL", db_url),
        ("LOCATOR_ADMIN_KEY", os.getenv('LOCATOR_ADMIN_KEY', '')),
        ("LOCATOR_CANONICAL_URL", LOCATOR_URL),
        ("LOCATOR_STANDBY_PORT", str(LOCATOR_STANDBY_PORT)),
        # Tailnet IP to publish on; empty = compose default (all interfaces).
        ("LOCATOR_STANDBY_BIND", os.getenv('LOCATOR_STANDBY_BIND', '') or '0.0.0.0'),
    ]
    # Merge, never replace: on a unit that already runs locator this file is
    # the primary's own config (grid key, canonical URL, ...). Rewriting it
    # from scratch on failover silently dropped those, and the next restart
    # came up without them. Existing non-empty values win; only missing or
    # blank keys are filled in.
    path = os.path.join(host, ".env")
    lines, have = [], {}
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        pass
    for i, line in enumerate(lines):
        k, sep, v = line.partition("=")
        if sep and not line.lstrip().startswith("#"):
            have[k.strip()] = (i, v)
    for k, v in defaults:
        if k not in have:
            lines.append(f"{k}={v}")
        elif not have[k][1].strip() and v:
            lines[have[k][0]] = f"{k}={v}"
    try:
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        print(f"[{UNIT_NAME}] ⚠️  failover: could not write locator .env: {e}")


def _ensure_locator_checkout():
    """Clone or refresh this unit's locator checkout; return its host path or
    None. The standby compose ships in the repo, so a unit that never hosted
    locator can still come up — previously a missing project dir returned
    early, which made failover impossible on exactly the units it exists for."""
    target = LOCATOR_COMPOSE_DIR or LOCATOR_STANDBY_DIR
    host = _host_dir_for_create(target)
    if os.path.isdir(os.path.join(host, ".git")):
        pull = _git(host, "pull", "--ff-only")
        if pull.returncode != 0:
            print(f"[{UNIT_NAME}] ⚠️  failover: locator pull failed, using existing checkout: "
                  f"{pull.stderr.strip()[:140]}")
        _write_locator_env(host)
        return host

    if not shutil.which("git") and not os.path.isdir("/host/proc"):
        print(f"[{UNIT_NAME}] ❌ failover: no locator checkout and no git to clone one")
        return None
    os.makedirs(os.path.dirname(host), exist_ok=True)
    clone = _git(os.path.dirname(host), "clone", LOCATOR_REPO_URL, host, timeout=300)
    if clone.returncode != 0:
        print(f"[{UNIT_NAME}] ❌ failover: locator clone failed: {clone.stderr.strip()[:160]}")
        return None
    print(f"[{UNIT_NAME}] 📥 failover: cloned locator → {host}")
    _write_locator_env(host)
    return host


def _start_local_locator_docker(host_dir):
    # A locator container already on this unit (the primary on unit7, or a
    # standby from an earlier failover) is restarted, never replaced: the
    # standby compose shares container_name "locator" and would recreate the
    # primary with standby settings. restart also un-wedges a hung process.
    state = subprocess.run(
        _docker_argv(["docker", "inspect", "-f", "{{.State.Status}}", "locator"]),
        capture_output=True, text=True, timeout=60,
    )
    if state.returncode == 0 and state.stdout.strip():
        verb = "start" if state.stdout.strip() in ("exited", "created") else "restart"
        r = subprocess.run(_docker_argv(["docker", verb, "locator"]),
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            print(f"[{UNIT_NAME}] ❌ failover: docker {verb} locator failed: {r.stderr.strip()[:200]}")
            return False
        print(f"[{UNIT_NAME}] 🔁 failover: existing locator container {verb}ed")
        return True
    result = subprocess.run(
        _docker_argv(["docker", "compose", "-f", "docker-compose.standby.yml", "up", "-d"],
                     cwd=host_dir),
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        # the cause is at the end of compose output (the head is just "Building")
        print(f"[{UNIT_NAME}] ❌ failover: compose up failed: {result.stderr.strip()[-600:]}")
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
        # A fresh clone has no deps installed — gunicorn/flask/requests come
        # from requirements.txt. Best-effort install into this interpreter
        # before starting; if it fails the gunicorn spawn error below reports it.
        if not importlib.util.find_spec("gunicorn"):
            pip = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--user", "-r", "requirements.txt"],
                cwd=host_dir, capture_output=True, text=True, timeout=600,
            )
            if pip.returncode != 0:
                print(f"[{UNIT_NAME}] ⚠️  failover: pip install said: {pip.stderr.strip()[:160]}")
        log_file = open(log_path, "a")
        env = dict(os.environ, UNIT_NAME=UNIT_NAME, LOCATOR_IS_PRIMARY="false",
                   SELF_CONTAINER_NAME="locator",
                   LOCATOR_CANONICAL_URL=LOCATOR_URL)
        subprocess.Popen(
            [sys.executable, "-m", "gunicorn",
             "--bind", f"0.0.0.0:{LOCATOR_STANDBY_PORT}", "--workers", "1", "--threads", "8",
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
    host_dir = _ensure_locator_checkout()
    if not host_dir:
        return
    print(f"[{UNIT_NAME}] 🆘 {LOCATOR_MISS_THRESHOLD}+ heartbeats unacknowledged — starting locator here")
    has_docker = bool(shutil.which("docker")) or os.path.isdir("/host/proc")
    started = (_start_local_locator_docker(host_dir) if has_docker
               else _start_local_locator_native(host_dir))
    if not started:
        return
    _local_locator_started = True
    print(f"[{UNIT_NAME}] ✅ failover: local locator started on {UNIT_NAME}")


def check_locator_failover():
    """Main-tick entry point: counts this tick's heartbeat."""
    _note_heartbeat(_hb_acked)


def _note_heartbeat(acked):
    """Count consecutive unacknowledged heartbeats (main tick and pulse
    thread alike); after LOCATOR_MISS_THRESHOLD in a row, start a locator on
    this unit. Resets (and re-arms) on the next acknowledged heartbeat."""
    global _locator_miss_streak, _local_locator_started
    # LOCATOR_COMPOSE_DIR is no longer required: a missing checkout is cloned
    # from LOCATOR_REPO_URL into LOCATOR_STANDBY_DIR at failover time.
    if not LOCATOR_FAILOVER_ENABLED:
        return

    # The question is whether locator acknowledged our heartbeat, not whether
    # some /health endpoint answers.
    with _failover_lock:
        _count_heartbeat(acked)


def _count_heartbeat(acked):
    global _locator_miss_streak, _local_locator_started
    if acked:
        if _locator_miss_streak:
            print(f"[{UNIT_NAME}] heartbeat acked again after {_locator_miss_streak} miss(es)")
        _locator_miss_streak = 0
        _local_locator_started = False
        return

    _locator_miss_streak += 1
    print(f"[{UNIT_NAME}] heartbeat not acknowledged #{_locator_miss_streak}/{LOCATOR_MISS_THRESHOLD}")
    if _locator_miss_streak < LOCATOR_MISS_THRESHOLD:
        return
    if _local_locator_started and not _local_locator_running():
        # The standby we started has since died — crash, or the primary's
        # election evicted it before the primary itself died. The latch only
        # cleared on a canonical /health 200, which can never arrive while the
        # canonical DNS points at dead infrastructure — so the standby stayed
        # down permanently while the streak climbed (seen at miss #133).
        # Re-arm so failover can fire again; the running-check inside
        # _start_local_locator keeps a live standby from being disturbed.
        print(f"[{UNIT_NAME}] ⚠️  failover: standby locator is down — re-arming")
        _local_locator_started = False
    if not _local_locator_started:
        _start_local_locator()


# ── CERT EXPIRY WATCHDOG ─────────────────────────────────────────────────────
# Traefik auto-renews ~30 days before expiry; this is the safety net that makes
# a silent renewal failure visible. Every CERT_CHECK_TICKS ticks, check the TLS
# cert of every hostname this unit routes (from container Traefik labels) and
# report days-to-expiry to the locator (/api/certs/report).

CERT_CHECK_TICKS = int(os.getenv("CERT_CHECK_TICKS", "360"))  # ~6h at 60s tick

# Fleet mTLS leaves live 168h, so they must be re-minted far more often than the
# public certs above are merely *watched*. Hourly is well inside the 3-day
# rotate-before window and costs one directory stat per tick when nothing is due.
MTLS_ROTATE_TICKS = int(os.getenv("MTLS_ROTATE_TICKS", "60"))  # ~1h at 60s tick


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
    if not _ensure_docker():
        return
    hosts = set()
    try:
        # Raw `docker ps` — Labels ride in the summary, and a containers.list()
        # costs one inspect per container.
        for c in _ensure_docker().api.containers():
            hosts.update(extract_traefik_hosts(c.get("Labels") or {}))
    except Exception as e:
        print(f"[{UNIT_NAME}] cert check: container scan failed: {e}")
        return
    # The fleet mTLS leaves are reported through this same call on purpose:
    # /api/certs/report REPLACES a unit's whole cert list, so two posters would
    # each erase the other's rows.
    mesh = []
    try:
        import rotate_mtls
        mesh = rotate_mtls.status()
    except Exception as e:
        print(f"[{UNIT_NAME}] mesh cert status failed: {e}")
    if not hosts and not mesh:
        return
    results = [_check_cert(h) for h in sorted(hosts)] + mesh
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
    # Added 2026-08-23, ahead of idle shutdown moving from opt-in to opt-out.
    # None of these has a wake-on-request path, so once stopped they stay
    # stopped until a human notices. Mirrors the locator's _PINNED_NAMES —
    # keep the two lists in step, since this one is the last word: the locator
    # decides, but the stop runs here.
    #   openbao    — the secrets broker every bao:// reference resolves
    #                through; stopping it breaks the next deploy on any unit.
    #   fluent-bit — the log shippers. A quiet shipper is the one you most need
    #                running, and unit8's being down 36h is why its containers
    #                were missing from the log filter lists entirely.
    #   keycloak / freeipa — identity. Stopping either locks people out of
    #                everything that authenticates against them.
    "openbao", "fluent-bit", "keycloak", "freeipa",
}


def _is_protected(container):
    """True if this container must never be stopped by automation.

    Substring match so compose-suffixed names stay covered too
    (the-beast-postgres-1, openvpn-client, pdns-db, ...)."""
    name = container.name.lower()
    if any(p in name for p in NEVER_STOP):
        return True
    return str(container.labels.get(PINNED_LABEL, "")).lower() in ("true", "1", "yes", "on")


def _fetch_idle_policy():
    """Container names this unit may idle-stop, as decided by locator.yml.

    Asks the locator rather than reading a docker label, because a label can
    only be changed by recreating the container while locator.yml is editable
    from the dashboard — the file is the fleet's stated source of truth.

    FAIL-SAFE: any error returns {}, which means only label-opted containers
    stay eligible. A locator that is down, slow or mid-rebuild can therefore
    never make a container newly stoppable — it can only fail to extend the
    list.
    """
    try:
        r = requests.get(
            f"{LOCATOR_URL}/api/idle/policy",
            params={"unit": UNIT_NAME},
            headers={"Host": LOCATOR_HOST_HEADER}, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
        )
        if r.status_code != 200:
            return {}
        return {str(k).lower(): (v or {}) for k, v in (r.json().get("containers") or {}).items()}
    except Exception:
        return {}


def report_idle_stats():
    """Report net-byte counters for idle-stop opt-in containers to the locator."""
    if not _ensure_docker():
        return
    entries = []
    policy = _fetch_idle_policy()
    try:
        # Reads the vitals sweep register_stats() already ran this tick —
        # rx/tx counters ride in it. The old path did its own containers.list
        # plus a stats() per watched container, a second serial pass of ~60
        # inspects plus ~4-6s per stats call on a loaded box.
        for rec in list(_last_running):
            name = rec.get("name") or ""
            name_l = name.lower()
            # locator.yml first, docker label second. Either opts a container
            # in; neither one being present means it is simply not watched, so
            # an undeclared, unlabelled container can never be stopped.
            pol = policy.get(name_l)
            if pol is None:
                pol = policy.get(re.sub(r"-\d+$", "", name_l))
            labels = rec.get("labels") or {}
            label_on = str(labels.get(IDLE_LABEL_ENABLE, "")).lower() in ("true", "1", "yes", "on")
            if pol is None and not label_on:
                continue
            if _is_protected(SimpleNamespace(name=name, labels=labels)):
                continue
            rx, tx = rec.get("net_rx_bytes"), rec.get("net_tx_bytes")
            if rx is None and tx is None:
                # Sweep-deadline straggler — no counters this tick.
                continue
            entries.append({
                "name": name,
                "net_bytes": (rx or 0) + (tx or 0),
                # Per-container label wins over the policy default so a
                # one-off override does not need a locator.yml edit.
                "timeout": labels.get(IDLE_LABEL_TIMEOUT, "") or (pol or {}).get("timeout", ""),
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
            headers={"Host": LOCATOR_HOST_HEADER}, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
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


# Disk-pressure safety net. The locator migrates registered services off a
# full disk, but that leaves the service's images behind and does nothing for
# pressure that was never a registered service (host logs, apt cache, stray
# files). Over DISK_CLEANUP_PERCENT this reclaims what is provably safe; over
# DISK_CRITICAL_PERCENT it also drops unused tagged images — a re-pull is
# cheap next to a dead box. Stopped containers are never pruned (idle-stop
# wake relies on `docker start`) and volumes are never touched (that's data).
DISK_CLEANUP_PERCENT  = float(os.getenv("DISK_CLEANUP_PERCENT", "85"))
DISK_CRITICAL_PERCENT = float(os.getenv("DISK_CRITICAL_PERCENT", "93"))
DISK_CLEANUP_INTERVAL = int(os.getenv("DISK_CLEANUP_INTERVAL", "600"))
DISK_LOG_CAP_MB       = int(os.getenv("DISK_LOG_CAP_MB", "200"))
DISK_LOG_KILL_MB      = int(os.getenv("DISK_LOG_KILL_MB", "1024"))
_last_disk_cleanup = 0.0


def _cap_container_logs(critical):
    """Container stdout logs are the one consumer nothing else reclaims — the
    json-file driver has no size cap unless the daemon is configured with one,
    so a single chatty container can write unbounded (a stray `tar ... >` to
    stdout once wrote 32 GB and filled this disk). Truncate any log over
    DISK_LOG_CAP_MB. At CRITICAL, also stop anonymous (non-compose) containers
    whose log exceeds DISK_LOG_KILL_MB — a dead box costs more than a stray
    `docker run`. Compose-managed services are never stopped: truncation alone
    bounds their bleed and the workload stays up."""
    docker_dir = "/host/var/lib/docker" if os.path.isdir("/host/proc") \
        else "/var/lib/docker"
    containers_dir = os.path.join(docker_dir, "containers")
    if not os.path.isdir(containers_dir):
        return
    try:
        logs = subprocess.run(
            ["find", containers_dir, "-name", "*-json.log",
             "-size", f"+{DISK_LOG_CAP_MB}M"],
            capture_output=True, text=True, timeout=60)
        paths = [p for p in logs.stdout.splitlines() if p.strip()]
    except Exception:
        return
    for path in paths:
        cid = os.path.basename(os.path.dirname(path))
        size_mb = 0
        try:
            size_mb = os.path.getsize(path) / 1e6
            with open(path, "w"):
                pass  # truncate in place — dockerd holds the fd open
            print(f"[{UNIT_NAME}] 🧹 truncated container log "
                  f"{cid[:12]} ({size_mb:.0f} MB)")
        except Exception as e:
            print(f"[{UNIT_NAME}] 🧹 log truncate {cid[:12]} failed: {e}")
        if critical and size_mb >= DISK_LOG_KILL_MB:
            try:
                insp = subprocess.run(
                    _docker_argv(["docker", "inspect", "--format",
                                  "{{index .Config.Labels \"com.docker.compose.project\"}}",
                                  cid]),
                    capture_output=True, text=True, timeout=30)
                if not insp.stdout.strip():
                    subprocess.run(_docker_argv(["docker", "stop", "-t", "10", cid]),
                                   capture_output=True, timeout=60)
                    print(f"[{UNIT_NAME}] 🧹 CRITICAL: stopped anonymous "
                          f"container {cid[:12]} (log {size_mb:.0f} MB)")
            except Exception as e:
                print(f"[{UNIT_NAME}] 🧹 stop {cid[:12]} failed: {e}")


def _root_exec_argv(script):
    """Like _exec_argv but keeps root instead of dropping to EXEC_HOST_USER —
    journalctl --vacuum and apt clean refuse to run as the owning user."""
    if os.path.isdir("/host/proc"):
        return ["chroot", "/host", "/bin/bash", "-c", script]
    return ["/bin/bash", "-c", script]


def disk_janitor():
    """Reclaim disk before a full disk crashes the unit. See the constants above."""
    global _last_disk_cleanup
    try:
        du = shutil.disk_usage("/host") if os.path.isdir("/host/proc") \
            else shutil.disk_usage("/")
        pct = du.used / du.total * 100
    except Exception:
        return
    if pct < DISK_CLEANUP_PERCENT:
        return
    critical = pct >= DISK_CRITICAL_PERCENT
    # The log cap is a cheap `find`+truncate — run it every tick once over
    # threshold so a fast writer can't fill the disk between janitor passes.
    # The heavy prunes below stay on the cleanup interval.
    _cap_container_logs(critical)
    now = time.time()
    if now - _last_disk_cleanup < DISK_CLEANUP_INTERVAL:
        return
    _last_disk_cleanup = now

    print(f"[{UNIT_NAME}] 🧹 disk at {pct:.1f}%"
          f"{' (CRITICAL)' if critical else ''} — running cleanup")

    steps = [
        "docker image prune -f",      # dangling images only
        "docker builder prune -f",    # build cache
        # network prune deliberately NOT here: it reclaims negligible disk but
        # breaks the docker-start wake path this janitor is supposed to leave
        # alone (see the note above) — a stopped-not-removed container (any
        # restart:unless-stopped service between a manual stop and its next
        # `up`) has its network orphaned and reaped out from under it, so
        # `docker start` then fails with "network ... not found" until someone
        # force-recreates it. Cost unit7's gitlab-runner ~12 days of silently
        # stuck CI pipelines before anyone noticed. 2026-09-28.
    ]
    if critical:
        # Untagged-by-a-container images too — departed services' leftovers and
        # staged pulls. They re-pull on demand; a full disk crashes everything.
        steps.append("docker image prune -af")
    steps += [
        "journalctl --vacuum-size=200M",
        "apt-get clean",
    ]
    for step in steps:
        argv = _root_exec_argv(step) if not step.startswith("docker") \
            else _docker_argv(step.split())
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=300)
            out = (r.stdout or r.stderr or "").strip().splitlines()
            print(f"[{UNIT_NAME}] 🧹 {step}: {out[-1][:160] if out else 'ok'}")
        except Exception as e:
            print(f"[{UNIT_NAME}] 🧹 {step} failed: {e}")

    try:
        du2 = shutil.disk_usage("/host") if os.path.isdir("/host/proc") \
            else shutil.disk_usage("/")
        print(f"[{UNIT_NAME}] 🧹 disk now {du2.used / du2.total * 100:.1f}% "
              f"(freed {(du.used - du2.used) / 1e9:.2f} GB)")
    except Exception:
        pass


# How long a start must hold 'running' before it counts as actually up, and
# the ceiling on the whole verification window. A container that exits a
# second after `docker start` used to report success — the locator then
# believed a dead service was alive and never relocated it.
START_VERIFY_STABLE_S = float(os.environ.get("START_VERIFY_STABLE_S", "3"))
START_VERIFY_DEADLINE_S = float(os.environ.get("START_VERIFY_DEADLINE_S", "20"))


def _verify_started(client, name):
    """Confirm `name` stays running after a start. Returns (ok, detail).

    'docker start' returning means only that the daemon accepted the request —
    a crash-looping or instantly-exiting container still reports success and
    the locator marks the service up. Poll inspect for START_VERIFY_DEADLINE_S:
    running for START_VERIFY_STABLE_S straight (or reported healthy) is a pass;
    exited/dead is an immediate fail; a restart counter that keeps climbing
    means a crash-loop, which gets its restart policy pinned and the container
    stopped so it quits burning the box — then fails, so the locator's
    relocation escalation can try another unit."""
    deadline = time.time() + START_VERIFY_DEADLINE_S
    stable_since = None
    last_state = {}
    while time.time() < deadline:
        try:
            c = client.containers.get(name)
            st = c.attrs.get("State") or {}
            last_state = st
            status = st.get("Status")
            if status == "running":
                health = (st.get("Health") or {}).get("Status")
                if health == "healthy":
                    return True, ""
                if stable_since is None:
                    stable_since = time.time()
                elif time.time() - stable_since >= START_VERIFY_STABLE_S:
                    return True, ""
            else:
                stable_since = None
                if status in ("exited", "dead"):
                    tail = ""
                    try:
                        tail = (c.logs(tail=8) or b"").decode(errors="replace")
                    except Exception:
                        pass
                    return False, (f"exited {st.get('ExitCode')} after start — "
                                   f"{tail[-300:]}".strip())
        except Exception as e:
            return False, f"post-start inspect failed: {e}"
        time.sleep(1.5)

    # Deadline hit without a stable running state — almost always a crash
    # loop. Pin the restart policy so docker stops resurrecting it, stop it,
    # and fail so the locator relocates rather than leaving it to spin.
    tail = ""
    try:
        c = client.containers.get(name)
        tail = (c.logs(tail=8) or b"").decode(errors="replace")
        try:
            c.update(restart_policy={"Name": "no"})
        except Exception:
            pass
        c.stop(timeout=10)
    except Exception:
        pass
    return False, (f"never stayed up within {START_VERIFY_DEADLINE_S:.0f}s "
                   f"(status {last_state.get('Status')}, "
                   f"restarts {last_state.get('RestartCount')}) — stopped to "
                   f"break the loop. {tail[-300:]}".strip())


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

    if action == "deploy":
        return _execute_deploy(cmd, result)

    if action == "redact_env":
        return _execute_redact_env(cmd, result)

    name = cmd.get("container")
    if not _ensure_docker() or not name:
        return result
    try:
        c = _ensure_docker().containers.get(name)
    except Exception as e:
        if action != "start":
            print(f"[{UNIT_NAME}] command {action} '{name}' failed: {e}")
            result["stderr"] = str(e)
            return result
        # Container object is gone — a completed migration's compose down
        # removes it, and this is most likely a rollback/wake start. Every
        # migrated service's compose lives in the stacks repo on every unit,
        # so relaunch from there instead of failing.
        stacks = _ensure_stacks_repo()
        f = _stack_file(stacks, name) if stacks else None
        if not f:
            result["stderr"] = str(e)
            return result
        up = subprocess.run(
            _docker_argv(["docker", "compose", "-f", f, "up", "-d"]),
            capture_output=True, text=True, timeout=300)
        if up.returncode != 0:
            result["stderr"] = (up.stderr or up.stdout or "")[-300:]
            print(f"[{UNIT_NAME}] start '{name}' relaunch failed: {result['stderr'][:120]}")
            return result
        ok, why = _verify_started(_ensure_docker(), name)
        if not ok:
            print(f"[{UNIT_NAME}] 🔴 '{name}' relaunched but did not stay up: {why[:160]}")
            result["stderr"] = why
            return result
        print(f"[{UNIT_NAME}] 🟢 relaunched '{name}' from stacks (locator command)")
        result["success"] = True
        return result
    try:
        if action == "stop":
            if _is_protected(c):
                print(f"[{UNIT_NAME}] 🛡️  refusing to stop protected container '{name}'")
                return result
            c.stop(timeout=30)
            # 'restart: always' ignores a deliberate stop across a docker
            # daemon restart — the container resurrects itself without the
            # locator's say-so and silently eats whatever the stop freed.
            # Locator is the only start authority, so pin the policy down.
            # Best-effort: a failed update leaves the stop in place either
            # way, just without the daemon-restart guarantee.
            try:
                rp = (c.attrs.get("HostConfig") or {}).get("RestartPolicy") or {}
                if rp.get("Name") == "always":
                    c.update(restart_policy={"Name": "unless-stopped"})
                    print(f"[{UNIT_NAME}]    '{name}' restart policy always→unless-stopped")
            except Exception as e:
                print(f"[{UNIT_NAME}]    '{name}' restart-policy check skipped: {e}")
            print(f"[{UNIT_NAME}] 💤 stopped '{name}' (locator command)")
            src = str(cmd.get("source") or "")
            if src.startswith("power:"):
                _drain_waiters[name] = src.split(":", 1)[1]
            result["success"] = True
            return result
        if action == "start":
            try:
                c.start()
            except Exception as e:
                # The object exists but refuses to start — dead network ref,
                # a bind source that vanished since the container was created
                # (docker auto-creates a DIRECTORY in its place, which then
                # fails the mount), or a spec gone stale across migrations.
                # The stacks repo is the declared spec and this is the same
                # recovery the container-gone branch above already does: rm
                # the husk, compose up. No stack file → report the original
                # error unchanged.
                stacks = _ensure_stacks_repo()
                f = _stack_file(stacks, name) if stacks else None
                if not f:
                    raise
                print(f"[{UNIT_NAME}] start '{name}' failed ({e}); relaunching from stacks")
                subprocess.run(
                    _docker_argv(["docker", "rm", "-f", name]),
                    capture_output=True, text=True, timeout=60)
                up = subprocess.run(
                    _docker_argv(["docker", "compose", "-f", f, "up", "-d"]),
                    capture_output=True, text=True, timeout=300)
                if up.returncode != 0:
                    result["stderr"] = (up.stderr or up.stdout or "")[-300:]
                    print(f"[{UNIT_NAME}] start '{name}' relaunch failed: {result['stderr'][:120]}")
                    return result
                ok, why = _verify_started(_ensure_docker(), name)
                if not ok:
                    print(f"[{UNIT_NAME}] 🔴 '{name}' relaunched but did not stay up: {why[:160]}")
                    result["stderr"] = why
                    return result
                print(f"[{UNIT_NAME}] 🟢 relaunched '{name}' from stacks after failed start")
                result["success"] = True
                return result
            ok, why = _verify_started(_ensure_docker(), name)
            if not ok:
                print(f"[{UNIT_NAME}] 🔴 '{name}' started but did not stay up: {why[:160]}")
                result["stderr"] = why
                return result
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
            headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
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
                headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
            )
        except Exception:
            pass


# ── DRAIN-RELEASE WAITERS ────────────────────────────────────────────────────
# A power drain stops containers via commands sourced "power:<drain_id>". The
# locator queues a start on /api/power/restore, but that queue is in-memory —
# a locator restart between drain and restore loses it, and the container
# stays down until a human notices. Waiters close that pull-side gap: after a
# power stop we record the drain, then poll /api/power/drain/<id> each tick and
# start the container once the drain is restored (the locator's approval — it
# only sets restored after the LLM job is done with the freed room). A 404
# means the locator forgot the drain entirely, so nothing holds the container
# anymore — start it then too. docker start on a running container is a no-op,
# so racing the restore's queued start is harmless.
_drain_waiters = {}   # container name -> drain_id


def check_drain_releases():
    """Start containers whose power drain has been released by the locator."""
    if not _drain_waiters or not _ensure_docker():
        return
    headers = {"Host": LOCATOR_HOST_HEADER}
    for name, drain_id in list(_drain_waiters.items()):
        try:
            r = requests.get(f"{LOCATOR_URL}/api/power/drain/{drain_id}",
                             headers=headers, timeout=LOCATOR_HTTP_TIMEOUT, verify=False)
        except Exception:
            continue
        if r.status_code == 404:
            approved = True
        elif r.status_code == 200:
            approved = bool(r.json().get("restored"))
        else:
            continue
        if not approved:
            continue
        try:
            c = _ensure_docker().containers.get(name)
            if c.status != "running":
                c.start()
                print(f"[{UNIT_NAME}] 🟢 drain {drain_id} released — "
                      f"started '{name}' (waiter)")
        except Exception as e:
            print(f"[{UNIT_NAME}] drain-released start '{name}' failed: {e}")
            continue
        _drain_waiters.pop(name, None)


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
    """Keep the DDNS_ZONES A-records pointed at the edge, on IP change.

    Called only from the writable-pdns node (see the main loop). The record
    value is the HAProxy edge address (EDGE_PUBLIC_IP), not this node's own
    public IP — they are different units. Falls back to the discovered public
    IP only when EDGE_PUBLIC_IP is unset.
    """
    if not DDNS_ENABLED:
        return

    current_ip = os.getenv("EDGE_PUBLIC_IP", "").strip() or _get_public_ip()
    if not current_ip:
        print(f"[{UNIT_NAME}] DDNS: could not determine edge/public IP")
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
            headers={"Host": LOCATOR_HOST_HEADER}, timeout=LOCATOR_HTTP_TIMEOUT, verify=False,
        )
    except Exception:
        pass


_git_token_cache = None


GIT_AUTHOR_NAME = os.getenv("GIT_AUTHOR_NAME", "lokey")
GIT_AUTHOR_EMAIL = os.getenv("GIT_AUTHOR_EMAIL", f"lokey@{UNIT_NAME}.fleet.blacksheep")


GIT_TOKEN_REF = "bao://secret/compose/git-token#GIT_TOKEN"
_git_token_seeded = False


def _seed_git_token(token):
    """Publish a working git token under one canonical ref so a bare install
    (plain-dir checkout, no .git-credentials — unit2 shipped this way) can
    pull it back through the admin-keyed resolve. First unit with a token
    seeds it; everyone else benefits."""
    global _git_token_seeded
    if _git_token_seeded or not LOCATOR_ADMIN_KEY:
        return
    try:
        r = requests.post(f"{LOCATOR_URL}/api/secrets/ingest", headers={
            "Host": LOCATOR_HOST_HEADER,
            "X-Locator-Admin-Key": LOCATOR_ADMIN_KEY},
            json={"unit": UNIT_NAME, "source": "git-token",
                  "path": "lokey canonical", "content": f"GIT_TOKEN={token}\n"},
            timeout=60, verify=False)
        if r.status_code == 200 and r.json().get("verified") is True:
            _git_token_seeded = True
            print(f"[{UNIT_NAME}] git-token: seeded {GIT_TOKEN_REF}", flush=True)
    except Exception:
        pass


def _canonical_git_token():
    """Resolve the seeded GIT_TOKEN_REF through the locator. Retried each
    call — no negative caching, a locator restart must not freeze this."""
    if not LOCATOR_ADMIN_KEY:
        return ""
    try:
        from bao_env import fetch as _bao_fetch
        return _bao_fetch([GIT_TOKEN_REF], LOCATOR_URL, LOCATOR_HOST_HEADER,
                          LOCATOR_ADMIN_KEY).get(GIT_TOKEN_REF, "")
    except Exception:
        return ""


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
        if _git_token_cache:
            _seed_git_token(_git_token_cache)
    if not _git_token_cache:
        # scrub_git_tokens() has moved the token out of the URL and left a
        # bao:// reference in lokey's own .git/config instead. Not cached
        # when empty, so a locator that was down at startup is retried.
        # This has to sit OUTSIDE the `is None` init block: once the cache is
        # set to "" that branch never runs again, and without this every pull
        # after the first fell back to bare git — "could not read Username"
        # on every credential-less remote, forever.
        tok = _repo_token(_host_dir(LOKEY_PROJECT_DIR))
        if tok:
            _seed_git_token(tok)
            return tok
        return _canonical_git_token() or ""
    return _git_token_cache


_tokenref_cache = {}   # checkout path -> (config mtime, ref)
_tokenval_cache = {}   # bao:// ref -> value, process memory only


def _repo_token(cwd):
    """The token a scrubbed checkout authenticates with, or None.

    scrub_git_tokens() leaves `lokey.tokenref = bao://...` in the checkout's
    .git/config — a reference, not a secret — and the value is fetched through
    the locator on first use and kept only in this process's memory.
    """
    cfg = os.path.join(cwd, ".git", "config")
    try:
        mtime = os.stat(cfg).st_mtime
    except OSError:
        return None
    cached = _tokenref_cache.get(cwd)
    if cached and cached[0] == mtime:
        ref = cached[1]
    else:
        try:
            ref = subprocess.run(
                ["git", "-c", "safe.directory=*", "-C", cwd, "config", "--local", "--get", "lokey.tokenref"],
                capture_output=True, text=True, timeout=15,
            ).stdout.strip()
        except Exception:
            ref = ""
        _tokenref_cache[cwd] = (mtime, ref)
    if not ref:
        return None
    if ref not in _tokenval_cache:
        try:
            if "/units/" in ref and LOKEY_UNIT_KEY:
                _tokenval_cache[ref] = _unit_resolve([ref])[ref]
            else:
                from bao_env import fetch as _bao_fetch
                _tokenval_cache[ref] = _bao_fetch([ref], LOCATOR_URL, LOCATOR_HOST_HEADER, LOCATOR_ADMIN_KEY)[ref]
        except Exception as e:
            print(f"[{UNIT_NAME}] git-token: could not resolve {ref}: {e}")
            return None
    return _tokenval_cache[ref]


def _git(cwd, *args, timeout=90, token=None):
    """Run git against a host checkout.

    safe.directory is forced because the container runs as root while the
    checkouts are owned by the login user; without it git refuses with
    "dubious ownership" and every sync would fail.
    """
    # Identity is forced for the same reason safe.directory is: this container
    # has no git config and no HOME with one, so `git commit` died with
    # "Committer identity unknown" on every call. Nothing checked the commit's
    # exit status, and `git push` with nothing staged exits 0 — so a migration
    # reported success, stopped the container, and published nothing. The
    # service then existed on no node at all.
    cmd = ["git", "-c", "safe.directory=*",
           "-c", f"user.name={GIT_AUTHOR_NAME}",
           "-c", f"user.email={GIT_AUTHOR_EMAIL}"]
    env = dict(os.environ)
    # Never prompt: an ssh remote with an unknown host key would otherwise hang
    # until the timeout. self_update() set this itself before it moved here.
    env.setdefault("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=no -o BatchMode=yes")
    token = token or _repo_token(cwd) or _git_token()
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
        # HOME=/tmp stranded pulls on checkouts whose only credentials live in
        # the owner's ~/.git-credentials — /tmp has no gitconfig, so the store
        # helper never ran and credential-less remotes failed with "could not
        # read Username". Point HOME at the owner's real home (via /host) so
        # the same store+config the login shell uses applies. /tmp stays the
        # fallback for checkouts outside a recognizable home.
        env["HOME"] = _owner_home(cwd) or "/tmp"

    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env=env, preexec_fn=preexec)


def _owner_home(cwd):
    """The checkout owner's home dir as this process can open it, else None.

    cwd is already /host-mapped when it gets here, so /host/home/<user>/…
    yields /host/home/<user>; a native (non-container) lokey gets the bare
    /home/<user>. Root-owned checkouts never reach this — _drop_to_owner
    returns None for uid 0 — so only real users' homes are produced.
    """
    m = re.match(r"^(?:/host)?(/home/[^/]+|/Users/[^/]+)(?:/|$)", cwd)
    return f"{HOST_PREFIX}{m.group(1)}" if m else None


_PASSWD_SYNCED = set()

def _ensure_passwd_entry(uid, home):
    """Give a host uid a container /etc/passwd entry if it lacks one.

    git over SSH runs `ssh` after the uid drop; ssh calls getpwuid() and dies
    with "No user exists for uid N" when the host owner has no counterpart in
    the container's passwd — and even with an entry, ssh expands ~/.ssh/config
    from the PASSWD home (not $HOME), so the entry must carry the owner's real
    home or ssh misses the host aliases/keys the login user relies on.
    The entry is container-local and only names the uid.
    """
    if uid in _PASSWD_SYNCED:
        return
    home = home or "/nonexistent"
    try:
        ent = pwd.getpwuid(uid)
        if not home.startswith("/nonexistent") and ent.pw_dir.startswith("/nonexistent"):
            _rewrite_passwd_home(uid, home)
        _PASSWD_SYNCED.add(uid)
        return
    except (KeyError, ImportError):
        pass
    try:
        with open("/etc/passwd", "a") as fh:
            fh.write(f"lokey-sync{uid}:x:{uid}:{uid}:checkout owner:{home}:/usr/sbin/nologin\n")
        _PASSWD_SYNCED.add(uid)
    except OSError:
        pass


def _rewrite_passwd_home(uid, home):
    """Point an existing synthetic entry's home at the owner's real dir."""
    try:
        lines = open("/etc/passwd").read().splitlines()
        with open("/etc/passwd", "w") as fh:
            for line in lines:
                parts = line.split(":")
                if len(parts) >= 6 and parts[0].startswith("lokey-sync") and parts[2] == str(uid):
                    parts[5] = home
                    line = ":".join(parts)
                fh.write(line + "\n")
    except OSError:
        pass


def _ensure_home_link(home):
    """Symlink /home/<user> -> /host/home/<user> when the bare path is absent.

    The owner's ssh config may name keys by absolute path
    (IdentityFile /home/me/.ssh/gitlab). Inside the container the real dir is
    /host/home/me — one symlink makes both spellings resolve.
    """
    m = re.match(r"^/host((?:/home|/Users)/[^/]+)$", home or "")
    if not m:
        return
    bare = m.group(1)
    try:
        if not os.path.exists(bare):
            os.symlink(home, bare)
    except OSError:
        pass


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
    home = _owner_home(path)
    _ensure_passwd_entry(uid, home)
    _ensure_home_link(home)

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


# ── GIT TOKEN SCRUB ──────────────────────────────────────────────────────────
# A token typed into a remote URL (https://oauth2:glpat-...@gitlab.com/...) sits
# in plaintext in .git/config, prints with every `git remote -v`, and is copied
# into anything that backs the checkout up. Found that way on 2026-09-15 in two
# checkouts on two units — one of them written by lokey's own stacks clone.
#
# Order is the whole point, same as the locator's quarantine: the token goes
# into OpenBao FIRST (the ingest route reads it back before answering), the URL
# is rewritten second, and the checkout must still reach its remote third —
# otherwise the old URL is put back. A unit that cannot vault (no admin key, or
# the locator is down) only reports: removing a token with no copy left to
# authenticate with would silently break every pull on that checkout.

SCRUB_GIT_TOKENS_ENABLED = os.getenv("SCRUB_GIT_TOKENS_ENABLED", "true").lower() == "true"
SCRUB_GIT_TOKENS_DRY_RUN = os.getenv("SCRUB_GIT_TOKENS_DRY_RUN", "false").lower() == "true"
SCRUB_GIT_TOKENS_ROOTS   = [p.strip() for p in os.getenv(
    "SCRUB_GIT_TOKENS_ROOTS",
    f"/home/{REMOTE_USER}/projects,/home/{REMOTE_USER}/server,/home/{REMOTE_USER}/stacks,/root/projects",
).split(",") if p.strip()]
SCRUB_GIT_TOKENS_DEPTH   = int(os.getenv("SCRUB_GIT_TOKENS_DEPTH", "4"))

_URL_USERINFO_RE = re.compile(r"^(?P<scheme>https?://)(?P<userinfo>[^@/\s]+)@(?P<rest>.+)$", re.I)
_BARE_TOKEN_RE   = re.compile(r"^(glpat-|gldt-|glrt-|ghp_|gho_|ghs_|ghu_|github_pat_)")
_SCRUB_PRUNE     = {"node_modules", ".git", "__pycache__", "venv", ".venv", "site-packages", "vendor"}
_scrub_reported  = set()   # (path, key) already announced as report-only


def _split_url_token(url):
    """(clean_url, host, secret) when `url` carries a credential, else None."""
    m = _URL_USERINFO_RE.match(url or "")
    if not m:
        return None
    user, sep, secret = m.group("userinfo").partition(":")
    if not sep:
        # https://TOKEN@host — only a token-shaped username counts, so a plain
        # https://alice@host (no secret at all) is left alone.
        if not (_BARE_TOKEN_RE.match(user) or len(user) >= 20):
            return None
        secret = user
    if not secret:
        return None
    rest = m.group("rest")
    host = rest.split("/", 1)[0].split(":", 1)[0].lower()
    return m.group("scheme") + rest, host, secret


def _find_checkouts():
    seen = set()
    for root in SCRUB_GIT_TOKENS_ROOTS:
        base = _host_dir(root)
        if not os.path.isdir(base):
            continue
        base_depth = base.rstrip("/").count("/")
        for dirpath, dirnames, _files in os.walk(base):
            if os.path.isdir(os.path.join(dirpath, ".git")):
                real = os.path.realpath(dirpath)
                if real not in seen:
                    seen.add(real)
                    yield dirpath
            if dirpath.count("/") - base_depth >= SCRUB_GIT_TOKENS_DEPTH:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames
                               if d not in _SCRUB_PRUNE and ".bak" not in d]


def _vault_git_token(host, secret, path):
    """File one token in OpenBao via the locator. Returns its bao:// ref or None.

    One OpenBao path per token: ingest replaces the whole secret at a path, so
    sharing a path per host would let the next token found erase the last.
    """
    # A unit key is preferred: it files under this unit's own prefix, which the
    # same unit can read back without the admin key — so this works on every
    # unit, not just the one that happens to hold LOCATOR_ADMIN_KEY.
    if LOKEY_UNIT_KEY:
        auth = _unit_key_headers()
    elif LOCATOR_ADMIN_KEY:
        auth = {"Host": LOCATOR_HOST_HEADER, "X-Locator-Admin-Key": LOCATOR_ADMIN_KEY}
    else:
        return None
    import hashlib
    digest = hashlib.sha256(secret.encode()).hexdigest()[:10]
    field = f"TOKEN_{digest}"
    source = re.sub(r"[^A-Za-z0-9._-]", "-", f"git-{host}-{digest}" if LOKEY_UNIT_KEY
                    else f"git-{UNIT_NAME}-{host}-{digest}")
    try:
        r = requests.post(
            f"{LOCATOR_URL}/api/secrets/ingest",
            headers=auth,
            json={"unit": (UNIT_KEY_UNIT or UNIT_NAME) if LOKEY_UNIT_KEY else UNIT_NAME,
                  "source": source, "path": _unhost(path),
                  "content": f"{field}={secret}\n"},
            timeout=30, verify=False,
        )
        body = r.json() if r.status_code == 200 else {}
    except Exception as e:
        print(f"[{UNIT_NAME}] git-token: vault call failed for {host}: {type(e).__name__}")
        return None
    if field not in (body.get("stored") or []):
        print(f"[{UNIT_NAME}] git-token: locator did not confirm storing {field} (HTTP {r.status_code})")
        return None
    return (body.get("refs") or {}).get(field)


def _scrub_one(path, key, url):
    """Move one remote URL's token into OpenBao. Returns a report line or None."""
    parts = _split_url_token(url)
    if not parts:
        return None
    clean, host, secret = parts
    where = f"{_unhost(path)} ({key})"

    if SCRUB_GIT_TOKENS_DRY_RUN:
        return f"would scrub {where}"

    ref = _vault_git_token(host, secret, path)
    if not ref:
        if (path, key) not in _scrub_reported:
            _scrub_reported.add((path, key))
            report_event("git-token-exposed",
                         f"{UNIT_NAME}: plaintext token in {where} left in place — "
                         f"could not vault it ({'no unit key or LOCATOR_ADMIN_KEY' if not (LOKEY_UNIT_KEY or LOCATOR_ADMIN_KEY) else 'locator refused'})")
        return None

    remote = key.split(".")[1]
    # Was the token even working? A token that is already rejected cannot be
    # "broken" by removing it, so only a working one earns a rollback.
    was_ok = _git(path, "ls-remote", "--heads", url, timeout=60).returncode == 0

    if _git(path, "config", "--local", key, clean).returncode != 0:
        return f"FAILED to rewrite {where}"
    _git(path, "config", "--local", "lokey.tokenref", ref)
    _tokenval_cache[ref] = secret

    now_ok = _git(path, "ls-remote", "--heads", remote, timeout=60, token=secret).returncode == 0
    if was_ok and not now_ok:
        _git(path, "config", "--local", key, url)
        _git(path, "config", "--local", "--unset", "lokey.tokenref")
        report_event("git-token-scrub-rollback",
                     f"{UNIT_NAME}: {where} could not reach its remote without the inline token — restored")
        return f"rolled back {where}"

    note = "" if was_ok else " (token was already rejected by the remote)"
    report_event("git-token-scrubbed", f"{UNIT_NAME}: moved plaintext token out of {where} → {ref}{note}")
    return f"scrubbed {where}{note}"


def scrub_git_tokens():
    """Remove plaintext tokens from git remote URLs in every checkout on this unit."""
    if not SCRUB_GIT_TOKENS_ENABLED:
        return []
    results = []
    for path in _find_checkouts():
        try:
            listed = _git(path, "config", "--local", "--get-regexp", r"^remote\..*\.(url|pushurl)$")
        except Exception:
            continue
        for line in listed.stdout.splitlines():
            key, _, url = line.partition(" ")
            try:
                line_result = _scrub_one(path, key, url.strip())
            except Exception as e:
                line_result = f"error on {_unhost(path)} ({key}): {type(e).__name__}"
            if line_result:
                results.append(line_result)
                print(f"[{UNIT_NAME}] git-token: {line_result}")
    return results


# ── ENV SECRET SCRUB ─────────────────────────────────────────────────────────
# People set services and scripts up the ordinary way — credentials typed into
# a .env. This sweep follows behind and moves them out, on every unit, with or
# without Docker:
#
#   1. only credential-shaped variables are sent to the locator (envscan), with
#      this unit's own key — ports, hosts and flags never leave the unit;
#   2. the locator files them in OpenBao under compose/units/<unit>/<project>,
#      reads them back, and returns the keys it confirmed;
#   3. lokey reads each one back itself, records the bao:// refs, and only then
#      deletes those lines from .env.
#
# Where the refs go, and how a value comes back:
#   - compose project (a compose file beside the .env): docker-compose.yml under
#     x-bao-secrets; _compose_on_host() resolves them on a recreate through lokey.
#   - anything else: a .env.bao beside the .env; whatever used to read .env runs
#     `eval "$(lokey secrets env <dir>)"` to get them.
#
# Deliberately left alone:
#   - a .env changed in the last ENV_SCRUB_MIN_AGE seconds (someone is setting up)
#   - compose: a project loading .env via `env_file:`, or a variable compose never
#     interpolates as ${KEY} — those values reach the container from the file
#     itself, so removing them would lose them on the next recreate
#   - no compose: a .env a cron job or systemd unit still loads without
#     `lokey secrets env` — removing it would break that job on its next run
#   - lokey, the locator and OpenBao: the chain that resolves secrets cannot
#     depend on itself to start
# A program started by hand that reads a cleaned .env gets its values from
# `lokey secrets env`; nothing is deleted without a verified copy in OpenBao.

ENV_SCRUB_ENABLED = os.getenv("ENV_SCRUB_ENABLED", "true").lower() == "true"
ENV_SCRUB_DRY_RUN = os.getenv("ENV_SCRUB_DRY_RUN", "false").lower() == "true"
ENV_SCRUB_MIN_AGE = int(os.getenv("ENV_SCRUB_MIN_AGE", "1800"))
ENV_SCRUB_SKIP    = {"lokey", "locator", "openbao"} | {
    s.strip() for s in os.getenv("ENV_SCRUB_SKIP", "").split(",") if s.strip()}
ENV_SCRUB_ROOTS   = [p.strip() for p in os.getenv(
    "ENV_SCRUB_ROOTS",
    f"/home/{REMOTE_USER}/projects,/home/{REMOTE_USER}/server,/home/{REMOTE_USER}/stacks,/root/projects",
).split(",") if p.strip()]
UNIT_KEY_UNIT, LOKEY_UNIT_KEY = unitsecrets.identity()

_env_scrub_reported = set()
_read_bao_block = unitsecrets.read_bao_block
_write_bao_block = unitsecrets.write_bao_block


def _unit_key_headers():
    return {"Host": LOCATOR_HOST_HEADER, "X-Lokey-Unit": UNIT_KEY_UNIT or UNIT_NAME,
            "X-Lokey-Key": LOKEY_UNIT_KEY}


def _report_once(tag, message):
    if tag in _env_scrub_reported:
        return
    _env_scrub_reported.add(tag)
    print(f"[{UNIT_NAME}] env-scrub: {message}")
    report_event("env-secrets", f"{UNIT_NAME}: {message}")


def _project_compose_files(workdir, config_files):
    """Host paths of a project's compose files, main file first."""
    paths = []
    for p in [x.strip() for x in (config_files or "").split(",") if x.strip()]:
        host = os.path.join(_host_dir(os.path.dirname(p)), os.path.basename(p))
        if os.path.isfile(host):
            paths.append(host)
    if not paths:
        found = _find_local_compose_file(workdir)
        if found:
            paths.append(found)
    return paths


def _uses_env_file(text, fname):
    """True when a compose file loads `fname` via env_file:."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)env_file\s*:\s*(.*)$", line)
        if not m:
            continue
        values = [m.group(2)]
        indent = len(m.group(1))
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            values.append(nxt)
        for v in values:
            for tok in re.split(r"[\s,\[\]]+", v.replace("path:", " ").replace("- ", " ")):
                if os.path.basename(tok.strip("'\"")) == fname:
                    return True
    return False


def _uses_env_file_dotenv(text):
    """True when a compose file loads the project .env via env_file:."""
    return _uses_env_file(text, ".env")


def _interpolates(texts, key):
    pat = re.compile(r"\$\{" + re.escape(key) + r"(?:[:?\-+][^}]*)?\}|\$" + re.escape(key) + r"\b")
    return any(pat.search(t) for t in texts)


def _atomic_write(path, text, like=None):
    """Replace `path` with text, keeping the owner and mode of `like` (or of path)."""
    st = os.stat(like or path)
    tmp = f"{path}.lokey-tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, path)


def _unit_resolve(refs):
    return unitsecrets.resolve(refs, LOCATOR_URL, LOCATOR_HOST_HEADER,
                               UNIT_KEY_UNIT or UNIT_NAME, LOKEY_UNIT_KEY)


def _bao_secrets_for(workdir):
    """{KEY: value} for everything a project directory has vaulted, or {}."""
    refs = unitsecrets.refs_for_dir(_host_dir(workdir))
    if not refs:
        return {}
    table = _unit_resolve(refs.values())
    return {k: table[ref] for k, ref in refs.items()}


def _running_compose_projects():
    client = _ensure_docker()
    if not client:
        return {}
    projects = {}
    # Raw `docker ps` — Labels ride in the summary, no per-container inspect.
    for c in client.api.containers():
        labels = c.get("Labels") or {}
        project = labels.get("com.docker.compose.project")
        workdir = labels.get("com.docker.compose.project.working_dir")
        if project and workdir:
            projects.setdefault((project, workdir), labels.get("com.docker.compose.project.config_files", ""))
    return projects


def _is_env_file(name):
    """Files the sweep treats as env sources: .env and every .env.<name>
    sibling — .env.bao, .env.oauth, .env.dbtier, .env.bak-*, .env.example.
    A plaintext secret in any of them is the same leak. .lokey-tmp is our
    own atomic-write scratch, never a source."""
    return (name == ".env" or name.startswith(".env.")) \
        and not name.endswith(".lokey-tmp")


def _env_files_in(host_dir):
    """Every env file in a dir, .env first so the primary file wins the
    '<source>' bao path and the siblings get file-scoped sources."""
    try:
        names = [f for f in os.listdir(host_dir) if _is_env_file(f)]
    except OSError:
        return []
    return [".env"] * (".env" in names) + sorted(f for f in names if f != ".env")


def _env_dirs():
    """Directories under the scrub roots that hold any env file (host paths)."""
    seen = set()
    for root in ENV_SCRUB_ROOTS:
        base = _host_dir(root)
        if not os.path.isdir(base):
            continue
        depth0 = base.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(base):
            if any(_is_env_file(f) for f in filenames):
                real = os.path.realpath(dirpath)
                if real not in seen:
                    seen.add(real)
                    yield dirpath
            if dirpath.count("/") - depth0 >= SCRUB_GIT_TOKENS_DEPTH:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames if d not in _SCRUB_PRUNE and ".bak" not in d]


def _consumer_texts():
    """(label, text) for every cron entry and systemd unit on this unit, with the
    text of any script they run inlined — what could be loading a .env."""
    out = []
    hp = "/host" if os.path.isdir("/host/proc") else ""
    cron = []
    if not hp:
        try:
            cron.append(("crontab", subprocess.run(["crontab", "-l"], capture_output=True,
                                                   text=True, timeout=15).stdout))
        except Exception:
            pass
    for d in (f"{hp}/var/spool/cron/crontabs", f"{hp}/var/spool/cron", f"{hp}/etc/cron.d"):
        try:
            names = os.listdir(d)
        except OSError:
            continue  # absent, or root-only for a native (non-root) lokey
        if names:
            for fn in names:
                p = os.path.join(d, fn)
                if os.path.isfile(p):
                    try:
                        cron.append((f"cron:{fn}", open(p, errors="replace").read()))
                    except OSError:
                        pass
    units = []
    for d in (f"{hp}/etc/systemd/system", f"{hp}/home/{REMOTE_USER}/.config/systemd/user",
              os.path.expanduser("~/.config/systemd/user"), os.path.expanduser("~/Library/LaunchAgents")):
        if not os.path.isdir(d):
            continue
        for dirpath, _dns, fns in os.walk(d):
            for fn in fns:
                if fn.endswith((".service", ".timer", ".conf", ".plist")):
                    try:
                        units.append((f"unit:{fn}", open(os.path.join(dirpath, fn), errors="replace").read()))
                    except OSError:
                        pass
    for label, text in cron + units:
        scripts = []
        for path in set(re.findall(r"(/[\w.@+-]+(?:/[\w.@+ -]+)+)", text)):
            host = hp + path if hp and not path.startswith("/host/") else path
            try:
                if os.path.isfile(host) and os.path.getsize(host) < 262144:
                    scripts.append(open(host, errors="replace").read())
            except OSError:
                pass
        out.append((label, "\n".join([text] + scripts)))
    return out


def _unswitched_consumers(env_host_path, consumers):
    """Consumers that load this .env and do not yet fetch from `lokey secrets env`."""
    real = _unhost(env_host_path)
    directory = os.path.dirname(real)
    hits = []
    for label, text in consumers:
        loads = real in text or (directory in text and ".env" in text)
        if loads and "lokey secrets env" not in text:
            hits.append(label)
    return sorted(set(hits))


def _source_name(project, host_dir):
    import hashlib
    base = re.sub(r"[^A-Za-z0-9._-]", "-", project).lstrip("._-") or "project"
    if project:
        return base
    return f"{base}-{hashlib.sha1(_unhost(host_dir).encode()).hexdigest()[:6]}"


_env_backup_posted = {}   # env path -> sha1 of posted secret blob


def _file_source(project, host_dir, fname):
    """bao path source for one env file. The primary .env keeps '<source>'; a
    sibling gets '<source>-env.<name>' so same-named keys in different files
    can never overwrite each other in the vault."""
    src = _source_name(project, host_dir)
    if fname == ".env":
        return src
    return src + "-" + re.sub(r"[^A-Za-z0-9._-]", "-", fname.lstrip("."))


def _backup_env_secrets(project, workdir):
    """Vault a copy of every env file's secret lines into OpenBao.

    Independent of the scrub: fires even when the scrub skips the dir
    (env_file: consumers, unreferenced keys, non-compose loaders) — exactly
    the population whose secrets exist ONLY as plaintext on this disk. The
    copy lands under a '<source>-env-backup' bao path so it can never
    overwrite the scrub's own refs at '<source>'. Pure backup — the file is
    never modified; hash-cached so unchanged files don't re-post every pass.
    """
    if not (LOKEY_UNIT_KEY or LOCATOR_ADMIN_KEY):
        return
    host_dir = _host_dir(workdir)
    for fname in _env_files_in(host_dir):
        try:
            _backup_env_file(project, host_dir, fname)
        except Exception as e:
            print(f"[{UNIT_NAME}] env-backup: {workdir}/{fname}: {type(e).__name__}: {e}")


def _backup_env_file(project, host_dir, fname):
    env_path = os.path.join(host_dir, fname)
    if not os.path.isfile(env_path):
        return
    with open(env_path, errors="replace") as fh:
        env_text = fh.read()
    candidates = envscan.secret_lines(env_text)
    if not candidates:
        return
    blob = "\n".join(line for _i, _k, line in candidates) + "\n"
    import hashlib
    digest = hashlib.sha1(blob.encode()).hexdigest()
    if _env_backup_posted.get(env_path) == digest:
        return
    if LOKEY_UNIT_KEY:
        auth = _unit_key_headers()
    else:
        auth = {"Host": LOCATOR_HOST_HEADER,
                "X-Locator-Admin-Key": LOCATOR_ADMIN_KEY}
    src = _file_source(project, host_dir, fname) + "-backup"
    r = requests.post(
        f"{LOCATOR_URL}/api/secrets/ingest", headers=auth, json={
            "unit": UNIT_KEY_UNIT or UNIT_NAME, "source": src,
            "path": _unhost(env_path), "content": blob},
        timeout=60, verify=False)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code == 200 and body.get("verified") is True:
        _env_backup_posted[env_path] = digest
        print(f"[{UNIT_NAME}] env-backup: vaulted {body.get('stored')} ({src})")


def _compose_service_blocks(lines):
    """(name, start, end) for each service under top-level `services:` —
    line-index spans, end exclusive. Indentation-driven so comments and key
    order survive; the compose file is only ever rewritten surgically."""
    svc_i = next((i for i, l in enumerate(lines)
                  if re.match(r"^services:\s*(#.*)?$", l)), None)
    if svc_i is None:
        return []
    first = next((i for i in range(svc_i + 1, len(lines))
                  if lines[i].strip() and not lines[i].lstrip().startswith("#")), None)
    if first is None:
        return []
    ind = len(lines[first]) - len(lines[first].lstrip())
    blocks, i = [], first
    while i < len(lines):
        l = lines[i]
        if not l.strip() or l.lstrip().startswith("#"):
            i += 1
            continue
        cur = len(l) - len(l.lstrip())
        if cur < ind:
            break
        if cur == ind and re.match(r"^\s*\S[^:]*:\s*(#.*)?$", l):
            end = next((j for j in range(i + 1, len(lines))
                        if lines[j].strip() and not lines[j].lstrip().startswith("#")
                        and len(lines[j]) - len(lines[j].lstrip()) <= ind),
                       len(lines))
            blocks.append((l.strip().split(":")[0], i, end))
            i = end
        else:
            i += 1
    return blocks


def _expand_inline_env_maps(lines):
    """`environment: {A: 1}` inline maps can't take children — expand them to
    block form up front so scan/surgery code only ever sees block form."""
    out = []
    for l in lines:
        m = re.match(r"^(\s*)environment\s*:\s*\{\s*(.*?)\s*\}\s*(#.*)?$",
                     l.rstrip("\n"))
        if m:
            pairs = [p.strip() for p in m.group(2).split(",") if p.strip()]
            if all(":" in p for p in pairs):
                out.append(f"{m.group(1)}environment:\n")
                out.extend(f"{m.group(1)}  {p}\n" for p in pairs)
                continue
        out.append(l)
    return out


def _convert_envfile_overrides(text, fname, keys):
    """env_file: hands a file's lines to the container VERBATIM — a vaulted
    `KEY=bao://...` would reach it as a literal string. `environment:` beats
    env_file: in compose, and `${KEY}` interpolates from the resolved values
    lokey exports into the compose run, so pinning `KEY: ${KEY}` on every
    env_file consumer keeps the container right through the rewrite.
    Returns (new_text, services_patched)."""
    lines = _expand_inline_env_maps(text.splitlines(keepends=True))
    inserts = []
    patched = 0
    for _name, lo, hi in _compose_service_blocks(lines):
        if not _uses_env_file("".join(lines[lo:hi]), fname):
            continue
        ef_i = next((j for j in range(lo + 1, hi)
                     if re.match(r"^\s*env_file\s*:", lines[j])), None)
        if ef_i is None:
            continue
        eind = len(lines[ef_i]) - len(lines[ef_i].lstrip())
        ef_end = next((j for j in range(ef_i + 1, hi)
                       if lines[j].strip() and not lines[j].lstrip().startswith("#")
                       and len(lines[j]) - len(lines[j].lstrip()) <= eind), hi)
        env_i = next((j for j in range(lo + 1, hi)
                      if re.match(rf"^\s{{{eind}}}environment\s*:\s*(#.*)?$", lines[j])), None)
        if env_i is not None:
            env_end = next((j for j in range(env_i + 1, hi)
                            if lines[j].strip() and not lines[j].lstrip().startswith("#")
                            and len(lines[j]) - len(lines[j].lstrip()) <= eind), hi)
            kids = [l for l in lines[env_i + 1:env_end] if l.strip()]
            list_form = bool(kids and kids[0].lstrip().startswith("-"))
            cind = len(kids[0]) - len(kids[0].lstrip()) if kids else eind + 2
            have = set()
            for l in kids:
                m = re.match(r"^\s*-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]", l)
                if m:
                    have.add(m.group(1))
            add = [k for k in keys if k not in have]
            if not add:
                # All keys already pinned by a previous pass — the service is
                # converted, it just needed nothing new. Count it so callers
                # do not read "0 patched" as "couldn't convert".
                patched += 1
                continue
            ins = [(f"{' ' * cind}- {k}=${{{k}}}\n" if list_form
                    else f"{' ' * cind}{k}: ${{{k}}}\n") for k in add]
            inserts.append((env_i + 1, ins))
        else:
            ins = [f"{' ' * eind}environment:\n"] + \
                  [f"{' ' * (eind + 2)}{k}: ${{{k}}}\n" for k in keys]
            inserts.append((ef_end, ins))
        patched += 1
    for pos, new in sorted(inserts, reverse=True):
        lines[pos:pos] = new
    return "".join(lines), patched


def _convert_envfile_in_compose(path, fname, keys):
    """Apply _convert_envfile_overrides to one compose file on disk."""
    with open(path, errors="replace") as fh:
        src = fh.read()
    if not _uses_env_file(src, fname):
        return 0
    new, n = _convert_envfile_overrides(src, fname, keys)
    if n:
        _atomic_write(path, new, like=path)
        print(f"[{UNIT_NAME}] env-scrub: rewrote env_file:{fname} to "
              f"${{VAR}} overrides in {n} service(s) of {_unhost(path)}",
              flush=True)
    return n


_URL_CREDS_RE = re.compile(r"://[^/\s'\"]*:[^@\s'\"]+@")


def _compose_env_entries(lines, lo, hi):
    """(line_index, key, raw_value) for every environment: entry in a service
    block — map form (`KEY: value`) and list form (`- KEY=value`)."""
    out = []
    for j in range(lo + 1, hi):
        m = re.match(r"^(\s*)environment\s*:\s*(#.*)?$", lines[j])
        if not m:
            continue
        eind = len(m.group(1))
        for k in range(j + 1, hi):
            l = lines[k]
            if not l.strip() or l.lstrip().startswith("#"):
                continue
            if len(l) - len(l.lstrip()) <= eind:
                break
            mm = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", l)
            if not mm:
                mm = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*$", l)
            if mm:
                out.append((k, mm.group(1), mm.group(2).strip()))
    return out


def _scrub_compose_file(project, host_path):
    """Secrets embedded directly in compose YAML (chat-stack's REDIS_URL sat
    in plaintext — the .env sweep never sees compose literals). Vault them via
    the same ingest path, rewrite each entry to ${KEY}, and record the refs in
    x-bao-secrets so compose runs through lokey keep resolving."""
    if time.time() - os.stat(host_path).st_mtime < ENV_SCRUB_MIN_AGE:
        return None
    with open(host_path, errors="replace") as fh:
        text = fh.read()
    lines = _expand_inline_env_maps(text.splitlines(keepends=True))
    label = os.path.basename(os.path.dirname(host_path)) or project
    found = []
    for _sname, lo, hi in _compose_service_blocks(lines):
        for idx, key, val in _compose_env_entries(lines, lo, hi):
            bare = val.strip().strip("'\"").strip()
            if not bare or bare.startswith("${") or "bao://" in bare:
                continue
            if envscan.is_storable(key, bare) or _URL_CREDS_RE.search(bare):
                found.append((idx, key, bare))
    if not found:
        return None
    names = sorted({k for _i, k, _v in found})
    if ENV_SCRUB_DRY_RUN:
        return f"would vault compose literals in {os.path.basename(host_path)}: {names}"

    r = requests.post(f"{LOCATOR_URL}/api/secrets/ingest",
                      headers=_unit_key_headers(), json={
        "unit": UNIT_KEY_UNIT or UNIT_NAME,
        "source": _file_source(project, os.path.dirname(host_path),
                               os.path.basename(host_path)),
        "path": _unhost(host_path),
        "content": "\n".join(f"{k}={v}" for _i, k, v in found) + "\n"},
        timeout=60, verify=False)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code != 200 or body.get("verified") is not True:
        _report_once(f"ingest:{host_path}:{r.status_code}",
                     f"{label}: locator did not confirm compose secrets "
                     f"(HTTP {r.status_code}) — file untouched")
        return None
    refs = body.get("refs") or {}
    confirmed = [k for k in names if k in set(body.get("stored") or []) and refs.get(k)]
    if not confirmed:
        return None
    values = {k: v for _i, k, v in found}
    table = _unit_resolve([refs[k] for k in confirmed])
    confirmed = [k for k in confirmed if table.get(refs[k]) == values[k]]
    if not confirmed:
        _report_once(f"readback:{host_path}",
                     f"{label}: could not read vaulted compose secrets back — file untouched")
        return None

    lines2 = list(lines)
    for idx, key, _v in found:
        if key not in confirmed:
            continue
        l = lines2[idx]
        if re.match(r"^\s*-\s*", l):
            lines2[idx] = re.sub(r"(=)\s*.*$", rf"\g<1>${{{key}}}", l.rstrip("\n")) + "\n"
        else:
            lines2[idx] = re.sub(r"(:)\s*.*$", rf"\g<1> ${{{key}}}", l.rstrip("\n")) + "\n"
    new_text = unitsecrets.write_bao_block(
        "".join(lines2), {k: refs[k] for k in confirmed})
    _atomic_write(host_path, new_text, like=host_path)
    print(f"[{UNIT_NAME}] env-scrub: vaulted compose literals in "
          f"{_unhost(host_path)}: {confirmed}", flush=True)
    return f"vaulted compose literals {confirmed} in {os.path.basename(host_path)}"


def _scrub_dir(project, workdir, config_files, consumers):
    results = []
    for fname in _env_files_in(_host_dir(workdir)):
        try:
            r = _scrub_env_file(project, workdir, config_files, consumers, fname)
        except Exception as e:
            r = f"{fname}: error {type(e).__name__}: {e}"
        if r:
            results.append(r)
    return "; ".join(results) if results else None


def _scrub_compose_secrets(project, workdir, config_files):
    """Vault literal secrets sitting in compose YAML itself."""
    out = []
    for p in _project_compose_files(workdir, config_files):
        try:
            r = _scrub_compose_file(project, p)
        except Exception as e:
            r = f"{os.path.basename(p)}: error {type(e).__name__}: {e}"
        if r:
            out.append(r)
    return "; ".join(out) if out else None


def _scrub_env_file(project, workdir, config_files, consumers, fname):
    """Scrub one env file. Every sibling gets the same vault-then-rewrite
    treatment as .env, with two file-shaped rules on top:

      - a non-.env file still raw-loaded by something (compose env_file:,
        cron/systemd source) keeps its plaintext — the backup pass already
        vaulted it, and the report says what to switch
      - dormant copies (.env.bak-*, .env.example, .sample/.template/.dist)
        are loaded by nothing, so their secrets are vaulted and their lines
        rewritten to bao:// refs — the file keeps its shape and its history,
        the values live only in OpenBao
    """
    host_dir = _host_dir(workdir)
    env_path = os.path.join(host_dir, fname)
    primary = fname == ".env"
    if time.time() - os.stat(env_path).st_mtime < ENV_SCRUB_MIN_AGE:
        return None
    with open(env_path, errors="replace") as fh:
        env_text = fh.read()
    candidates = envscan.secret_lines(env_text)
    if not candidates:
        return None

    compose_paths = _project_compose_files(workdir, config_files)
    label = project or os.path.basename(workdir.rstrip("/"))
    tag = label if primary else f"{label} {fname}"
    texts = []
    for p in compose_paths:
        with open(p, errors="replace") as fh:
            texts.append(fh.read())
    names = sorted({k for _i, k, _l in candidates})

    dormant = not primary and (
        ".bak" in fname or fname.endswith((".example", ".sample", ".template", ".dist")))
    if primary:
        if compose_paths:
            users = _unswitched_consumers(env_path, consumers)
            if users:
                _report_once(f"consumers:{workdir}:{','.join(users)}",
                             f"{label}: .env is still loaded by {users} — left in place until they run "
                             f"`eval \"$(lokey secrets env {_unhost(host_dir)})\"`")
                return None
            if any(_uses_env_file_dotenv(t) for t in texts):
                # env_file: hands the file's lines to the container verbatim, so
                # rewriting values to bao:// refs would inject literal refs.
                # lokey converts the consumer itself: environment: ${VAR}
                # overrides on each env_file service, then the normal
                # vault-and-rewrite path applies below.
                if ENV_SCRUB_DRY_RUN:
                    return f"would rewrite env_file:{fname} consumers to ${{VAR}} overrides and vault {tag}: {names}"
                patched = sum(_convert_envfile_in_compose(p, fname, names)
                              for p in compose_paths)
                if patched:
                    texts = []
                    for p in compose_paths:
                        with open(p, errors="replace") as fh:
                            texts.append(fh.read())
                else:
                    _report_once(f"envfile:{workdir}", f"{label}: loads .env via env_file: and could not be "
                                 f"converted to ${{VAR}} overrides automatically — credentials left in place")
                    return None
            keys = list(candidates)
            unreferenced = sorted({k for _i, k, _l in candidates
                                   if not _interpolates(texts, k)})
            if unreferenced:
                _report_once(f"noref:{workdir}:{','.join(unreferenced)}",
                             f"{label}: {unreferenced} not referenced as ${{VAR}} in compose — "
                             f"nothing raw-loads .env, so they're vaulted and rewritten to refs anyway")
        else:
            users = _unswitched_consumers(env_path, consumers)
            if users:
                _report_once(f"consumers:{workdir}:{','.join(users)}",
                             f"{label}: .env is still loaded by {users} — left in place until they run "
                             f"`eval \"$(lokey secrets env {_unhost(host_dir)})\"`")
                return None
            keys = candidates
    else:
        keys = candidates
        if not dormant:
            unpatched = False
            if any(_uses_env_file(t, fname) for t in texts):
                if ENV_SCRUB_DRY_RUN:
                    return f"would rewrite env_file:{fname} consumers to ${{VAR}} overrides and vault {tag}: {names}"
                for p in compose_paths:
                    with open(p, errors="replace") as fh:
                        psrc = fh.read()
                    if _uses_env_file(psrc, fname) and \
                            _convert_envfile_in_compose(p, fname, names) == 0:
                        unpatched = True
                texts = []
                for p in compose_paths:
                    with open(p, errors="replace") as fh:
                        texts.append(fh.read())
            raw = []
            if unpatched:
                raw.append(f"compose env_file:{fname}")
            raw += _unswitched_consumers(env_path, consumers)
            if raw:
                _report_once(f"rawfile:{env_path}:{','.join(sorted(set(raw)))}",
                             f"{tag}: {names} vaulted as backup but left in place — {fname} is raw-loaded by "
                             f"{sorted(set(raw))}; switch it to ${{VAR}} + x-bao-secrets or `lokey secrets env`")
                return None
    if not keys:
        return None
    confirmed_names = sorted({k for _i, k, _l in keys})
    if ENV_SCRUB_DRY_RUN:
        return f"would vault {tag} ({'compose' if primary and compose_paths else 'refs in place'}): {confirmed_names}"

    r = requests.post(f"{LOCATOR_URL}/api/secrets/ingest", headers=_unit_key_headers(), json={
        "unit": UNIT_KEY_UNIT or UNIT_NAME, "source": _file_source(project, host_dir, fname),
        "path": _unhost(env_path),
        "content": "\n".join(line for _i, _k, line in keys) + "\n"}, timeout=60, verify=False)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code != 200 or body.get("verified") is not True:
        _report_once(f"ingest:{env_path}:{r.status_code}", f"{tag}: locator did not confirm (HTTP {r.status_code}) — file untouched")
        return None
    refs = body.get("refs") or {}
    confirmed = [k for k in confirmed_names if k in set(body.get("stored") or []) and refs.get(k)]
    if not confirmed:
        return None

    # Whatever brings these back must work before anything is removed.
    values = {k: envscan._strip_value(envscan.ENV_ASSIGN_RE.match(line).group("value")) for _i, k, line in keys}
    table = _unit_resolve([refs[k] for k in confirmed])
    confirmed = [k for k in confirmed if table.get(refs[k]) == values[k]]
    if not confirmed:
        _report_once(f"readback:{env_path}", f"{tag}: could not read the vaulted values back — file untouched")
        return None

    # 1) record where each value now lives
    new_refs = {k: refs[k] for k in confirmed}
    if primary and compose_paths:
        main = compose_paths[0]
        with open(main, errors="replace") as fh:
            new_text = _write_bao_block(fh.read(), new_refs)
        if not set(confirmed) <= set(_read_bao_block(new_text)):
            raise RuntimeError("x-bao-secrets block did not round-trip")
        _atomic_write(main, new_text)
        where = "docker-compose.yml"
    elif primary:
        bao_path = os.path.join(host_dir, unitsecrets.BAO_FILE)
        old = open(bao_path, errors="replace").read() if os.path.isfile(bao_path) else ""
        new_text = unitsecrets.write_bao_file(old, new_refs)
        if not set(confirmed) <= set(unitsecrets.read_bao_file(new_text)):
            raise RuntimeError(".env.bao did not round-trip")
        if not os.path.exists(bao_path):
            open(bao_path, "w").close()
        _atomic_write(bao_path, new_text, like=env_path)
        where = unitsecrets.BAO_FILE
    else:
        where = f"{fname} (refs in place)"

    # 2) only then update the file — and only if it did not change meanwhile
    with open(env_path, errors="replace") as fh:
        if fh.read() != env_text:
            return f"{tag}: file changed during the sweep — refs recorded, lines kept for the next pass"
    lines = env_text.splitlines()
    if primary:
        drop = {i for i, k, _l in keys if k in confirmed}
        kept = [l for i, l in enumerate(lines) if i not in drop]
        _atomic_write(env_path, "\n".join(kept) + ("\n" if kept else ""))
        done = "removed from .env"
    else:
        for i, k, _l in keys:
            if k in confirmed:
                lines[i] = f"{k}={refs[k]}"
        _atomic_write(env_path, "\n".join(lines) + ("\n" if env_text.endswith("\n") else ""))
        done = f"values replaced with refs in {fname}"

    report_event("env-secrets", f"{UNIT_NAME}: {tag}: moved {confirmed} to OpenBao, {done}")
    return f"vaulted {tag}: {confirmed} ({where})"


def _skipped_dir(project, workdir):
    name = os.path.basename(workdir.rstrip("/"))
    return (project in ENV_SCRUB_SKIP or name in ENV_SCRUB_SKIP
            or workdir.rstrip("/") == LOKEY_PROJECT_DIR.rstrip("/"))


def scrub_env_secrets():
    """Move credentials out of .env files on this unit (compose or not)."""
    if not ENV_SCRUB_ENABLED:
        return []
    if not LOKEY_UNIT_KEY:
        _report_once("nokey", "no unit key (LOKEY_UNIT_KEY or ~/.config/lokey/unit.key) — .env credentials are not being vaulted")
        return []
    targets = {}
    for (project, workdir), config_files in _running_compose_projects().items():
        targets[os.path.realpath(_host_dir(workdir))] = (project, workdir, config_files)
    for host_dir in _env_dirs():
        targets.setdefault(os.path.realpath(host_dir), ("", _unhost(host_dir), ""))
    consumers = None
    results = []
    for project, workdir, config_files in targets.values():
        if _skipped_dir(project, workdir):
            continue
        if consumers is None:
            consumers = _consumer_texts()
        # Backup fires even when the scrub below skips this dir — the skip
        # cases are exactly where secrets are plaintext-only.
        _backup_env_secrets(project, workdir)
        try:
            res = _scrub_dir(project, workdir, config_files, consumers)
        except Exception as e:
            res = f"{project or workdir}: error {type(e).__name__}: {e}"
        if res:
            results.append(res)
            print(f"[{UNIT_NAME}] env-scrub: {res}")
        try:
            cres = _scrub_compose_secrets(project, workdir, config_files)
        except Exception as e:
            cres = f"{project or workdir}: compose-secrets error {type(e).__name__}: {e}"
        if cres:
            results.append(cres)
            print(f"[{UNIT_NAME}] env-scrub: {cres}")
    return results


DOCKER_CLI_IMAGE = os.getenv("LOKEY_DOCKER_CLI_IMAGE", "docker:27-cli")
LOKEY_GIT_REMOTE = os.getenv("LOKEY_GIT_REMOTE",
                             "https://gitlab.com/gbonds1/lokey.git")


def _ensure_git_checkout(host_dir):
    """self_update needs a git working copy. A manually-deployed dir (plain
    files, no .git — unit2 shipped this way) fails rev-parse forever and can
    never update. Bootstrap it in place: init + origin + fetch + reset, so
    the tree becomes the repo's content and pulls work from here on.
    Local-only modifications are discarded — nothing else manages this dir."""
    has_git = subprocess.run(
        ["git", "-C", host_dir, "rev-parse", "--git-dir"],
        capture_output=True, text=True).returncode == 0
    has_head = has_git and subprocess.run(
        ["git", "-C", host_dir, "rev-parse", "--verify", "HEAD"],
        capture_output=True, text=True).returncode == 0
    if has_git and has_head:
        return True
    # A previous attempt that died at fetch leaves .git with no HEAD — same
    # fix path as no .git at all. init/set-url are idempotent over it.
    print(f"[{UNIT_NAME}] self_update: {host_dir} is not a usable git checkout "
          f"(git={has_git} head={has_head}) — bootstrapping in place", flush=True)
    if not has_git:
        r = _git(host_dir, "init", "-b", "main", timeout=30)
        if r.returncode != 0:
            print(f"[{UNIT_NAME}] self_update: bootstrap 'init' failed: "
                  f"{r.stderr.strip()[:200]}", flush=True)
            return False
    if subprocess.run(["git", "-C", host_dir, "remote", "get-url", "origin"],
                      capture_output=True, text=True).returncode != 0:
        _git(host_dir, "remote", "add", "origin", LOKEY_GIT_REMOTE, timeout=30)
    else:
        _git(host_dir, "remote", "set-url", "origin", LOKEY_GIT_REMOTE, timeout=30)
    steps = [
        (["fetch", "origin", "main"], 180),
        (["reset", "--hard", "origin/main"], 60),
    ]
    for args, timeout in steps:
        r = _git(host_dir, *args, timeout=timeout)
        if r.returncode != 0:
            print(f"[{UNIT_NAME}] self_update: bootstrap '{' '.join(args)}' "
                  f"failed: {r.stderr.strip()[:200]}", flush=True)
            return False
    # Point the fresh checkout at the canonical token ref — same contract
    # scrub_git_tokens() leaves behind, so _repo_token() resolves it.
    _git(host_dir, "config", "--local", "lokey.tokenref", GIT_TOKEN_REF)
    print(f"[{UNIT_NAME}] self_update: {host_dir} bootstrapped to origin/main",
          flush=True)
    return True


def _rebuild_self(host_dir):
    """Rebuild this lokey container without being killed halfway through.

    The old code ran `docker compose up -d --build` as a CHILD OF THIS PROCESS.
    compose then stops this container in order to recreate it — killing the very
    process driving the recreate. It usually survived as an orphan, which is why
    it worked for months, but it raced on unit8 (2026-08-23) and left the old
    container Exited(137) with the replacement stuck in Created. That unit
    stopped reporting to the registry entirely and needed a human.

    Two phases:

      1. BUILD from here. Building never touches the running container, so if it
         fails we abort having changed nothing — much better than discovering a
         broken build halfway through a recreate.

      2. Hand the RECREATE to a short-lived helper container. It has its own
         lifecycle, so stopping lokey cannot interrupt it. chroot/setsid do not
         help: they change the filesystem root, not the PID namespace, so the
         process would still die with the container.

    Falls back to the old inline behaviour if the helper cannot be launched (no
    image, no pull). That is no worse than before, and a unit that cannot pull
    an image should still get its update.
    """
    print(f"[{UNIT_NAME}] self_update: building new image...", flush=True)
    build = subprocess.run(
        _docker_argv(["docker", "compose", "-f", f"{host_dir}/docker-compose.yml",
                      "build"], cwd=host_dir),
        capture_output=True, text=True, timeout=900,
    )
    if build.returncode != 0:
        print(f"[{UNIT_NAME}] self_update: BUILD FAILED, keeping current "
              f"container: {build.stderr.strip()[-400:]}", flush=True)
        return

    daemon_dir = _daemon_path(host_dir)
    project = os.getenv("COMPOSE_PROJECT_NAME",
                        os.path.basename(daemon_dir.rstrip("/")))
    print(f"[{UNIT_NAME}] self_update: image built — handing the recreate to a "
          f"helper container", flush=True)

    helper = subprocess.run(
        _docker_argv([
            "docker", "run", "--rm", "-d",
            "--name", f"lokey-selfupdate-{int(time.time())}",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            # Mounted at the SAME path the daemon uses, so compose resolves the
            # project and any relative bind mounts exactly as it would on the host.
            "-v", f"{daemon_dir}:{daemon_dir}",
            "-w", daemon_dir,
            DOCKER_CLI_IMAGE,
            # -p pinned: compose otherwise derives the project name from the
            # working directory, and a mismatch would stand up a SECOND lokey
            # alongside this one instead of replacing it.
            # Then verify: unit4 (2026-10-14) saw the replacement land in
            # `Created` and stay there — compose raced its own start. Any
            # service container still not running gets an explicit start.
            "sh", "-c",
            f"docker compose -p {shlex.quote(project)} up -d; sleep 3; "
            f"for id in $(docker compose -p {shlex.quote(project)} ps -aq); do "
            f"[ \"$(docker inspect -f '{{{{.State.Running}}}}' $id)\" = true ] || "
            f"docker start $id; done",
        ]),
        capture_output=True, text=True, timeout=120,
    )
    if helper.returncode == 0:
        print(f"[{UNIT_NAME}] self_update: helper launched, this container is "
              f"about to be replaced", flush=True)
        return

    print(f"[{UNIT_NAME}] self_update: helper launch failed "
          f"({helper.stderr.strip()[-300:]}) — falling back to inline recreate",
          flush=True)
    subprocess.Popen(
        _docker_argv(["docker", "compose", "-f", f"{host_dir}/docker-compose.yml",
                      "up", "-d"], cwd=host_dir)
    )


def self_update():
    """git pull lokey; if new code detected, rebuild (Docker) or restart (native)."""
    # Docker containers mount the host root at /host; native installs use the path directly.
    host_dir = f"/host{LOKEY_PROJECT_DIR}"
    if not os.path.isdir(host_dir):
        host_dir = LOKEY_PROJECT_DIR
    if not os.path.isdir(host_dir):
        print(f"[{UNIT_NAME}] self_update: project dir not found ({LOKEY_PROJECT_DIR})")
        return
    if not _ensure_git_checkout(host_dir):
        return

    before = subprocess.run(
        ["git", "-C", host_dir, "rev-parse", "HEAD"],
        capture_output=True, text=True
    ).stdout.strip()

    # Through _git() for its credential helper. A bare `git pull` only worked
    # while the token sat in the remote URL; once scrub_git_tokens() moves it to
    # OpenBao, that pull would fail and the fleet would stop updating itself.
    pull = _git(host_dir, "pull", "--ff-only", timeout=30)
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
        _rebuild_self(host_dir)
    else:
        # Native (macOS launchd / systemd): exit and let the supervisor restart us
        import sys
        print(f"[{UNIT_NAME}] self_update: exiting for supervisor restart")
        sys.exit(0)


def install_cli():
    """Put a current `lokey` command on this machine's PATH.

    Runs at startup (and on the update tick) so every device and node that runs
    a lokey client can issue locator commands from its own shell, instead of
    only from whatever box happened to have the CLI copied onto it.
    """
    try:
        from install_cli import ensure_cli_installed
        ensure_cli_installed(
            project_dir=LOKEY_PROJECT_DIR,
            unit_name=UNIT_NAME,
            url=LOCATOR_URL,
            header=LOCATOR_HOST_HEADER,
        )
    except Exception as e:
        print(f"[{UNIT_NAME}] cli-install: skipped ({e})")


if __name__ == "__main__":
    print(f"🚀 Lokey starting on {UNIT_NAME}...")

    install_cli()

    # Collect and cache IPs on startup
    _private_ip = get_private_ip()
    _tailscale_ip_cached = get_tailscale_ip()
    _start_public_ip_background_fetch()  # Non-blocking fetch, result cached globally

    # Log IPs for startup diagnostics
    print(f"[{UNIT_NAME}] private_ip: {_private_ip or 'unavailable'}")
    print(f"[{UNIT_NAME}] tailscale_ip: {_tailscale_ip_cached or 'unavailable'}")
    print(f"[{UNIT_NAME}] public_ip: fetching (non-blocking)...")

    threading.Thread(target=_heartbeat_pulse_loop, daemon=True,
                     name="heartbeat-pulse").start()

    _dns_tick = 0
    _update_tick = 0
    _cert_tick = 0
    _mtls_tick = 0
    while True:
        register_stats()
        check_locator_failover()
        check_pending_migrations()
        check_pending_commands()
        check_drain_releases()
        keep_alive()
        report_idle_stats()
        disk_janitor()
        # Renew this node's fleet mTLS leaves before reporting, so a report in
        # the same tick shows the post-rotation lifetimes. No UNIT_NAME gate:
        # rotate() discovers what to rotate from the containers actually running
        # here, so it is a no-op on a node that carries no mesh identity.
        if _mtls_tick % MTLS_ROTATE_TICKS == 0:
            try:
                from rotate_mtls import rotate as rotate_mesh_certs
                rotate_mesh_certs()
            except Exception as e:
                print(f"[{UNIT_NAME}] mtls rotate error: {e}")
        _mtls_tick += 1
        if _cert_tick % CERT_CHECK_TICKS == 0:
            report_cert_status()
        _cert_tick += 1
        # DNS for Traefik-routed hosts. No UNIT_NAME gate: writable_here() is
        # true only where the writable PowerDNS primary container runs, so this
        # follows pdns to whatever unit it lives on. Everywhere else it is a
        # cheap no-op. (The old unit2 sync_dns_apache path — BIND on retired
        # Apache — is dropped.)
        _dns_tick += 1
        if _dns_tick >= 5:
            _dns_tick = 0
            try:
                from sync_dns_pdns import sync as pdns_sync, writable_here
                if writable_here():
                    pdns_sync(target_ip=_public_ip)
                    ddns_ip_watcher()
            except Exception as e:
                print(f"[{UNIT_NAME}] dns-sync error: {e}")
        _update_tick += 1
        if _update_tick >= 5:
            _update_tick = 0
            install_cli()
            self_update()
            sync_repos()
            scrub_git_tokens()
            scrub_env_secrets()
        time.sleep(TICK_RATE)
