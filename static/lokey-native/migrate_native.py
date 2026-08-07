"""
Native (non-Docker/systemd) migration executor.

Shared by hard-stats.py (Docker hosts — one more execute_migration() dispatch
branch) and /usr/local/lokey/lokey.py (bare-metal hosts, which have zero
migration execution code today — see check_pending_migrations() added there).

Migration types (parallel to hard-stats.py's git_push_and_stop/
git_pull_and_start/git_pull_only for containers):

  native_stop_and_sync    — runs on the SOURCE unit: stop the systemd unit,
                            rsync its config/working dir to the target.
  native_prereq_and_start — runs on the TARGET unit: ensure declared
                            prereqs (apt packages, other systemd units,
                            disk headroom), then start the unit.

Both dispatch through execute_native_migration(mig) and return the same
(success: bool, extra: dict) shape hard-stats.py's git-based executors use,
so the calling agent's completion report works identically either way.
"""
import os
import shutil
import subprocess

REMOTE_USER = os.getenv("REMOTE_USER", "root")


def _find_ssh_key():
    """Return the first usable private key in ~/.ssh."""
    ssh_dir = os.path.expanduser("~/.ssh")
    for name in ("id_ed25519", "id_rsa"):
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


def _systemctl(action, unit, timeout=30):
    result = subprocess.run(["systemctl", action, unit], capture_output=True, text=True, timeout=timeout)
    return result.returncode == 0, (result.stderr or result.stdout).strip()


def _is_unit_active(unit):
    result = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=10)
    return result.stdout.strip() == "active"


def _apt_package_installed(pkg):
    result = subprocess.run(["dpkg", "-s", pkg], capture_output=True, text=True, timeout=10)
    return result.returncode == 0


def _ensure_prereqs(prereqs, timeout=120):
    """
    Best-effort readiness check/fix on THIS node for a service about to run
    here. Returns (all_satisfied, missing_list). Installing a missing
    package is safe to do speculatively — it never starts anything — which
    is why this same function is reused by Phase 3's pre-staging as well as
    real migration execution.
    """
    prereqs = prereqs or {}
    missing = []

    for pkg in prereqs.get("apt_packages", []) or []:
        if _apt_package_installed(pkg):
            continue
        result = subprocess.run(
            ["apt-get", "install", "-y", pkg],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0 or not _apt_package_installed(pkg):
            missing.append(f"apt:{pkg}")

    for unit in prereqs.get("systemd_units", []) or []:
        if not _is_unit_active(unit):
            missing.append(f"systemd:{unit}")

    min_disk_gb = prereqs.get("min_disk_gb")
    if min_disk_gb:
        try:
            free_gb = shutil.disk_usage("/").free / (1024 ** 3)
            if free_gb < min_disk_gb:
                missing.append(f"disk:{free_gb:.1f}gb<{min_disk_gb}gb")
        except Exception:
            pass

    return (not missing), missing


def execute_native_migration(mig):
    """
    Dispatch a native migration. Returns (success, extra) — same shape as
    hard-stats.py's git-based execute_migration() — so callers don't need
    to special-case native vs. container migrations.
    """
    mig_type = mig.get("type")
    if mig_type == "native_stop_and_sync":
        return _stop_and_sync(mig)
    if mig_type == "native_prereq_and_start":
        return _prereq_and_start(mig)
    return False, {"error": f"unknown native migration type {mig_type!r}"}


def _stop_and_sync(mig):
    """
    sync_path and systemd_unit must be supplied at migration-creation time —
    unlike a docker-compose project, there's no label to auto-discover a
    native service's config/working directory from.
    """
    mig_id       = mig["id"]
    name         = mig["container"]  # holds the systemd unit's friendly name here
    to_ip        = mig.get("to_ip")
    sync_path    = mig.get("sync_path")
    systemd_unit = mig.get("systemd_unit", name)

    print(f"[native] \U0001F4E4 native_stop_and_sync {mig_id}: {name} -> {to_ip}")

    if not sync_path:
        print(f"[native] FAILED {mig_id}: no sync_path provided for {name}")
        return False, {}
    if not to_ip:
        print(f"[native] FAILED {mig_id}: no to_ip provided")
        return False, {}

    ok, err = _systemctl("stop", systemd_unit)
    if not ok:
        print(f"[native] FAILED {mig_id}: systemctl stop {systemd_unit}: {err}")
        return False, {}

    key = _find_ssh_key()
    ssh_opts = "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10"
    if key:
        ssh_opts += f" -i {key}"

    rsync_cmd = [
        "rsync", "-az", "--delete", "-e", ssh_opts,
        sync_path.rstrip("/") + "/",
        f"{REMOTE_USER}@{to_ip}:{sync_path.rstrip('/')}/",
    ]
    result = subprocess.run(rsync_cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"[native] FAILED {mig_id}: rsync: {result.stderr.strip()[:200]}")
        return False, {}

    print(f"[native] OK {mig_id}: native_stop_and_sync complete - {name} handed off")
    return True, {"sync_path": sync_path, "systemd_unit": systemd_unit}


def _prereq_and_start(mig):
    """Files already arrived via the source's rsync push in _stop_and_sync."""
    mig_id       = mig["id"]
    name         = mig["container"]
    systemd_unit = mig.get("systemd_unit", name)
    prereqs      = mig.get("prereqs", {})

    print(f"[native] \U0001F4E5 native_prereq_and_start {mig_id}: {name} (unit: {systemd_unit})")

    ok, missing = _ensure_prereqs(prereqs)
    if not ok:
        print(f"[native] FAILED {mig_id}: unmet prereqs: {missing}")
        return False, {"missing_prereqs": missing}

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
    ok, err = _systemctl("start", systemd_unit)
    if not ok:
        print(f"[native] FAILED {mig_id}: systemctl start {systemd_unit}: {err}")
        return False, {}

    print(f"[native] OK {mig_id}: native_prereq_and_start complete - {name} running")
    return True, {}
