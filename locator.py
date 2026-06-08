"""
Black Sheep Locator — Universal Service Registry + Load Balancer
"""
import os, json, uuid, time, threading, subprocess, pathlib, re
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string, Response

app = Flask(__name__)

# ── PATHS ─────────────────────────────────────────────────────────────────────
DATA_DIR       = pathlib.Path(os.getenv("DATA_DIR", "/app/data"))
REGISTRY_FILE  = DATA_DIR / "registry.json"
MIGRATION_FILE = DATA_DIR / "migrations.json"
COMPOSE_DIR    = DATA_DIR / "compose"
for d in (DATA_DIR, COMPOSE_DIR): d.mkdir(parents=True, exist_ok=True)

# ── CONFIG ────────────────────────────────────────────────────────────────────
UNIT_NAME         = os.getenv("UNIT_NAME", "unit4")
BALANCE_INTERVAL  = int(os.getenv("BALANCE_INTERVAL",   "120"))  # s between balance checks
BALANCE_HIGH      = float(os.getenv("BALANCE_HIGH",      "40"))  # min load% before we care
BALANCE_DIFF      = float(os.getenv("BALANCE_DIFF",       "5"))  # max gap% between nodes
BALANCE_COOLDOWN  = int(os.getenv("BALANCE_COOLDOWN",   "300"))  # s between migrations
BALANCE_STRIKES   = int(os.getenv("BALANCE_STRIKES",      "2"))  # anti-flap consecutive checks
OOM_THRESHOLD     = float(os.getenv("OOM_THRESHOLD",      "90")) # % — bypass anti-flap
GIT_AUTO_PUSH     = os.getenv("GIT_AUTO_PUSH", "true").lower() == "true"
GIT_REMOTE        = os.getenv("GIT_REMOTE", "")  # e.g. git@gitlab.com:org/compose-backup.git

_PINNED_NAMES = {
    "traefik", "powerdns", "locator", "lokey", "tailscale",
    "apache", "openvpn", "ns1-auth", "ns1",
}

# ── LOCKS ─────────────────────────────────────────────────────────────────────
_reg_lock = threading.RLock()
_mig_lock = threading.RLock()
_git_lock = threading.Lock()

# ── HELPERS ───────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _load_json(path: pathlib.Path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default

def _save_json(path: pathlib.Path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)

def _registry():
    return _load_json(REGISTRY_FILE, {"services": {}, "nodes": {}})

def _save_registry(r):
    _save_json(REGISTRY_FILE, r)

def _migrations():
    return _load_json(MIGRATION_FILE, {})

def _save_migrations(m):
    _save_json(MIGRATION_FILE, m)

def _best_ip(node: dict) -> str | None:
    for key in ("tailscale_ip", "ip", "openvpn_ip"):
        ip = node.get(key, "")
        if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", str(ip).strip()):
            return str(ip).strip()
    return None

def _is_stale(node: dict, max_age: int = 300) -> bool:
    ts = node.get("last_metrics")
    if not ts:
        return True
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()
        return age > max_age
    except Exception:
        return True

def _node_load(node: dict) -> float | None:
    vals = [node.get(k) for k in ("cpu_percent", "mem_percent", "disk_percent")]
    vals = [v for v in vals if v is not None]
    return max(vals) if vals else None

def _git_auto_push():
    if not GIT_AUTO_PUSH:
        return
    with _git_lock:
        try:
            d = str(COMPOSE_DIR)
            if not (COMPOSE_DIR / ".git").exists():
                subprocess.run(["git", "init"], cwd=d, capture_output=True)
                subprocess.run(["git", "config", "user.email", "locator@blacksheep"], cwd=d, capture_output=True)
                subprocess.run(["git", "config", "user.name", "locator"], cwd=d, capture_output=True)
                if GIT_REMOTE:
                    subprocess.run(["git", "remote", "add", "origin", GIT_REMOTE], cwd=d, capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=d, capture_output=True)
            r = subprocess.run(
                ["git", "commit", "-m", f"auto: compose snapshot {_now()}"],
                cwd=d, capture_output=True, text=True
            )
            if "nothing to commit" in r.stdout:
                return
            if GIT_REMOTE:
                subprocess.run(
                    ["git", "push", "-u", "origin", "HEAD:main", "--force"],
                    cwd=d, capture_output=True, timeout=30
                )
                print(f"[locator] git-push: compose files pushed")
        except Exception as e:
            print(f"[locator] git-push error: {e}")

# ── REGISTRATION ──────────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json(force=True) or {}
    name     = data.get("name", "")
    host     = data.get("host", UNIT_NAME)
    typ      = data.get("type", "service")
    status   = data.get("status", "ONLINE")
    metadata = data.get("metadata", {})
    category = data.get("category", typ)
    url      = data.get("url")

    with _reg_lock:
        r = _registry()
        n = r["nodes"].setdefault(host, {})
        n["last_seen"] = _now()
        if status == "ONLINE":
            n["status"] = "ONLINE"

        key = f"{host}__{name}" if name else f"{host}__{typ}"
        r["services"][key] = {
            "name": name, "host": host, "type": typ, "status": status,
            "category": category, "url": url, "last_seen": _now(),
            "metadata": metadata,
        }
        _save_registry(r)
    return jsonify({"ok": True})


@app.route("/nodes/<node_id>/metrics", methods=["PATCH"])
def patch_node_metrics(node_id):
    data = request.get_json(force=True) or {}
    with _reg_lock:
        r = _registry()
        n = r["nodes"].setdefault(node_id, {})
        for k in ("cpu_percent", "mem_percent", "disk_percent", "disk_total_gb", "disk_used_gb"):
            if data.get(k) is not None:
                n[k] = data[k]
        for k in ("tailscale_ip", "ip"):
            if data.get(k):
                n[k] = data[k]
        n["last_metrics"] = _now()
        n["status"] = "ONLINE"
        _save_registry(r)
    return jsonify({"ok": True})


@app.route("/api/nodes", methods=["GET"])
def api_nodes():
    with _reg_lock:
        return jsonify(_registry()["nodes"])


@app.route("/api/services", methods=["GET"])
def api_services():
    with _reg_lock:
        return jsonify(_registry()["services"])


# ── COMPOSE STORE ─────────────────────────────────────────────────────────────
@app.route("/api/compose/<container_name>", methods=["POST"])
def store_compose(container_name):
    content = request.get_data(as_text=True)
    if not content.strip():
        return jsonify({"error": "empty"}), 400
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", container_name)
    (COMPOSE_DIR / f"{safe}.yml").write_text(content)
    threading.Thread(target=_git_auto_push, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/compose/<container_name>", methods=["GET"])
def get_compose(container_name):
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", container_name)
    path = COMPOSE_DIR / f"{safe}.yml"
    if not path.exists():
        return ("", 404)
    return Response(path.read_text(), mimetype="text/yaml")


@app.route("/api/compose", methods=["GET"])
def list_compose():
    files = sorted(COMPOSE_DIR.glob("*.yml"))
    return jsonify([f.stem for f in files])


# ── MIGRATION API ─────────────────────────────────────────────────────────────
@app.route("/api/migrations/pending", methods=["GET"])
def pending_migrations():
    unit = request.args.get("unit")
    with _mig_lock:
        m = _migrations()
    result = [
        v for v in m.values()
        if v["status"] == "PENDING" and (not unit or v["from_node"] == unit)
    ]
    return jsonify(result)


@app.route("/api/migrations/<mig_id>/claim", methods=["POST"])
def claim_migration(mig_id):
    data = request.get_json(force=True) or {}
    unit = data.get("unit")
    with _mig_lock:
        m = _migrations()
        mig = m.get(mig_id)
        if not mig:
            return jsonify({"error": "not found"}), 404
        if mig["status"] != "PENDING":
            return jsonify({"error": "already claimed"}), 409
        if unit and mig["from_node"] != unit:
            return jsonify({"error": "not yours"}), 403
        mig["status"] = "IN_PROGRESS"
        mig["claimed_at"] = _now()
        _save_migrations(m)
    return jsonify({"ok": True})


@app.route("/api/migrations/complete", methods=["POST"])
def complete_migration():
    data = request.get_json(force=True) or {}
    mig_id  = data.get("id")
    success = data.get("success", False)
    with _mig_lock:
        m = _migrations()
        if mig_id and mig_id in m:
            m[mig_id]["status"]       = "DONE" if success else "FAILED"
            m[mig_id]["completed_at"] = _now()
            _save_migrations(m)
    return jsonify({"ok": True})


@app.route("/api/balance/status", methods=["GET"])
def balance_status():
    with _reg_lock:
        r = _registry()
    with _mig_lock:
        m = _migrations()
    return jsonify({
        "nodes": r["nodes"],
        "migrations": list(m.values()),
        "config": {
            "BALANCE_HIGH":    BALANCE_HIGH,
            "BALANCE_DIFF":    BALANCE_DIFF,
            "BALANCE_STRIKES": BALANCE_STRIKES,
            "OOM_THRESHOLD":   OOM_THRESHOLD,
        },
    })


# ── LOAD BALANCER ─────────────────────────────────────────────────────────────
_strikes: dict[str, int] = {}
_cooldowns: dict[str, float] = {}

def _movable_containers(host: str, registry: dict) -> list[str]:
    result = []
    for svc in registry["services"].values():
        if svc.get("host") != host or svc.get("type") != "container":
            continue
        name = svc.get("name", "")
        if not name or any(p in name.lower() for p in _PINNED_NAMES):
            continue
        result.append(name)
    return result

def load_balancer():
    with _reg_lock:
        r = _registry()
    live = {
        nid: n for nid, n in r["nodes"].items()
        if n.get("status") == "ONLINE" and not _is_stale(n)
    }
    if len(live) < 2:
        print(f"[locator] balance: {len(live)} live node(s) — skipping")
        return

    loads = {nid: _node_load(n) for nid, n in live.items()}
    loads = {k: v for k, v in loads.items() if v is not None}
    if len(loads) < 2:
        return

    max_id = max(loads, key=loads.__getitem__)
    min_id = min(loads, key=loads.__getitem__)
    max_load = loads[max_id]
    min_load = loads[min_id]
    diff = max_load - min_load

    mem_pct = live[max_id].get("mem_percent") or 0
    is_oom  = mem_pct >= OOM_THRESHOLD

    # No action needed: both nodes are within tolerance or all are under threshold
    if max_load < BALANCE_HIGH and not is_oom:
        _strikes.pop(max_id, None)
        return

    if diff < BALANCE_DIFF and not is_oom:
        _strikes.pop(max_id, None)
        print(f"[locator] balance: gap={diff:.1f}% < {BALANCE_DIFF}% — no action")
        return

    if is_oom:
        print(f"[locator] balance: ⚠️ OOM on {max_id} mem={mem_pct:.1f}% — emergency bypass")
    else:
        _strikes[max_id] = _strikes.get(max_id, 0) + 1
        if _strikes[max_id] < BALANCE_STRIKES:
            print(f"[locator] balance: {max_id} strike {_strikes[max_id]}/{BALANCE_STRIKES} load={max_load:.1f}% diff={diff:.1f}%")
            return

    now = time.time()
    if not is_oom and now - _cooldowns.get(max_id, 0) < BALANCE_COOLDOWN:
        remain = BALANCE_COOLDOWN - (now - _cooldowns[max_id])
        print(f"[locator] balance: {max_id} cooldown ({remain:.0f}s left)")
        return

    movable = _movable_containers(max_id, r)
    if not movable:
        print(f"[locator] balance: {max_id} has no movable containers")
        return

    tgt_ip = _best_ip(live[min_id])
    if not tgt_ip:
        print(f"[locator] balance: {min_id} has no reachable IP")
        return

    src_ip = _best_ip(live[max_id])
    container = movable[0]
    mig_id = str(uuid.uuid4())[:8]
    mig = {
        "id":        mig_id,
        "container": container,
        "from_node": max_id,
        "from_ip":   src_ip,
        "to_node":   min_id,
        "to_ip":     tgt_ip,
        "status":    "PENDING",
        "queued_at": _now(),
        "reason":    f"{'OOM_EMERGENCY' if is_oom else 'BALANCE'}: {max_id}={max_load:.1f}% → {min_id}={min_load:.1f}% (gap {diff:.1f}%)",
    }
    with _mig_lock:
        m = _migrations()
        m[mig_id] = mig
        _save_migrations(m)

    _strikes.pop(max_id, None)
    _cooldowns[max_id] = now
    print(f"[locator] balance: queued {mig_id} — {container}: {max_id}({max_load:.1f}%) → {min_id}({min_load:.1f}%)")


def _balancer_loop():
    while True:
        try:
            load_balancer()
        except Exception as e:
            print(f"[locator] balancer error: {e}")
        time.sleep(BALANCE_INTERVAL)


# ── TACTICAL GRID WEB UI ──────────────────────────────────────────────────────
_UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Black Sheep Locator</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--accent:#a855f7;
  --green:#22c55e;--red:#f43f5e;--yellow:#f59e0b;--blue:#06b6d4;
  --text:#e2e8f0;--muted:#64748b;
}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;font-size:13px;min-height:100vh}
header{display:flex;align-items:center;gap:12px;padding:16px 24px;border-bottom:1px solid var(--border);background:rgba(168,85,247,.04)}
.logo{font-size:1.3rem;font-weight:700;color:var(--accent);letter-spacing:2px}
.logo span{color:var(--text)}
.subtitle{color:var(--muted);font-size:11px;letter-spacing:1px}
.ts{margin-left:auto;color:var(--muted);font-size:11px}
main{padding:24px;display:flex;flex-direction:column;gap:24px}
section{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.sec-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}
.sec-head .dot{width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 8px var(--accent)}

/* NODE CARDS */
.node-row{display:flex;gap:16px;padding:16px;flex-wrap:wrap}
.node-card{flex:1;min-width:200px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:14px;position:relative;overflow:hidden}
.node-card.oom{border-color:var(--red);box-shadow:0 0 12px rgba(244,63,94,.2)}
.node-name{font-weight:700;font-size:14px;color:var(--text);margin-bottom:10px}
.node-ip{font-size:10px;color:var(--muted);margin-bottom:10px}
.metric-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.metric-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.metric-val{font-size:12px;font-weight:600}
.bar{height:4px;background:var(--border);border-radius:2px;margin-bottom:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px;transition:width .4s ease}
.status-badge{position:absolute;top:12px;right:12px;font-size:9px;padding:2px 6px;border-radius:3px;font-weight:700;letter-spacing:.5px}
.badge-online{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.badge-stale{background:rgba(245,158,11,.15);color:var(--yellow);border:1px solid rgba(245,158,11,.3)}
.badge-offline{background:rgba(244,63,94,.15);color:var(--red);border:1px solid rgba(244,63,94,.3)}

/* TABLE */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{padding:8px 12px;text-align:left;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid rgba(30,30,46,.6);vertical-align:middle;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:rgba(168,85,247,.04)}
.host-chip{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;border:1px solid;background:rgba(168,85,247,.1);color:var(--accent);border-color:rgba(168,85,247,.3)}
.type-chip{display:inline-block;padding:1px 5px;border-radius:3px;font-size:10px;color:var(--muted);border:1px solid var(--border)}
.net-chip{display:inline-block;padding:1px 5px;border-radius:3px;font-size:9px;margin:1px;background:rgba(6,182,212,.1);color:var(--blue);border:1px solid rgba(6,182,212,.25)}
.svc-link{color:var(--blue);text-decoration:none}
.svc-link:hover{text-decoration:underline}
.dot-green{width:7px;height:7px;border-radius:50%;background:var(--green);display:inline-block;margin-right:5px}
.dot-red{width:7px;height:7px;border-radius:50%;background:var(--red);display:inline-block;margin-right:5px}
.dot-yellow{width:7px;height:7px;border-radius:50%;background:var(--yellow);display:inline-block;margin-right:5px}
.mem-txt{font-size:10px;color:var(--muted)}
.mig-row td{font-size:11px}
.mig-status-PENDING{color:var(--yellow)}
.mig-status-IN_PROGRESS{color:var(--blue)}
.mig-status-DONE{color:var(--green)}
.mig-status-FAILED{color:var(--red)}
.reason{color:var(--muted);font-size:10px;max-width:320px;white-space:normal;line-height:1.4}
.filter-bar{display:flex;gap:8px;padding:12px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center}
.filter-bar input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:4px;font-family:inherit;font-size:12px;outline:none;width:220px}
.filter-bar input:focus{border-color:var(--accent)}
.filter-bar select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:4px;font-family:inherit;font-size:12px;outline:none}
.count{color:var(--muted);font-size:11px;margin-left:auto}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">BLACK<span> SHEEP</span> LOCATOR</div>
    <div class="subtitle">SERVICE REGISTRY · LOAD BALANCER · TACTICAL GRID</div>
  </div>
  <div class="ts" id="clock"></div>
</header>
<main>

<!-- NODES -->
<section>
  <div class="sec-head"><span class="dot"></span>NODES</div>
  <div class="node-row" id="node-row"></div>
</section>

<!-- SERVICES GRID -->
<section>
  <div class="sec-head"><span class="dot"></span>TACTICAL GRID</div>
  <div class="filter-bar">
    <input id="srch" placeholder="filter by name, host, network..." oninput="renderGrid()">
    <select id="ftype" onchange="renderGrid()"><option value="">all types</option><option>container</option><option>web</option><option>service</option></select>
    <select id="fhost" onchange="renderGrid()"><option value="">all units</option></select>
    <span class="count" id="count"></span>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>NAME</th>
        <th>UNIT</th>
        <th>TYPE</th>
        <th>NETWORKS</th>
        <th>STATUS</th>
        <th>MEM</th>
        <th>URL</th>
        <th>LAST SEEN</th>
      </tr></thead>
      <tbody id="grid-body"></tbody>
    </table>
  </div>
</section>

<!-- MIGRATIONS -->
<section>
  <div class="sec-head"><span class="dot"></span>MIGRATION QUEUE</div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>ID</th><th>CONTAINER</th><th>FROM</th><th>TO</th>
        <th>STATUS</th><th>QUEUED</th><th>REASON</th>
      </tr></thead>
      <tbody id="mig-body"></tbody>
    </table>
  </div>
</section>

</main>

<script>
let _svcs = {}, _nodes = {}, _migs = [];

function ago(ts) {
  if (!ts) return '—';
  const s = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm';
  return Math.floor(s/3600) + 'h';
}
function pct_color(v) {
  if (v == null) return '#64748b';
  if (v > 90) return '#f43f5e';
  if (v > 70) return '#f59e0b';
  if (v > 40) return '#06b6d4';
  return '#22c55e';
}

function renderNodes() {
  const el = document.getElementById('node-row');
  el.innerHTML = Object.entries(_nodes).map(([id, n]) => {
    const stale = !n.last_metrics || (Date.now() - new Date(n.last_metrics)) > 300000;
    const oom   = (n.mem_percent||0) >= 90;
    const badge = stale ? 'stale' : (n.status === 'ONLINE' ? 'online' : 'offline');
    const bar   = (v, c) => `<div class="bar"><div class="bar-fill" style="width:${v||0}%;background:${c}"></div></div>`;
    const ip    = n.tailscale_ip || n.ip || '';
    return `<div class="node-card${oom?' oom':''}">
      <div class="node-name">${id}</div>
      <div class="node-ip">${ip} · ${n.disk_used_gb||0}/${n.disk_total_gb||0} GB</div>
      <span class="status-badge badge-${badge}">${badge.toUpperCase()}</span>
      <div class="metric-row"><span class="metric-label">CPU</span><span class="metric-val" style="color:${pct_color(n.cpu_percent)}">${(n.cpu_percent||0).toFixed(1)}%</span></div>
      ${bar(n.cpu_percent, pct_color(n.cpu_percent))}
      <div class="metric-row"><span class="metric-label">MEM</span><span class="metric-val" style="color:${pct_color(n.mem_percent)}">${(n.mem_percent||0).toFixed(1)}%</span></div>
      ${bar(n.mem_percent, pct_color(n.mem_percent))}
      <div class="metric-row"><span class="metric-label">DISK</span><span class="metric-val" style="color:${pct_color(n.disk_percent)}">${(n.disk_percent||0).toFixed(1)}%</span></div>
      ${bar(n.disk_percent, pct_color(n.disk_percent))}
    </div>`;
  }).join('') || '<div style="padding:16px;color:var(--muted)">no nodes registered</div>';

  // populate host filter
  const sel = document.getElementById('fhost');
  const cur = sel.value;
  sel.innerHTML = '<option value="">all units</option>' +
    Object.keys(_nodes).map(id => `<option${id===cur?' selected':''}>${id}</option>`).join('');
}

function renderGrid() {
  const srch  = document.getElementById('srch').value.toLowerCase();
  const ftype = document.getElementById('ftype').value;
  const fhost = document.getElementById('fhost').value;

  const rows = Object.entries(_svcs)
    .filter(([, s]) => {
      if (ftype && s.type !== ftype) return false;
      if (fhost && s.host !== fhost) return false;
      if (srch) {
        const nets = (s.metadata?.networks||[]).join(' ').toLowerCase();
        const haystack = [s.name, s.host, s.type, nets].join(' ').toLowerCase();
        if (!haystack.includes(srch)) return false;
      }
      return true;
    })
    .sort(([,a],[,b]) => (a.host+a.name).localeCompare(b.host+b.name));

  document.getElementById('count').textContent = rows.length + ' services';

  const body = document.getElementById('grid-body');
  body.innerHTML = rows.map(([, s]) => {
    const nets = (s.metadata?.networks || []);
    const netHtml = nets.length
      ? nets.map(n => `<span class="net-chip">${n}</span>`).join('')
      : '<span style="color:var(--muted)">—</span>';
    const mem = s.metadata?.mem_percent;
    const memHtml = mem != null ? `<span class="mem-txt" style="color:${pct_color(mem)}">${mem.toFixed(1)}%</span>` : '—';
    const dot = s.status === 'ONLINE' ? 'dot-green' : 'dot-red';
    const urlHtml = s.url ? `<a class="svc-link" href="${s.url}" target="_blank">${s.url.replace(/https?:\/\//,'')}</a>` : '—';
    return `<tr>
      <td title="${s.name||''}">${s.name||'—'}</td>
      <td><span class="host-chip">${s.host||'?'}</span></td>
      <td><span class="type-chip">${s.type||'?'}</span></td>
      <td>${netHtml}</td>
      <td><span class="${dot}"></span>${s.status||'?'}</td>
      <td>${memHtml}</td>
      <td>${urlHtml}</td>
      <td>${ago(s.last_seen)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:24px">no services</td></tr>';
}

function renderMigrations() {
  const body = document.getElementById('mig-body');
  const sorted = [..._migs].sort((a,b) => (b.queued_at||'').localeCompare(a.queued_at||'')).slice(0,50);
  body.innerHTML = sorted.map(m => `<tr class="mig-row">
    <td>${m.id}</td>
    <td>${m.container}</td>
    <td>${m.from_node}</td>
    <td>${m.to_node}</td>
    <td class="mig-status-${m.status}">${m.status}</td>
    <td>${ago(m.queued_at)}</td>
    <td class="reason">${m.reason||'—'}</td>
  </tr>`).join('') || '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:16px">no migrations</td></tr>';
}

async function refresh() {
  try {
    const [n, s, b] = await Promise.all([
      fetch('/api/nodes').then(r=>r.json()),
      fetch('/api/services').then(r=>r.json()),
      fetch('/api/balance/status').then(r=>r.json()),
    ]);
    _nodes = n;
    _svcs  = s;
    _migs  = b.migrations || [];
    renderNodes();
    renderGrid();
    renderMigrations();
  } catch(e) { console.error(e) }
}

setInterval(()=>{
  const d = new Date();
  document.getElementById('clock').textContent =
    d.toUTCString().replace('GMT','UTC');
}, 1000);

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(_UI)


# ── STARTUP ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[locator] starting on {UNIT_NAME} — BALANCE_DIFF={BALANCE_DIFF}% OOM={OOM_THRESHOLD}%")
    t = threading.Thread(target=_balancer_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, threaded=True)
