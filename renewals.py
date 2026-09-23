"""
renewals.py — the fleet's one credential-expiry authority.

THE RULE (fleet policy, 2026-08-30): every credential with an expiry — mTLS
leaves, API tokens, git tokens, TLS certs — is reissued SEVEN DAYS BEFORE it
expires. Not when it breaks, not when someone notices.

WHY IT LIVES IN THE LOCATOR
    The locator is already the only holder of the OpenBao broker token, already
    receives every unit's cert report, and already has a command queue into
    every node's lokey. Putting the rule anywhere else means each node deciding
    its own renewal policy in isolation — which is how you end up with the same
    rule implemented four times and wrong in three of them. Here it is one
    inventory, one threshold, one scheduler.

    Nodes still do the node-local work (write the file, reload the service),
    because only the node can. But they do it when told. The one exception is
    lokey's own safety net at 2 days, which exists solely so a locator outage
    cannot take the mesh down with it.

WHAT THE QUEUE MAY CARRY
    /api/commands/pending is UNAUTHENTICATED (see the note above
    _queue_exec_command). So a renewal command is only ever an instruction —
    "rotate now" — never key material. The node then fetches the new secret
    itself over the admin-key channel. Nothing secret is ever queued.

INVENTORY
    fleet-mtls     per-unit mesh leaves, expiry from /api/certs/report.
                   Renew: queue `rotate_mtls.py --force` on that unit.
    bao-broker     the locator's own OpenBao token. Renew: renew_self (the
                   existing bao_token_renewer does the routine renewals; this
                   is the audit that it is actually working).
    gitlab-pat     the PAT lokey pushes with. Renew: the GitLab self-rotate
                   API. DISABLED by default — see ROTATE_GITLAB below, the
                   redistribution half needs a policy change first.
    public-tls     Let's Encrypt hosts reported by lokey. Traefik renews these
                   itself at 30 days; anything still inside 7 days means that
                   renewal is FAILING, so this alerts rather than reissues.

Everything here fails soft and is idempotent: a renewal that cannot run is
logged and retried on the next pass, and a credential already renewed is simply
no longer due.
"""

import os
import threading
import time
from datetime import datetime, timezone

import requests

# The fleet rule. One number, one place.
RENEW_BEFORE_DAYS = int(os.environ.get("RENEW_BEFORE_DAYS", "7"))
RENEW_INTERVAL = int(os.environ.get("RENEW_INTERVAL", "3600"))      # hourly
RENEW_ENABLED = os.environ.get("RENEW_ENABLED", "true").lower() in ("1", "true", "yes")
# A renewal just queued needs time to run before we conclude it did not work.
RENEW_COOLDOWN = int(os.environ.get("RENEW_COOLDOWN", "7200"))

# GitLab PAT rotation is built but OFF: rotating the token is one API call, but
# the new value then has to reach every unit's git credential store, and the
# broker's OpenBao policy is READ-ONLY on secret/* today (locator-broker in
# setup-fleet-pki.sh). Rotating without a way to distribute would lock every
# unit out of git. Turn this on in the same change that grants the broker
# create/update on secret/data/gitlab/*.
ROTATE_GITLAB = os.environ.get("ROTATE_GITLAB", "false").lower() in ("1", "true", "yes")
GITLAB_HOST = os.environ.get("GITLAB_HOST", "gitlab.com")
# Where the PAT is filed in OpenBao KV-v2 — mount then path, the same split
# bao:// references parse into (bao.parse_ref).
GITLAB_KV_MOUNT = os.environ.get("GITLAB_KV_MOUNT", "secret")
GITLAB_KV_PATH = os.environ.get("GITLAB_KV_PATH", "gitlab/pat")

MESH_KINDS = ("haproxy-client", "traefik-mesh")

_last_action: dict = {}      # credential id -> unix ts of the last renewal we drove
_state: dict = {}            # credential id -> latest evaluation, for /api/renewals
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc)


def _log(msg):
    print(f"🔁 renewals: {msg}", flush=True)


def _cooling(cid):
    return (time.time() - _last_action.get(cid, 0)) < RENEW_COOLDOWN


def _mark(cid):
    _last_action[cid] = time.time()


def _days_left(iso):
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return int((exp - _now()).total_seconds() // 86400)
    except Exception:
        return None


# ── the inventory ───────────────────────────────────────────────────────────

def _mesh_items(cert_state):
    """Fleet mTLS leaves, one per (unit, cert), from what lokey last reported."""
    items = []
    for unit, info in (cert_state or {}).items():
        for c in info.get("certs") or []:
            if c.get("kind") not in MESH_KINDS:
                continue
            items.append({
                "id": f"mtls:{unit}:{c.get('host')}",
                "type": "fleet-mtls",
                "unit": unit,
                "name": c.get("host"),
                "days_left": c.get("days_left"),
                "error": c.get("error"),
                "renewable": True,
            })
    return items


def _public_tls_items(cert_state):
    """Public LE certs. Reported, never reissued from here — see module docs."""
    items = []
    for unit, info in (cert_state or {}).items():
        for c in info.get("certs") or []:
            if c.get("kind") in MESH_KINDS:
                continue
            items.append({
                "id": f"tls:{unit}:{c.get('host')}",
                "type": "public-tls",
                "unit": unit,
                "name": c.get("host"),
                "days_left": c.get("days_left"),
                "error": c.get("error"),
                "renewable": False,
            })
    return items


def _bao_items(bao):
    """The locator's own broker token."""
    try:
        st = bao.status()
    except Exception as e:
        return [{"id": "token:bao-broker", "type": "bao-broker", "unit": "locator",
                 "name": "OpenBao broker token", "days_left": None,
                 "error": f"status failed: {e}", "renewable": True}]
    ttl = st.get("token_ttl_seconds")
    return [{
        "id": "token:bao-broker",
        "type": "bao-broker",
        "unit": "locator",
        "name": "OpenBao broker token",
        "days_left": None if ttl is None else int(ttl // 86400),
        "error": None if st.get("token_ok") else "token not usable",
        "renewable": True,
    }]


def _gitlab_token():
    """The PAT, from OpenBao if it is stored there. Returns '' when absent."""
    try:
        import bao
        return (bao.read_secret(GITLAB_KV_MOUNT, GITLAB_KV_PATH) or {}).get("token", "").strip()
    except Exception:
        return ""


def _gitlab_items():
    token = _gitlab_token()
    if not token:
        return []
    try:
        r = requests.get(f"https://{GITLAB_HOST}/api/v4/personal_access_tokens/self",
                         headers={"PRIVATE-TOKEN": token}, timeout=20)
        d = r.json() if r.status_code == 200 else {}
    except Exception as e:
        return [{"id": "token:gitlab-pat", "type": "gitlab-pat", "unit": "locator",
                 "name": "GitLab PAT", "days_left": None,
                 "error": str(e)[:120], "renewable": ROTATE_GITLAB}]
    exp = d.get("expires_at")
    days = None
    if exp:
        try:
            days = int((datetime.fromisoformat(exp).replace(tzinfo=timezone.utc)
                        - _now()).total_seconds() // 86400)
        except Exception:
            days = None
    return [{
        "id": "token:gitlab-pat",
        "type": "gitlab-pat",
        "unit": "locator",
        "name": f"GitLab PAT '{d.get('name')}'",
        "days_left": days,
        "error": None if d.get("active") else "token inactive or revoked",
        "renewable": ROTATE_GITLAB and "self_rotate" in (d.get("scopes") or []),
    }]


def inventory(cert_state, bao):
    """Every credential the fleet knows the expiry of. Renews nothing."""
    items = []
    items += _mesh_items(cert_state)
    items += _public_tls_items(cert_state)
    items += _bao_items(bao)
    items += _gitlab_items()
    for it in items:
        d = it.get("days_left")
        it["due"] = bool(it.get("error")) or (d is not None and d <= RENEW_BEFORE_DAYS)
    return items


# ── the renewals ────────────────────────────────────────────────────────────

def _renew_mesh(item, queue_exec):
    """Tell that unit's lokey to re-mint. The command carries no key material —
    lokey fetches the new leaf itself from /api/certs/issue."""
    queue_exec(
        item["unit"],
        "docker exec lokey python /app/rotate_mtls.py --force",
        source="renewals",
        label=f"rotate mTLS ({item['name']})",
    )
    return True


def _renew_bao(item, bao):
    try:
        bao.renew_self()
        return True
    except Exception as e:
        _log(f"broker token renew failed: {e}")
        return False


def _renew_gitlab(item):
    """Self-rotate the PAT and store the replacement in OpenBao.

    Both halves or neither: if the write back to OpenBao fails after GitLab has
    already issued the replacement, the old token is ALREADY dead and the new
    one is only in this function's memory — so it is logged as critical and the
    caller must not treat it as a success.
    """
    import bao
    token = _gitlab_token()
    if not token:
        return False
    expires = (_now().date().replace(year=_now().year + 1)).isoformat()
    r = requests.post(
        f"https://{GITLAB_HOST}/api/v4/personal_access_tokens/self/rotate",
        headers={"PRIVATE-TOKEN": token}, json={"expires_at": expires}, timeout=30)
    if r.status_code not in (200, 201):
        _log(f"gitlab rotate refused: HTTP {r.status_code} {r.text[:160]}")
        return False
    new = (r.json() or {}).get("token")
    if not new:
        _log("gitlab rotate returned no token")
        return False
    try:
        bao.write_secret(GITLAB_KV_MOUNT, GITLAB_KV_PATH,
                         {"token": new, "expires_at": expires})
        import vaultwarden
        vaultwarden.mirror("gitlab/pat", {"token": new},
                           notes=f"gitlab PAT rotated by locator, expires {expires}")
    except Exception as e:
        _log(f"🚨 CRITICAL: GitLab PAT was rotated but could NOT be stored "
             f"({e}). The old token is dead. Re-issue by hand now.")
        return False
    _log(f"gitlab PAT rotated, now valid to {expires}")
    return True


def run_once(cert_state, bao, queue_exec):
    """One pass: evaluate everything, renew what is due. Never raises."""
    items = inventory(cert_state, bao)
    with _lock:
        _state.clear()
        _state.update({it["id"]: it for it in items})

    for it in items:
        if not it["due"]:
            continue
        d = it.get("days_left")
        why = it.get("error") or f"{d}d left (rule: {RENEW_BEFORE_DAYS}d)"
        if not it["renewable"]:
            _log(f"⚠️  {it['type']} {it['name']} on {it['unit']}: {why} — "
                 f"NOT auto-renewable, needs a human")
            continue
        if _cooling(it["id"]):
            continue
        _log(f"{it['type']} {it['name']} on {it['unit']} is due: {why} — renewing")
        try:
            if it["type"] == "fleet-mtls":
                ok = _renew_mesh(it, queue_exec)
            elif it["type"] == "bao-broker":
                ok = _renew_bao(it, bao)
            elif it["type"] == "gitlab-pat":
                ok = _renew_gitlab(it)
            else:
                ok = False
        except Exception as e:
            _log(f"{it['id']} renewal errored: {e}")
            ok = False
        if ok:
            _mark(it["id"])
    return items


def snapshot():
    """Last evaluation, for /api/renewals."""
    with _lock:
        items = sorted(_state.values(),
                       key=lambda i: (i.get("days_left") is None, i.get("days_left") or 0))
    return {
        "enabled": RENEW_ENABLED,
        "renew_before_days": RENEW_BEFORE_DAYS,
        "interval_seconds": RENEW_INTERVAL,
        "due": [i for i in items if i.get("due")],
        "credentials": items,
    }


def worker(cert_state_getter, bao, queue_exec):
    """Background thread body. Wired up in locator.py's worker list."""
    if not RENEW_ENABLED:
        _log("disabled (RENEW_ENABLED=false)")
        return
    _log(f"credential renewal active — reissue at {RENEW_BEFORE_DAYS} days "
         f"remaining, checked every {RENEW_INTERVAL}s")
    # Let the units report in first; an empty inventory on a cold start would
    # otherwise just be a wasted pass.
    time.sleep(90)
    while True:
        try:
            run_once(cert_state_getter(), bao, queue_exec)
        except Exception as e:
            _log(f"pass failed: {e}")
        time.sleep(RENEW_INTERVAL)
