"""OpenBao secrets broker for the Locator.

WHY THIS EXISTS
---------------
locator.yml carries an `env:` block whose values are pushed to target units and
merged into their compose `.env` (see enforce_unit_placement + lokey's
_merge_env_file). Those values used to be literals, which meant every secret the
fleet needed sat in plaintext in a git-tracked file that is ALSO editable from
the dashboard's YAMLs tab. This module lets locator.yml hold *references*
instead, and makes locator the single holder of the OpenBao token.

REFERENCE SYNTAX
----------------
    KEY: bao://<mount>/<path>#<field>      -> KEY = that field's value
    _bao_import_<n>: bao://<mount>/<path>  -> every field of that secret,
                                              key-name upper-cased, merged in

Anything not starting with "bao://" is passed through untouched, so mixed
literal/reference blocks work and nothing that exists today changes behaviour.

FAIL-LOUD CONTRACT
------------------
A missing path, a missing field, an empty value, a sealed OpenBao or an expired
token all raise BaoError. Callers MUST drop the whole deploy rather than seed a
partial .env: a blank secret does not fail visibly, it fails days later as an
"unauthorized_client" nobody can trace. That lesson came from the reech client
secret drifting by one character. Same rule here.

WHY THE VALUES ARE NEVER PUSHED IN A COMMAND PAYLOAD
----------------------------------------------------
/api/commands/pending is unauthenticated by design (lokey heartbeats predate
the admin key) and Traefik's locator-api router deliberately bypasses Keycloak
for /api/. Anything placed in a queued command is world-readable. So deploy
commands carry only the bao:// REFERENCE, and lokey exchanges it for the value
against /api/secrets/resolve using LOCATOR_ADMIN_KEY.
"""

import os
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import json

BAO_ADDR = os.environ.get("BAO_ADDR", "http://100.99.131.20:8200").rstrip("/")
BAO_TOKEN_FILE = os.environ.get("BAO_TOKEN_FILE", "/app/secrets/bao.token")
# PKI engine that issues the fleet's internal mTLS certs (Blacksheep Fleet Root
# CA). A mount only, never a role: the role names the constraints (allowed
# domains, max TTL, whether it may sign client vs server certs) and is chosen
# per call, so one broker token can issue against several roles.
BAO_PKI_MOUNT = os.environ.get("BAO_PKI_MOUNT", "pki").strip("/")
BAO_CACHE_TTL = int(os.environ.get("BAO_CACHE_TTL", "300"))
BAO_TIMEOUT = int(os.environ.get("BAO_TIMEOUT", "10"))

PREFIX = "bao://"
IMPORT_KEY_PREFIX = "_bao_import"


class BaoError(RuntimeError):
    """Any failure to produce a real value. Never swallowed into a blank."""


_cache = {}            # "mount/path" -> (expires_at, {field: value})
_cache_lock = threading.Lock()
_token_cache = {"value": None, "mtime": None}


def _token():
    """Read the broker token, re-reading only when the file changes on disk.

    Kept out of the environment on purpose: a token in os.environ shows up in
    `docker inspect` for anyone on the host, and locator's compose file is
    committed to git.
    """
    env_token = os.environ.get("BAO_TOKEN", "").strip()
    if env_token:
        return env_token
    try:
        mtime = os.path.getmtime(BAO_TOKEN_FILE)
    except OSError as e:
        raise BaoError(f"no OpenBao token at {BAO_TOKEN_FILE}: {e}")
    if _token_cache["mtime"] != mtime:
        try:
            with open(BAO_TOKEN_FILE) as f:
                _token_cache["value"] = f.read().strip()
        except OSError as e:
            raise BaoError(f"cannot read {BAO_TOKEN_FILE}: {e}")
        _token_cache["mtime"] = mtime
    if not _token_cache["value"]:
        raise BaoError(f"{BAO_TOKEN_FILE} is empty")
    return _token_cache["value"]


def _request(path, method="GET", body=None):
    url = f"{BAO_ADDR}/v1/{path.lstrip('/')}"
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
    req = urllib.request.Request(url, data=payload, method=method)
    req.add_header("X-Vault-Token", _token())
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=BAO_TIMEOUT) as resp:
            raw = resp.read().decode()
            # A 204 with no body is a successful write, not a parse failure.
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        # 403 here is almost always the broker policy missing a path, not a bad
        # token — say so, because the two look identical in a stack trace.
        raise BaoError(f"OpenBao {e.code} for {path}: {body}")
    except urllib.error.URLError as e:
        raise BaoError(f"cannot reach OpenBao at {BAO_ADDR}: {e.reason}")
    except Exception as e:
        raise BaoError(f"OpenBao request to {path} failed: {e}")


def parse_ref(ref):
    """'bao://secret/reech#client_secret' -> ('secret', 'reech', 'client_secret').

    The field is optional (import form). The mount is the first segment; the
    rest is the secret path, so nested paths like secret/apps/reech work.
    """
    if not isinstance(ref, str) or not ref.startswith(PREFIX):
        raise BaoError(f"not an OpenBao reference: {ref!r}")
    rest = ref[len(PREFIX):]
    body, _, field = rest.partition("#")
    body = body.strip("/")
    if not body:
        raise BaoError(f"reference has no path: {ref!r}")
    parts = body.split("/")
    if len(parts) < 2:
        raise BaoError(
            f"reference {ref!r} needs <mount>/<path> (e.g. bao://secret/reech#client_secret)")
    return parts[0], "/".join(parts[1:]), (field.strip() or None)


def read_secret(mount, path, use_cache=True):
    """All fields of one KV-v2 secret, TTL-cached.

    Cached because a fleet-wide placement sweep resolves the same handful of
    secrets once per service per unit; without this a rebalance would hammer
    OpenBao with hundreds of identical reads a minute.
    """
    ck = f"{mount}/{path}"
    now = time.time()
    if use_cache:
        with _cache_lock:
            hit = _cache.get(ck)
            if hit and hit[0] > now:
                return hit[1]
    quoted = urllib.parse.quote(path, safe="/")
    resp = _request(f"{mount}/data/{quoted}")
    if resp.get("errors"):
        raise BaoError(f"OpenBao error for {ck}: {resp['errors']}")
    try:
        data = resp["data"]["data"]
    except (KeyError, TypeError):
        # A KV-v1 mount answers with a flat .data and no nesting. Saying which
        # is which beats a bare KeyError three layers down.
        raise BaoError(
            f"{ck} did not return KV-v2 data (is the mount KV v1?)")
    if not isinstance(data, dict):
        raise BaoError(f"{ck} returned {type(data).__name__}, expected a mapping")
    with _cache_lock:
        _cache[ck] = (now + BAO_CACHE_TTL, data)
    return data


def resolve_ref(ref, use_cache=True):
    """One reference -> one non-empty string value."""
    mount, path, field = parse_ref(ref)
    if not field:
        raise BaoError(
            f"{ref!r} names no field; use bao://{mount}/{path}#<field> "
            f"or the _bao_import form to pull every field")
    data = read_secret(mount, path, use_cache=use_cache)
    if field not in data:
        raise BaoError(
            f"field {field!r} not in {mount}/{path} "
            f"(has: {', '.join(sorted(data)) or 'nothing'})")
    value = data[field]
    if value is None or str(value) == "":
        raise BaoError(f"{mount}/{path}#{field} is empty — refusing to seed a blank")
    return str(value)


def is_ref(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def has_refs(env_map):
    """True if anything in this env block needs OpenBao at all."""
    if not isinstance(env_map, dict):
        return False
    return any(is_ref(v) for v in env_map.values())


def resolve_env_map(env_map, use_cache=True):
    """Resolve a locator.yml env block. Returns (resolved_map, [refs_used]).

    Non-reference values pass through untouched, so a block may mix literals
    (INGEST_PORT: "8080") with references and behave exactly as before for the
    literal half.
    """
    if not isinstance(env_map, dict):
        return {}, []
    out, used = {}, []
    for key, value in env_map.items():
        skey = str(key)
        if skey.startswith(IMPORT_KEY_PREFIX) and is_ref(value):
            mount, path, field = parse_ref(value)
            if field:
                raise BaoError(
                    f"{skey} imports a whole secret; drop the '#{field}' from {value!r}")
            data = read_secret(mount, path, use_cache=use_cache)
            if not data:
                raise BaoError(f"{mount}/{path} is empty — nothing to import")
            for k, v in data.items():
                if v is None or str(v) == "":
                    raise BaoError(
                        f"{mount}/{path}#{k} is empty — refusing to seed a blank")
                out[str(k).upper()] = str(v)
            used.append(value)
            continue
        if is_ref(value):
            out[skey] = resolve_ref(value, use_cache=use_cache)
            used.append(value)
        else:
            out[skey] = str(value)
    return out, used


def invalidate(prefix=None):
    """Drop cached secrets. Called after a rotation so the next deploy is fresh."""
    with _cache_lock:
        if prefix is None:
            n = len(_cache)
            _cache.clear()
            return n
        doomed = [k for k in _cache if k.startswith(prefix)]
        for k in doomed:
            del _cache[k]
        return len(doomed)


def status():
    """Broker health for the dashboard. Deliberately carries NO secret values."""
    out = {
        "addr": BAO_ADDR,
        "token_file": BAO_TOKEN_FILE,
        "cache_ttl_seconds": BAO_CACHE_TTL,
        "reachable": False,
        "sealed": None,
        "token_ok": False,
        "configured": False,
    }
    with _cache_lock:
        out["cached_secrets"] = len(_cache)
    # Health needs no token, so an unconfigured broker still reports the server.
    try:
        req = urllib.request.Request(f"{BAO_ADDR}/v1/sys/health")
        try:
            with urllib.request.urlopen(req, timeout=BAO_TIMEOUT) as resp:
                health = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            # /sys/health signals state through the STATUS CODE and still
            # returns a body: 503 sealed, 501 uninitialised, 429/472/473
            # standby. urlopen raises on all of those, so catching only the
            # happy path reported a sealed vault as unreachable — sending the
            # operator after a network fault when the body already said
            # "sealed": true. The server answered; that is reachable.
            body = e.read().decode() or "{}"
            try:
                health = json.loads(body)
            except ValueError:
                raise
        out["reachable"] = True
        out["sealed"] = bool(health.get("sealed"))
        out["version"] = health.get("version")
    except Exception as e:
        out["error"] = f"health check failed: {e}"
        return out
    try:
        out["configured"] = bool(_token())
    except BaoError as e:
        out["error"] = str(e)
        return out
    try:
        info = _request("auth/token/lookup-self")["data"]
        out["token_ok"] = True
        out["token_ttl_seconds"] = info.get("ttl")
        out["token_renewable"] = info.get("renewable")
        out["token_policies"] = info.get("policies")
        out["token_display_name"] = info.get("display_name")
    except BaoError as e:
        out["error"] = str(e)
    return out


def renew_self():
    """Extend the broker token's lease. A periodic token dies silently at TTL."""
    resp = _request("auth/token/renew-self", method="POST")
    return (resp.get("auth") or {}).get("lease_duration")


def write_secret(mount, path, data, merge=True):
    """Store fields into a KV-v2 secret, merging with what is already there.

    merge=True is the default because quarantining one compose file must not
    wipe fields an earlier sweep already filed under the same path. A write
    that silently dropped a sibling service's password would be the exact
    failure this whole module exists to prevent.
    """
    if not isinstance(data, dict) or not data:
        raise BaoError(f"nothing to write to {mount}/{path}")
    for k, v in data.items():
        if v is None or str(v) == "":
            raise BaoError(f"refusing to store an empty value for {k}")
    payload = dict(data)
    if merge:
        try:
            existing = read_secret(mount, path, use_cache=False)
            payload = {**existing, **data}
        except BaoError:
            # Nothing there yet (404) — a first write is the normal case.
            pass
    quoted = urllib.parse.quote(path, safe="/")
    resp = _request(f"{mount}/data/{quoted}", method="POST",
                    body={"data": {str(k): str(v) for k, v in payload.items()}})
    if resp.get("errors"):
        raise BaoError(f"write to {mount}/{path} failed: {resp['errors']}")
    invalidate(f"{mount}/{path}")
    return sorted(data)


def issue_cert(role, common_name, alt_names=None, ip_sans=None, ttl=None,
               mount=None):
    """Issue a leaf cert+key from the fleet PKI. Never cached.

    A cert is minted fresh every time on purpose — unlike a KV secret there is
    no stable value to cache, and the private key must never be reused across
    two issuances. Returns the OpenBao PKI `issue` payload as-is:

        certificate, private_key, issuing_ca, ca_chain (list),
        serial_number, expiration (unix seconds)

    `role` decides what may be signed. The HAProxy edge presents a *client*
    cert to the Traefik mesh, and each Traefik mesh entrypoint presents a
    *server* cert; those are two roles with different `client_flag`/
    `server_flag`, so the caller must name the right one — issuing a client
    cert against the server role yields a cert Traefik will reject at the mesh
    handshake, which looks like a network fault three hops away.

    Raises BaoError on any failure (sealed vault, missing role, a CN the role's
    allowed_domains forbids) so the caller drops the deploy rather than wiring
    up a half-issued identity.
    """
    role = (role or "").strip()
    common_name = (common_name or "").strip()
    if not role:
        raise BaoError("issue_cert needs a role")
    if not common_name:
        raise BaoError("issue_cert needs a common_name")
    body = {"common_name": common_name}
    # PKI wants comma-joined strings, not JSON lists.
    if alt_names:
        body["alt_names"] = ",".join(alt_names) if isinstance(alt_names, (list, tuple)) else str(alt_names)
    if ip_sans:
        body["ip_sans"] = ",".join(ip_sans) if isinstance(ip_sans, (list, tuple)) else str(ip_sans)
    if ttl:
        body["ttl"] = str(ttl)
    pki = (mount or BAO_PKI_MOUNT).strip("/")
    resp = _request(f"{pki}/issue/{urllib.parse.quote(role, safe='')}",
                    method="POST", body=body)
    if resp.get("errors"):
        raise BaoError(f"PKI issue against {pki}/{role} failed: {resp['errors']}")
    data = resp.get("data") or {}
    if not data.get("certificate") or not data.get("private_key"):
        raise BaoError(
            f"PKI issue against {pki}/{role} returned no cert/key "
            f"(got: {', '.join(sorted(data)) or 'nothing'})")
    return data
