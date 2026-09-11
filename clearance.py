"""
═══════════════════════════════════════════════
  CLEARANCE — level 1..10 access control
═══════════════════════════════════════════════

Every principal that touches the Locator carries a clearance level from 10
(root/owner) down to 1 (guest). The level arrives as a claim on the Keycloak
access token; Keycloak in turn reads it out of FreeIPA over LDAP federation
(see docs/CLEARANCE.md). Nothing here talks to FreeIPA directly — the token is
the only thing this process trusts.

Four enforcement layers, all applied server-side:

  1. Per-endpoint minimum   — ROUTE_CLEARANCE, enforced in a before_request
  2. Row-level filtering    — filter_services() / filter_nodes()
  3. Field redaction        — redact_service() / redact_node()
  4. UI view visibility     — /api/whoami tells the dashboard what to render

Layer 4 is cosmetic on its own; it exists so the UI doesn't offer buttons that
layers 1-3 will refuse. The dashboard's old CSS gate hid the DOM but left every
API route open to `curl`, which is the hole this module closes.
"""

import os
import time
import threading
import fnmatch

from flask import request, jsonify, g

# ── LEVELS ──────────────────────────────────────────────────────────────────
# 10 is the most privileged. Names are advisory (they show in /api/whoami and
# in denial messages); the integer is what everything actually compares on.

ROOT       = 10   # owner — exec, shell, unrestricted
INFRA      = 9    # infrastructure admin — deploy, YAML writes, migrations
OPERATOR   = 8    # start/stop containers, trigger deploys
ENGINEER   = 7    # read compose/YAML, see SSH targets
STAFF      = 6    # full mesh read: every service, every node, internal IPs
PARTNER    = 5    # full service list, internal addressing redacted
CONTRACTOR = 4    # own tenant + services shared with it
CLIENT     = 3    # own tenant only
CUSTOMER   = 2    # own tenant, heavy redaction
GUEST      = 1    # liveness only

LEVEL_NAMES = {
    10: "root", 9: "infra", 8: "operator", 7: "engineer", 6: "staff",
    5: "partner", 4: "contractor", 3: "client", 2: "customer", 1: "guest",
}

# Anonymous. Not a valid clearance — it only satisfies routes listed as PUBLIC.
ANON = 0

# At or above this level a principal sees the whole mesh. Below it, row-level
# filtering restricts them to their own tenant.
SEES_ALL_ROWS = STAFF

# ── CONFIG ──────────────────────────────────────────────────────────────────

OIDC_ISSUER = os.environ.get(
    "OIDC_ISSUER", "https://bsco-keycloak.fly.dev/realms/blacksheep"
).rstrip("/")
# Accepted client(s). Comma-separated: the dashboard signs in as `locator`,
# but the client portal signs in as `client-portal`, and its admin box calls
# these same routes. Both are clients of the same realm, so the token is still
# signature- and issuer-verified — this only widens *which* client may present
# it, not who may act.
OIDC_AUDIENCES  = [a.strip() for a in
                   os.environ.get("OIDC_AUDIENCE", "locator,client-portal").split(",")
                   if a.strip()]
OIDC_AUDIENCE   = OIDC_AUDIENCES[0]
CLEARANCE_CLAIM = os.environ.get("CLEARANCE_CLAIM", "clearance")
TENANT_CLAIM    = os.environ.get("TENANT_CLAIM", "tenant")

# Master switch. Off by default so this module can be merged and deployed
# before Keycloak/FreeIPA are actually emitting the claim — flipping it on is
# the cutover. With it off, everything runs exactly as it did before.
ENFORCE = os.environ.get("CLEARANCE_ENFORCE", "false").lower() in ("1", "true", "yes")

# Machine agents (lokey, locatorctl, the unit agents) authenticate with the
# pre-existing shared key rather than an OIDC token. They are trusted at ROOT
# because that key already gated /api/exec, which is strictly more dangerous
# than anything else here.
ADMIN_KEY = os.environ.get("LOCATOR_ADMIN_KEY", "")

# Level 9 (INFRA) identity for the AI assistant, presented as X-Locator-AI-Key.
# Deliberately NOT the same secret as LOCATOR_ADMIN_KEY: that one mints ROOT and
# is the human owner's. INFRA already excludes exec/shell (ROOT-only), and the
# AI_DENIED_ENDPOINTS list below removes the destructive routes INFRA would
# otherwise reach.
AI_ADMIN_KEY = os.environ.get("LOCATOR_AI_ADMIN_KEY", "")

# Endpoints the AI service account may never call, whatever its level and
# whatever ENFORCE says. Destroying state is a human decision.
#
# This is a guardrail on our OWN automation, not a security boundary: while
# CLEARANCE_ENFORCE is off an unauthenticated caller can still reach these
# routes. What it guarantees is that an automated caller holding the AI key
# cannot delete something without a human doing it instead.
# Every identity the AI assistant can present. The static key is one of them;
# the Keycloak service account `ai-admin` (realm role clearance-9) is the other
# and arrives as via="oidc", so keying the deny on via alone silently exempted
# it — the guarantee has to follow the ACTOR, not the transport.
AI_PRINCIPAL_NAMES = frozenset({"service:ai-admin", "service-account-ai-admin"})


def is_ai_principal(principal):
    """True for any identity belonging to the AI assistant."""
    return (principal.via == "ai-admin-key"
            or principal.name in AI_PRINCIPAL_NAMES)


AI_DENIED_ENDPOINTS = frozenset({
    "delete_compose_file",   # DELETE /api/compose/<name>
    "secrets_quarantine",    # rewrites compose files on other units
    "delete_schedule",       # DELETE /api/schedule/<job_id>
    "deregister_service",    # DELETE /deregister/<name>
    "queue_exec", "exec",    # ROOT already, listed so the denial is explicit
    "admin_set_clearance",   # granting privilege is never automated
    "admin_pending_users",
})

# Heartbeats arrive from agents that may not carry the admin key yet. Leaving
# this false keeps /register and the node/metric push open, exactly as today,
# so turning ENFORCE on does not silently black-hole the mesh's telemetry.
# Flip it once every agent ships a key.
ENFORCE_INGEST = os.environ.get("CLEARANCE_ENFORCE_INGEST", "false").lower() in ("1", "true", "yes")

# ── ROUTE POLICY ────────────────────────────────────────────────────────────
# Keyed by Flask endpoint (the view function's name), which is stable and
# exact — unlike path matching, it cannot be fooled by a trailing slash or a
# path parameter. Anything not listed here is denied outright when ENFORCE is
# on: the policy fails closed, so a newly added route is unreachable until
# somebody makes a deliberate decision about it.

PUBLIC = {
    # Liveness and the SSO plumbing itself must answer before there is a token.
    "health_check",
    "silent_check_sso",
    "index",              # shell HTML only; every byte of data on it is fetched
                          # through the gated /api/* routes below
    "static",             # Flask's built-in static file server
    "whoami",             # tells the caller what it is; safe pre-auth
    "report_client_error",
    # Broker liveness. Values are never in this response, only reachable /
    # sealed / configured / token_ok — and it has to answer before a caller
    # can be told why a deploy failed.
    "secrets_status",
    # Click-to-wake. The 502 from an idle-stopped service reaches somebody who
    # holds no token and has no way to get one — the login is often behind the
    # service that is asleep — so this has to answer pre-auth or wake-on-request
    # is unreachable from a browser, which is what it had become. It is NOT
    # open: wake_page checks PUBLIC_WAKE per container and 403s anything nobody
    # opted in, and what an anonymous caller can then do is one verb — queue a
    # `start` for a container already in the registry. No registry data comes
    # back in the response.
    "wake_page",
    # The trigger map that tells a page WHICH container its link should wake.
    # Public for the same reason wake_page is: the caller is an anonymous
    # browser that has just been handed a 502. It lists only containers already
    # carrying public_wake, and only a hostname the visitor just typed against
    # the container name they are already allowed to wake — no registry record,
    # no addressing, nothing that is not public by construction.
    "wake_triggers",
}

# Ingest endpoints — written to by unattended agents. Gated by ENFORCE_INGEST
# rather than by clearance, since agents carry a shared key, not a user token.
INGEST = {
    "register_service",
    "update_nodes",
    "update_node_metrics",
    "idle_report",
    # Read by lokey on the same tick as idle_report; if this were left
    # unlisted, turning ENFORCE on would 403 it and idle-stop would quietly
    # stop working with no other symptom.
    "idle_policy",
    "commands_pending",
    "get_policy_for_unit",
    "commands_complete",
    "certs_report",
    "get_pending_migrations",
    "claim_migration",
    "complete_migration",
}

ROUTE_CLEARANCE = {
    # ── Read: registry surface ──────────────────────────────────────────
    # Low bar to reach, because what comes back is filtered per-tenant and
    # redacted per-level by layers 2 and 3. A level-2 customer hitting
    # /api/registry gets their own services with the addressing stripped.
    "get_full_registry":     CUSTOMER,
    "get_services":          CUSTOMER,
    "get_service":           CUSTOMER,
    "get_nodes":             CUSTOMER,
    "download_registry":     CUSTOMER,
    # Edge proxies poll this for live upstreams; same bar as the registry
    # reads it derives from.
    "traefik_service":       CUSTOMER,
    "traefik_all_services":  CUSTOMER,

    # ── Read: operational telemetry ─────────────────────────────────────
    "list_events_route":     CLIENT,
    "stream_events":         CLIENT,
    "election_status":       PARTNER,
    "balance_status":        PARTNER,
    "idle_status":           PARTNER,
    "certs_status":          PARTNER,
    # Expiry metadata for every tracked credential — never a value. Reads
    # like certs_status, so it sits with it; the renewal ACTION is a
    # worker, and minting still goes through certs_issue at ROOT.
    "renewals_status":       PARTNER,
    "dns_status":            ENGINEER,
    "list_migrations":       PARTNER,
    # Fleet refresh — status/history read like the other operational telemetry;
    # triggering one redeploys across the fleet, so that sits with the deploys.
    "refresh_status":        PARTNER,
    "refresh_runs":          PARTNER,
    "traccar_devices":       STAFF,     # live physical positions of people
    "get_available_networks": STAFF,
    "service_networks":      STAFF,
    "list_client_errors":    STAFF,
    "mesh_3d":               CLIENT,
    "register_device_page":  CLIENT,
    "register_device_qr":    CLIENT,
    # wake_page moved to PUBLIC — see the note there. The gate is now
    # per-container inside the handler rather than blanket per-route.

    # ── Read: configuration ─────────────────────────────────────────────
    # Compose files and YAML carry env vars, volume paths and credentials.
    "list_compose_files":    ENGINEER,
    "get_compose_file":      ENGINEER,
    "list_yamls":            ENGINEER,
    # Reading WHICH credentials exist and where — never their values.
    "secrets_refs":          ENGINEER,
    "secrets_scan":          ENGINEER,
    "get_yaml":              ENGINEER,
    "get_policy":            ENGINEER,
    "get_policy_locked":     ENGINEER,
    "list_schedule":         ENGINEER,
    "list_commands":         ENGINEER,
    "get_command":           ENGINEER,

    # ── Write: runtime control ──────────────────────────────────────────
    "toggle_container":      OPERATOR,
    "idle_wake":             OPERATOR,
    "shutdown_container":    OPERATOR,
    "trigger_browse":        OPERATOR,
    "deregister_service":    OPERATOR,

    # ── Write: configuration and deployment ─────────────────────────────
    "save_compose_file":     INFRA,
    "delete_compose_file":   INFRA,
    "save_yaml":             INFRA,
    "set_policy":            INFRA,
    "set_policy_bulk":       INFRA,
    "deploy_compose":        INFRA,
    "trigger_deploy_final":  INFRA,
    "refresh_run_now":       INFRA,
    "create_migration":      INFRA,
    "dns_sync":              INFRA,
    "create_schedule":       INFRA,
    "delete_schedule":       INFRA,
    "toggle_schedule":       INFRA,

    # ── Root: arbitrary code execution ──────────────────────────────────
    "queue_exec":            ROOT,
    # resolve hands back real secret VALUES (lokey trades a bao:// ref for
    # one using the admin key). quarantine rewrites live compose files on
    # other units. Both are owner-level, never delegated.
    "secrets_resolve":       ROOT,
    "secrets_refresh":       ROOT,
    # Mints a leaf cert from the OpenBao PKI via the locator broker. That is
    # credential issuance, so it sits with secrets_refresh at ROOT rather than
    # INFRA — the AI service account must not be able to mint fleet identities.
    # Was the ONLY route in the app with no policy entry, which under the
    # fail-closed rule would have made it 403 the moment ENFORCE went true.
    "certs_issue":           ROOT,
    "secrets_quarantine":    ROOT,

    # ── Root: identity administration ───────────────────────────────────
    # Lists accounts and grants clearance levels. Whoever can reach these can
    # promote themselves, so it sits at the same level as arbitrary exec.
    "admin_pending_users":   ROOT,
    "admin_set_clearance":   ROOT,
}

# Dashboard views, for layer 4. Keys match switchView()'s argument.
VIEW_CLEARANCE = {
    "grid":    CUSTOMER,
    "map":     CLIENT,
    "3js":     CLIENT,
    "traccar": STAFF,
    "yamls":   ENGINEER,
    "exec":    ROOT,
}

# ── FIELD REDACTION ─────────────────────────────────────────────────────────
# Minimum level required to see each field. Anything not named here is
# considered non-sensitive and always passes. Patterns are fnmatch globs so
# that e.g. every *_ip variant is covered without listing each one.

FIELD_MIN_LEVEL = [
    # Internal addressing — the reason the registry is not public in the first
    # place. A partner needs to know a service exists and is up; they do not
    # need its tailnet address.
    ("internal",        STAFF),
    ("ip",              STAFF),
    ("*_ip",            STAFF),      # public_ip, vpn_ip, tailscale_ip, ...
    ("ips",             STAFF),
    ("addr*",           STAFF),
    ("port",            PARTNER),
    ("hosts",           PARTNER),
    ("host",            PARTNER),

    # Access paths.
    ("ssh*",            ENGINEER),
    ("*_ssh",           ENGINEER),
    ("compose*",        ENGINEER),
    ("env",             ENGINEER),
    ("volumes",         ENGINEER),
    ("labels",          ENGINEER),
    ("prereqs",         ENGINEER),
    ("depends_on",      CONTRACTOR),

    # Physical/personal telemetry from self-registered devices.
    ("lat*",            STAFF),
    ("lon*",            STAFF),
    ("location",        STAFF),
    ("gps*",            STAFF),
    ("battery*",        CONTRACTOR),
    ("peripherals",     STAFF),
]

# metadata is a free-form bag written by whatever registered the service, so it
# cannot be whitelisted field-by-field with any confidence. Below STAFF only
# these keys survive; everything else in the bag is dropped.
METADATA_SAFE_KEYS = {"platform", "version", "model", "os", "arch", "uptime"}


def _field_min(key):
    """Lowest clearance that may see `key`. 0 when the field is never sensitive."""
    low = key.lower()
    for pattern, level in FIELD_MIN_LEVEL:
        if fnmatch.fnmatch(low, pattern):
            return level
    return 0


# ── TOKEN VERIFICATION ──────────────────────────────────────────────────────
# JWKS is fetched from the issuer and cached. A token whose `kid` is unknown
# forces one refetch (that is what a Keycloak key rotation looks like from
# here), rate-limited so a bogus kid cannot be used to hammer the IdP.

_jwks_cache = {"keys": {}, "fetched": 0.0}
_jwks_lock = threading.Lock()
_JWKS_TTL = int(os.environ.get("OIDC_JWKS_TTL", "3600"))
_JWKS_MIN_REFETCH = 60


class ClearanceError(Exception):
    """Token could not be verified. The message is safe to return to the caller."""


def _fetch_jwks(force=False):
    with _jwks_lock:
        age = time.time() - _jwks_cache["fetched"]
        # Checked before the imports below so a warm cache costs nothing and
        # needs nothing — the hot path for every authenticated request.
        if _jwks_cache["keys"] and not force and age < _JWKS_TTL:
            return _jwks_cache["keys"]
        if force and age < _JWKS_MIN_REFETCH:
            return _jwks_cache["keys"]

        import requests
        import jwt

        url = f"{OIDC_ISSUER}/protocol/openid-connect/certs"
        try:
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            doc = resp.json()
        except Exception as exc:
            # Serve the stale cache if we have one: a brief IdP outage should
            # not lock every authenticated user out of the dashboard.
            if _jwks_cache["keys"]:
                return _jwks_cache["keys"]
            raise ClearanceError(f"cannot reach identity provider: {exc}")

        keys = {}
        for entry in doc.get("keys", []):
            kid = entry.get("kid")
            if not kid:
                continue
            try:
                keys[kid] = jwt.PyJWK(entry).key
            except Exception:
                continue    # unsupported key type (EC curve we don't build for)
        if not keys:
            raise ClearanceError("identity provider published no usable keys")

        _jwks_cache["keys"] = keys
        _jwks_cache["fetched"] = time.time()
        return keys


def verify_token(token):
    """Verify a Keycloak access token. Returns its claims, or raises ClearanceError."""
    try:
        import jwt
    except ImportError:
        raise ClearanceError("PyJWT is not installed on the Locator")

    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise ClearanceError(f"malformed token: {exc}")

    kid = header.get("kid")
    keys = _fetch_jwks()
    key = keys.get(kid)
    if key is None:
        keys = _fetch_jwks(force=True)      # key rotation
        key = keys.get(kid)
    if key is None:
        raise ClearanceError("token signed by an unknown key")

    if header.get("alg") not in ("RS256", "RS384", "RS512", "PS256"):
        # Pinned explicitly: never let the token's own header talk us into
        # "none" or into an HMAC alg verified against the public key.
        raise ClearanceError(f"unacceptable token algorithm: {header.get('alg')}")

    try:
        return jwt.decode(
            token,
            key=key,
            algorithms=["RS256", "RS384", "RS512", "PS256"],
            issuer=OIDC_ISSUER,
            audience=OIDC_AUDIENCES,
            options={"require": ["exp", "iat", "iss"]},
            leeway=30,
        )
    except jwt.ExpiredSignatureError:
        raise ClearanceError("token expired")
    except jwt.InvalidAudienceError:
        # Keycloak only puts a client in `aud` when a mapper or a scope puts it
        # there; azp is the fallback the realm always sets.
        try:
            claims = jwt.decode(
                token, key=key,
                algorithms=["RS256", "RS384", "RS512", "PS256"],
                issuer=OIDC_ISSUER,
                options={"require": ["exp", "iat", "iss"], "verify_aud": False},
                leeway=30,
            )
        except Exception as exc:
            raise ClearanceError(f"invalid token: {exc}")
        if claims.get("azp") not in OIDC_AUDIENCES:
            raise ClearanceError(
                f"token was issued for '{claims.get('azp')}', which is not an "
                f"accepted client ({', '.join(OIDC_AUDIENCES)})")
        return claims
    except Exception as exc:
        raise ClearanceError(f"invalid token: {exc}")


def _level_from_claims(claims):
    """
    Pull the clearance level out of verified claims.

    Preferred shape is a plain integer claim, emitted by a Keycloak mapper that
    reads the FreeIPA LDAP attribute. Realm roles named `clearance-<n>` are
    accepted as a fallback so the scheme also works before the LDAP attribute
    mapper exists — the highest such role wins.
    """
    raw = claims.get(CLEARANCE_CLAIM)
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is not None:
        try:
            return max(0, min(10, int(str(raw).strip())))
        except (TypeError, ValueError):
            pass

    best = 0
    roles = list((claims.get("realm_access") or {}).get("roles") or [])
    for container in (claims.get("resource_access") or {}).values():
        roles.extend((container or {}).get("roles") or [])
    for role in roles:
        name = str(role)
        if name.startswith("clearance-"):
            try:
                best = max(best, min(10, int(name.split("-", 1)[1])))
            except (TypeError, ValueError):
                continue
    return best


def _tenant_from_claims(claims):
    """The tenant a principal belongs to, used for row-level filtering."""
    raw = claims.get(TENANT_CLAIM)
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw:
        return str(raw).strip().lower()
    # FreeIPA groups arrive as a `groups` claim; a `tenant-<name>` group is the
    # convention for customer/client orgs.
    for grp in claims.get("groups") or []:
        name = str(grp).lstrip("/")
        if name.startswith("tenant-"):
            return name.split("-", 1)[1].lower()
    return ""


class Principal:
    """Who is making the current request, and at what level."""

    __slots__ = ("level", "name", "tenant", "via", "claims")

    def __init__(self, level, name, tenant="", via="anonymous", claims=None):
        self.level = level
        self.name = name
        self.tenant = tenant
        self.via = via
        self.claims = claims or {}

    @property
    def level_name(self):
        return LEVEL_NAMES.get(self.level, "anonymous")

    @property
    def sees_all_rows(self):
        return self.level >= SEES_ALL_ROWS

    def to_dict(self):
        return {
            "name": self.name,
            "clearance": self.level,
            "clearance_name": self.level_name,
            "tenant": self.tenant,
            "via": self.via,
            "enforced": ENFORCE,
            "views": sorted(v for v, need in VIEW_CLEARANCE.items() if self.level >= need),
        }


ANONYMOUS = Principal(ANON, "anonymous")


def identify():
    """
    Resolve the caller of the current request.

    Never raises: an unverifiable token yields an anonymous principal carrying
    the reason, so the route policy decides what happens rather than every
    caller getting a 500.
    """
    import hmac

    supplied_key = request.headers.get("X-Locator-Admin-Key", "")
    if supplied_key and ADMIN_KEY and hmac.compare_digest(supplied_key, ADMIN_KEY):
        return Principal(ROOT, "service:admin-key", via="admin-key")

    ai_key = request.headers.get("X-Locator-AI-Key", "")
    if ai_key and AI_ADMIN_KEY and hmac.compare_digest(ai_key, AI_ADMIN_KEY):
        return Principal(INFRA, "service:ai-admin", via="ai-admin-key")

    token = ""
    auth = request.headers.get("Authorization", "")
    if auth[:7].lower() == "bearer ":
        token = auth[7:].strip()
    if not token:
        # EventSource cannot set request headers, so the dashboard keeps the
        # same Keycloak token in a SameSite=Strict cookie purely so the SSE
        # events stream can authenticate. Strict means no cross-site sending,
        # which keeps the CSRF surface a cookie would otherwise open closed.
        token = request.cookies.get("kc_token", "")
    if token:
        try:
            claims = verify_token(token)
        except ClearanceError as exc:
            p = Principal(ANON, "anonymous", via="invalid-token")
            p.claims = {"error": str(exc)}
            return p
        name = (claims.get("preferred_username") or claims.get("sub") or "unknown")
        return Principal(
            _level_from_claims(claims), name,
            tenant=_tenant_from_claims(claims), via="oidc", claims=claims,
        )

    return ANONYMOUS


def current():
    """The Principal for this request. Falls back to identifying on demand."""
    p = getattr(g, "principal", None)
    if p is None:
        p = identify()
        g.principal = p
    return p


def level():
    """Convenience: the current caller's clearance as an int."""
    return current().level


# ── LAYER 1: PER-ENDPOINT MINIMUM ───────────────────────────────────────────

def _deny(principal, needed, endpoint):
    body = {
        "error": "insufficient clearance",
        "endpoint": endpoint,
        "required_clearance": needed,
        "required_name": LEVEL_NAMES.get(needed, str(needed)),
        "your_clearance": principal.level,
    }
    if principal.level <= ANON:
        if principal.via == "invalid-token":
            body["reason"] = principal.claims.get("error", "token rejected")
            return jsonify(body), 401
        body["reason"] = "no credentials presented"
        return jsonify(body), 401
    return jsonify(body), 403


def install(app):
    """Wire the clearance gate into a Flask app. Call once, after routes exist."""

    @app.before_request
    def _clearance_gate():
        if request.method == "OPTIONS":
            return None                       # CORS preflight carries no auth

        endpoint = request.endpoint
        principal = identify()
        g.principal = principal

        # Deliberately ABOVE the ENFORCE check. Everything below is a grant
        # decision and is correctly skipped when enforcement is off; this is a
        # denial, so skipping it would make the guardrail inert -- configured
        # but doing nothing, which is the failure mode we keep hitting.
        if is_ai_principal(principal) and endpoint in AI_DENIED_ENDPOINTS:
            return jsonify({
                "error": "destructive action requires a human",
                "endpoint": endpoint,
                "principal": principal.name,
                "hint": "ask the owner to run this, or use the ROOT admin key",
            }), 403

        if not ENFORCE:
            return None

        if endpoint is None:
            return None                       # 404 — let Flask answer it
        if endpoint in PUBLIC:
            return None

        if endpoint in INGEST:
            if not ENFORCE_INGEST:
                return None
            if principal.level >= ROOT:
                return None
            return _deny(principal, ROOT, endpoint)

        needed = ROUTE_CLEARANCE.get(endpoint)
        if needed is None:
            # Fail closed. An unmapped route is a route nobody has classified,
            # and guessing in the permissive direction is how registries leak.
            return jsonify({
                "error": "endpoint has no clearance policy",
                "endpoint": endpoint,
            }), 403

        if principal.level < needed:
            return _deny(principal, needed, endpoint)
        return None

    return app


def require(needed):
    """Decorator form, for routes that want an explicit in-line check."""
    from functools import wraps

    def outer(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            if not ENFORCE:
                return fn(*args, **kwargs)
            principal = current()
            if principal.level < needed:
                return _deny(principal, needed, request.endpoint or fn.__name__)
            return fn(*args, **kwargs)
        return inner
    return outer


# ── LAYER 2: ROW-LEVEL FILTERING ────────────────────────────────────────────

def _owner_of(record):
    """
    Which tenant owns a service/node record.

    Existing records predate the whole notion, so this reads a few likely spots
    and returns "" when there is nothing to go on. An unowned record is treated
    as internal — visible at STAFF and above only — rather than as public,
    because defaulting the other way would expose the entire current registry
    to every level-2 customer the moment enforcement goes on.
    """
    if not isinstance(record, dict):
        return ""
    meta = record.get("metadata") or {}
    for source in (record, meta):
        for key in ("tenant", "owner", "customer", "client", "org"):
            val = source.get(key)
            if val:
                return str(val).strip().lower()
    return ""


def _is_public(record):
    """Explicitly marked as visible to any authenticated principal."""
    if not isinstance(record, dict):
        return False
    meta = record.get("metadata") or {}
    for source in (record, meta):
        vis = str(source.get("visibility", "")).strip().lower()
        if vis in ("public", "shared"):
            return True
    return False


def visible(record, principal=None):
    """Whether `principal` may see this row at all."""
    principal = principal or current()
    if not ENFORCE or principal.sees_all_rows:
        return True
    if principal.level <= ANON:
        return False
    if _is_public(record):
        return True
    owner = _owner_of(record)
    if not owner:
        return False                          # unowned == internal
    return owner == principal.tenant


def filter_map(mapping, principal=None):
    """Filter a {key: record} registry section down to the rows `principal` may see."""
    principal = principal or current()
    if not ENFORCE or principal.sees_all_rows:
        return mapping
    return {k: v for k, v in (mapping or {}).items() if visible(v, principal)}


# ── LAYER 3: FIELD REDACTION ────────────────────────────────────────────────

def redact(record, principal=None):
    """Strip fields the principal's level does not reach. Returns a copy."""
    principal = principal or current()
    if not ENFORCE or principal.level >= STAFF:
        return record
    if not isinstance(record, dict):
        return record

    out = {}
    for key, value in record.items():
        need = _field_min(key)
        if need and principal.level < need:
            continue
        if key == "metadata" and isinstance(value, dict):
            out[key] = {
                k: v for k, v in value.items()
                if k in METADATA_SAFE_KEYS and principal.level >= _field_min(k)
            }
            continue
        if isinstance(value, dict):
            out[key] = redact(value, principal)
        elif isinstance(value, list):
            out[key] = [redact(v, principal) if isinstance(v, dict) else v for v in value]
        else:
            out[key] = value
    return out


def redact_map(mapping, principal=None):
    """Redact every record in a {key: record} section."""
    principal = principal or current()
    if not ENFORCE or principal.level >= STAFF:
        return mapping
    return {k: redact(v, principal) for k, v in (mapping or {}).items()}


def project(mapping, principal=None):
    """Layers 2 and 3 together: filter rows, then redact what survives."""
    principal = principal or current()
    if not ENFORCE or principal.sees_all_rows:
        return mapping
    return redact_map(filter_map(mapping, principal), principal)
