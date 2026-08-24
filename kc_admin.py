"""
Keycloak identity administration — backs the client portal's "new accounts" box.

Two endpoints, both gated at clearance 10 by clearance.py's route policy:
  GET  /api/admin/pending-users   accounts with no clearance-N role yet
  POST /api/admin/set-clearance   assign clearance-<level> to a user

Keycloak is reached with a dedicated service-account client (`clearance-admin`)
holding only view-users / query-users / manage-users. The realm's master admin
password is never used here and never leaves fly.io.

Assignment *replaces* any existing clearance-* role rather than adding to it:
clearance.py resolves a user's level by taking the highest clearance-N role it
finds, so leaving a stale higher role behind would silently ignore a demotion.
"""

import os
import time
import json
import requests
from flask import request, jsonify

KC_BASE       = os.environ.get("KC_BASE", "https://bsco-keycloak.fly.dev").rstrip("/")
KC_REALM      = os.environ.get("KC_REALM", "blacksheep")
CLIENT_ID     = os.environ.get("KC_ADMIN_CLIENT_ID", "clearance-admin")
CLIENT_SECRET = os.environ.get("KC_ADMIN_CLIENT_SECRET", "")

TOKEN_URL = f"{KC_BASE}/realms/{KC_REALM}/protocol/openid-connect/token"
ADMIN_API = f"{KC_BASE}/admin/realms/{KC_REALM}"

_svc = {"token": "", "exp": 0.0}


class KCError(Exception):
    """Keycloak call failed. Message is safe to surface to a level-10 caller."""


def _svc_token():
    if _svc["token"] and time.time() < _svc["exp"] - 30:
        return _svc["token"]
    if not CLIENT_SECRET:
        raise KCError("KC_ADMIN_CLIENT_SECRET is not configured on the Locator")
    try:
        r = requests.post(TOKEN_URL, data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }, timeout=10)
    except Exception as exc:
        raise KCError(f"cannot reach Keycloak: {exc}")
    if r.status_code != 200:
        raise KCError(f"service account auth failed ({r.status_code}). "
                      f"Has {CLIENT_ID} been granted realm-management roles?")
    d = r.json()
    _svc["token"] = d["access_token"]
    _svc["exp"] = time.time() + int(d.get("expires_in", 60))
    return _svc["token"]


def _hdr(json_body=False):
    h = {"Authorization": "Bearer " + _svc_token()}
    if json_body:
        h["Content-Type"] = "application/json"
    return h


def _get(path, **params):
    r = requests.get(f"{ADMIN_API}{path}", params=params, headers=_hdr(), timeout=20)
    if r.status_code == 403:
        raise KCError(f"{CLIENT_ID} lacks realm-management rights (view-users / "
                      f"query-users / manage-users)")
    r.raise_for_status()
    return r.json()


LEVEL_NAMES = {
    10: "root", 9: "infra", 8: "operator", 7: "engineer", 6: "staff",
    5: "partner", 4: "contractor", 3: "client", 2: "customer", 1: "guest",
}


def _clearance_roles():
    """{level: role_representation} for the clearance-N realm roles."""
    out = {}
    for r in _get("/roles", max=200):
        name = r.get("name", "")
        if name.startswith("clearance-"):
            try:
                out[int(name.split("-", 1)[1])] = r
            except ValueError:
                continue
    return out


def register(app, clearance):
    """Attach the admin routes to the Flask app."""

    @app.route("/api/admin/pending-users", methods=["GET"])
    def admin_pending_users():
        try:
            users = _get("/users", max=1000, briefRepresentation="true")
            pending = []
            for u in users:
                roles = _get(f"/users/{u['id']}/role-mappings/realm")
                levels = []
                for r in roles:
                    n = str(r.get("name", ""))
                    if n.startswith("clearance-"):
                        try:
                            levels.append(int(n.split("-", 1)[1]))
                        except ValueError:
                            pass
                entry = {
                    "id": u["id"],
                    "username": u.get("username", ""),
                    "email": u.get("email", ""),
                    "firstName": u.get("firstName", ""),
                    "lastName": u.get("lastName", ""),
                    "enabled": u.get("enabled", True),
                    "createdTimestamp": u.get("createdTimestamp"),
                    "clearance": max(levels) if levels else None,
                }
                pending.append(entry)
            # Unassigned first, then newest — the ones needing a decision surface.
            pending.sort(key=lambda e: (e["clearance"] is not None,
                                        -(e.get("createdTimestamp") or 0)))
            return jsonify({
                "users": pending,
                "unassigned": sum(1 for e in pending if e["clearance"] is None),
                "total": len(pending),
                "levels": LEVEL_NAMES,
            })
        except KCError as exc:
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:
            return jsonify({"error": f"keycloak query failed: {exc}"}), 502

    @app.route("/api/admin/set-clearance", methods=["POST"])
    def admin_set_clearance():
        body = request.get_json(silent=True) or {}
        user_id = body.get("userId")
        try:
            level = int(body.get("level"))
        except (TypeError, ValueError):
            return jsonify({"error": "level must be an integer 1-10"}), 400
        if not user_id or not (1 <= level <= 10):
            return jsonify({"error": "userId and level (1-10) are required"}), 400

        try:
            roles = _clearance_roles()
            if level not in roles:
                return jsonify({"error": f"realm role clearance-{level} does not exist"}), 500

            current = _get(f"/users/{user_id}/role-mappings/realm")
            stale = [r for r in current if str(r.get("name", "")).startswith("clearance-")]
            if stale:
                requests.delete(f"{ADMIN_API}/users/{user_id}/role-mappings/realm",
                                headers=_hdr(True), data=json.dumps(stale), timeout=20)

            want = roles[level]
            r = requests.post(f"{ADMIN_API}/users/{user_id}/role-mappings/realm",
                              headers=_hdr(True),
                              data=json.dumps([{"id": want["id"], "name": want["name"]}]),
                              timeout=20)
            if r.status_code not in (200, 204):
                return jsonify({"error": "assignment rejected by Keycloak",
                                "detail": r.text[:300]}), 502
        except KCError as exc:
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:
            return jsonify({"error": f"assignment failed: {exc}"}), 502

        who = clearance.current().name
        print(f"🔐 CLEARANCE SET: {who} -> user {user_id} = clearance-{level}")
        return jsonify({"result": "ok", "userId": user_id, "level": level,
                        "level_name": LEVEL_NAMES.get(level), "assigned_by": who})

    return app
