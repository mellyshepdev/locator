"""
Tests for the clearance layer.

Run: python -m pytest test_clearance.py   (or: python test_clearance.py)

No network and no IdP: a throwaway RSA keypair is pushed straight into the
JWKS cache, so token verification is exercised for real — signature, issuer,
audience, expiry, algorithm — without Keycloak being up.
"""

import os
import time
import json
import unittest

os.environ.setdefault("CLEARANCE_ENFORCE", "true")
os.environ.setdefault("LOCATOR_ADMIN_KEY", "test-admin-key")
os.environ.setdefault("OIDC_ISSUER", "https://idp.example/realms/blacksheep")
os.environ.setdefault("OIDC_AUDIENCE", "locator")

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify

import clearance as C

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KID = "test-key-1"

# Seed the JWKS cache so _fetch_jwks never reaches for the network.
C._jwks_cache["keys"] = {_KID: _KEY.public_key()}
C._jwks_cache["fetched"] = time.time()


def make_token(clearance=None, tenant=None, roles=None, groups=None,
               aud="locator", iss=None, exp_delta=300, alg="RS256", key=None):
    now = int(time.time())
    claims = {
        "iss": iss or C.OIDC_ISSUER,
        "aud": aud,
        "azp": "locator",
        "sub": "user-uuid",
        "preferred_username": "tester",
        "iat": now,
        "exp": now + exp_delta,
    }
    if clearance is not None:
        claims["clearance"] = clearance
    if tenant is not None:
        claims["tenant"] = tenant
    if roles is not None:
        claims["realm_access"] = {"roles": roles}
    if groups is not None:
        claims["groups"] = groups
    return jwt.encode(claims, key or _KEY, algorithm=alg, headers={"kid": _KID})


def build_app():
    """A miniature app wired the way locator.py wires the real one."""
    app = Flask(__name__)
    C.install(app)

    @app.route("/health")
    def health_check():
        return jsonify({"status": "ONLINE"})

    @app.route("/api/registry")
    def get_full_registry():
        return jsonify(C.project(REGISTRY))

    @app.route("/api/yaml")
    def get_yaml():
        return jsonify({"yaml": "secret: true"})

    @app.route("/api/exec", methods=["POST"])
    def queue_exec():
        return jsonify({"ran": True})

    @app.route("/register", methods=["POST"])
    def register_service():
        return jsonify({"result": "registered"})

    @app.route("/api/brand-new")
    def brand_new_route():          # deliberately absent from ROUTE_CLEARANCE
        return jsonify({"leak": "everything"})

    return app


REGISTRY = {
    "web@unit1": {
        "name": "web", "status": "ONLINE", "host": "unit1",
        "internal": "http://10.0.0.5:8080", "ssh_target": "root@10.0.0.5",
        "metadata": {"tenant": "acme", "platform": "linux", "battery_percent": 88},
    },
    "db@unit2": {
        "name": "db", "status": "ONLINE", "host": "unit2",
        "internal": "http://10.0.0.6:5432",
        "metadata": {"tenant": "globex", "platform": "linux"},
    },
    "status-page@unit3": {
        "name": "status-page", "status": "ONLINE", "host": "unit3",
        "internal": "http://10.0.0.7:80",
        "metadata": {"visibility": "public"},
    },
    "mesh-core@unit8": {        # unowned -> internal only
        "name": "mesh-core", "status": "ONLINE", "host": "unit8",
        "internal": "http://10.0.0.8:5000",
    },
}


def auth(token):
    return {"Authorization": "Bearer " + token}


def _all_endpoints():
    """Every Flask endpoint defined across the app's modules.

    Routes live in locator.py and in kc_admin.py (registered onto the same app),
    so a coverage check that reads only locator.py reports the admin routes as
    stale policy entries.
    """
    import re
    here = os.path.dirname(__file__) or "."
    names = set()
    for mod in ("locator.py", "kc_admin.py"):
        path = os.path.join(here, mod)
        if not os.path.exists(path):
            continue
        src = open(path).read()
        names |= set(re.findall(
            r'@app\.route\([^\n]*\)\n(?:@app\.route\([^\n]*\)\n)*\s*def (\w+)\(', src))
    return names


class TestTokenVerification(unittest.TestCase):
    def test_valid_token_yields_level(self):
        claims = C.verify_token(make_token(clearance=7))
        self.assertEqual(C._level_from_claims(claims), 7)

    def test_expired_token_rejected(self):
        with self.assertRaises(C.ClearanceError) as cm:
            C.verify_token(make_token(clearance=7, exp_delta=-60))
        self.assertIn("expired", str(cm.exception))

    def test_wrong_issuer_rejected(self):
        with self.assertRaises(C.ClearanceError):
            C.verify_token(make_token(clearance=7, iss="https://evil.example/realms/x"))

    def test_wrong_audience_rejected(self):
        # aud mismatch AND azp mismatch -> rejected
        tok = jwt.encode(
            {"iss": C.OIDC_ISSUER, "aud": "other-app", "azp": "other-app",
             "sub": "u", "iat": int(time.time()), "exp": int(time.time()) + 300,
             "clearance": 10},
            _KEY, algorithm="RS256", headers={"kid": _KID})
        with self.assertRaises(C.ClearanceError):
            C.verify_token(tok)

    def test_audience_falls_back_to_azp(self):
        tok = jwt.encode(
            {"iss": C.OIDC_ISSUER, "aud": "account", "azp": "locator",
             "sub": "u", "iat": int(time.time()), "exp": int(time.time()) + 300,
             "clearance": 6},
            _KEY, algorithm="RS256", headers={"kid": _KID})
        self.assertEqual(C._level_from_claims(C.verify_token(tok)), 6)

    def test_unsigned_token_rejected(self):
        tok = jwt.encode({"iss": C.OIDC_ISSUER, "aud": "locator", "clearance": 10,
                          "iat": int(time.time()), "exp": int(time.time()) + 300},
                         key="", algorithm="none", headers={"kid": _KID})
        with self.assertRaises(C.ClearanceError):
            C.verify_token(tok)

    def test_token_signed_by_other_key_rejected(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(C.ClearanceError):
            C.verify_token(make_token(clearance=10, key=other))

    def test_unknown_kid_rejected(self):
        tok = jwt.encode({"iss": C.OIDC_ISSUER, "aud": "locator", "clearance": 10,
                          "iat": int(time.time()), "exp": int(time.time()) + 300},
                         _KEY, algorithm="RS256", headers={"kid": "who-dis"})
        # force-refetch is rate-limited to the seeded cache, so this stays offline
        with self.assertRaises(C.ClearanceError):
            C.verify_token(tok)


class TestLevelExtraction(unittest.TestCase):
    def test_claim_wins(self):
        self.assertEqual(C._level_from_claims({"clearance": 4}), 4)

    def test_string_claim(self):
        self.assertEqual(C._level_from_claims({"clearance": " 9 "}), 9)

    def test_list_claim(self):
        self.assertEqual(C._level_from_claims({"clearance": ["3"]}), 3)

    def test_role_fallback_takes_highest(self):
        claims = {"realm_access": {"roles": ["clearance-3", "clearance-8", "offline_access"]}}
        self.assertEqual(C._level_from_claims(claims), 8)

    def test_clamped_to_ten(self):
        self.assertEqual(C._level_from_claims({"clearance": 9999}), 10)

    def test_garbage_claim_is_zero(self):
        self.assertEqual(C._level_from_claims({"clearance": "root"}), 0)

    def test_no_claim_no_roles_is_zero(self):
        self.assertEqual(C._level_from_claims({}), 0)

    def test_tenant_from_group(self):
        self.assertEqual(C._tenant_from_claims({"groups": ["/tenant-Acme", "staff"]}), "acme")


class TestRoutePolicy(unittest.TestCase):
    def setUp(self):
        self.app = build_app()
        self.c = self.app.test_client()

    def test_public_route_needs_nothing(self):
        self.assertEqual(self.c.get("/health").status_code, 200)

    def test_anonymous_gets_401(self):
        r = self.c.get("/api/registry")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json()["reason"], "no credentials presented")

    def test_insufficient_gets_403(self):
        r = self.c.get("/api/yaml", headers=auth(make_token(clearance=3)))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["required_clearance"], C.ENGINEER)
        self.assertEqual(r.get_json()["your_clearance"], 3)

    def test_sufficient_passes(self):
        r = self.c.get("/api/yaml", headers=auth(make_token(clearance=7)))
        self.assertEqual(r.status_code, 200)

    def test_exec_needs_root(self):
        self.assertEqual(self.c.post("/api/exec", headers=auth(make_token(clearance=9))).status_code, 403)
        self.assertEqual(self.c.post("/api/exec", headers=auth(make_token(clearance=10))).status_code, 200)

    def test_admin_key_is_root(self):
        r = self.c.post("/api/exec", headers={"X-Locator-Admin-Key": "test-admin-key"})
        self.assertEqual(r.status_code, 200)

    def test_wrong_admin_key_is_anonymous(self):
        r = self.c.post("/api/exec", headers={"X-Locator-Admin-Key": "nope"})
        self.assertEqual(r.status_code, 401)

    def test_unmapped_route_fails_closed(self):
        r = self.c.get("/api/brand-new", headers=auth(make_token(clearance=10)))
        self.assertEqual(r.status_code, 403)
        self.assertIn("no clearance policy", r.get_json()["error"])

    def test_invalid_token_reports_401_with_reason(self):
        r = self.c.get("/api/registry", headers=auth("not.a.token"))
        self.assertEqual(r.status_code, 401)
        self.assertIn("malformed", r.get_json()["reason"])

    def test_ingest_open_while_enforce_ingest_off(self):
        self.assertFalse(C.ENFORCE_INGEST)
        self.assertEqual(self.c.post("/register").status_code, 200)

    def test_ingest_closed_when_enabled(self):
        C.ENFORCE_INGEST = True
        try:
            self.assertEqual(self.c.post("/register").status_code, 401)
            r = self.c.post("/register", headers={"X-Locator-Admin-Key": "test-admin-key"})
            self.assertEqual(r.status_code, 200)
        finally:
            C.ENFORCE_INGEST = False

    def test_options_preflight_never_gated(self):
        self.assertNotEqual(self.c.open("/api/yaml", method="OPTIONS").status_code, 401)


class TestRowFiltering(unittest.TestCase):
    def setUp(self):
        self.app = build_app()
        self.c = self.app.test_client()

    def rows(self, **kw):
        r = self.c.get("/api/registry", headers=auth(make_token(**kw)))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()

    def test_staff_sees_everything(self):
        self.assertEqual(set(self.rows(clearance=6)), set(REGISTRY))

    def test_root_sees_everything(self):
        self.assertEqual(set(self.rows(clearance=10)), set(REGISTRY))

    def test_client_sees_only_own_tenant_plus_public(self):
        got = self.rows(clearance=3, tenant="acme")
        self.assertEqual(set(got), {"web@unit1", "status-page@unit3"})

    def test_other_tenant_is_isolated(self):
        got = self.rows(clearance=3, tenant="globex")
        self.assertEqual(set(got), {"db@unit2", "status-page@unit3"})

    def test_tenantless_low_level_sees_only_public(self):
        got = self.rows(clearance=2)
        self.assertEqual(set(got), {"status-page@unit3"})

    def test_unowned_records_never_leak_below_staff(self):
        for lvl in (2, 3, 4, 5):
            self.assertNotIn("mesh-core@unit8", self.rows(clearance=lvl, tenant="acme"))


class TestFieldRedaction(unittest.TestCase):
    def setUp(self):
        self.app = build_app()
        self.c = self.app.test_client()

    def rows(self, **kw):
        return self.c.get("/api/registry", headers=auth(make_token(**kw))).get_json()

    def test_staff_sees_internal_addressing(self):
        self.assertIn("internal", self.rows(clearance=6)["web@unit1"])

    def test_client_loses_internal_addressing(self):
        rec = self.rows(clearance=3, tenant="acme")["web@unit1"]
        self.assertNotIn("internal", rec)
        self.assertNotIn("ssh_target", rec)
        self.assertEqual(rec["name"], "web")
        self.assertEqual(rec["status"], "ONLINE")

    def test_partner_keeps_host_loses_ip(self):
        rec = C.redact(REGISTRY["web@unit1"], C.Principal(C.PARTNER, "p", tenant="acme"))
        self.assertIn("host", rec)
        self.assertNotIn("internal", rec)

    def test_customer_loses_host_too(self):
        rec = C.redact(REGISTRY["web@unit1"], C.Principal(C.CUSTOMER, "c", tenant="acme"))
        self.assertNotIn("host", rec)

    def test_metadata_bag_is_whitelisted(self):
        rec = self.rows(clearance=3, tenant="acme")["web@unit1"]
        self.assertEqual(set(rec["metadata"]), {"platform"})
        self.assertNotIn("tenant", rec["metadata"])
        self.assertNotIn("battery_percent", rec["metadata"])

    def test_engineer_sees_ssh(self):
        rec = C.redact(REGISTRY["web@unit1"], C.Principal(C.ENGINEER, "e", tenant="acme"))
        self.assertIn("ssh_target", rec)

    def test_field_glob_matching(self):
        self.assertEqual(C._field_min("public_ip"), C.STAFF)
        self.assertEqual(C._field_min("tailscale_ip"), C.STAFF)
        self.assertEqual(C._field_min("ssh_user"), C.ENGINEER)
        self.assertEqual(C._field_min("status"), 0)
        self.assertEqual(C._field_min("name"), 0)


class TestEnforceOff(unittest.TestCase):
    """With the master switch off nothing changes — the pre-cutover contract."""

    def setUp(self):
        C.ENFORCE = False
        self.c = build_app().test_client()

    def tearDown(self):
        C.ENFORCE = True

    def test_anonymous_reaches_everything(self):
        self.assertEqual(self.c.get("/api/registry").status_code, 200)
        self.assertEqual(self.c.get("/api/yaml").status_code, 200)
        self.assertEqual(self.c.post("/api/exec").status_code, 200)

    def test_no_filtering_or_redaction(self):
        got = self.c.get("/api/registry").get_json()
        self.assertEqual(set(got), set(REGISTRY))
        self.assertIn("internal", got["web@unit1"])


class TestPolicyCoverage(unittest.TestCase):
    def test_every_locator_endpoint_is_classified(self):
        """
        Every route in locator.py must be PUBLIC, INGEST, or carry a level.
        This is the test that fails when somebody adds a route and forgets —
        the gate would fail it closed at runtime, which is safe but confusing.
        """
        import re
        endpoints = _all_endpoints()
        classified = C.PUBLIC | C.INGEST | C.UNIT_KEY | set(C.ROUTE_CLEARANCE)
        missing = sorted(endpoints - classified)
        self.assertEqual(missing, [], f"unclassified endpoints: {missing}")

    def test_no_stale_policy_entries(self):
        """
        Catch the opposite mistake: a policy entry naming a route that no
        longer exists. Harmless at runtime, but it silently stops protecting
        whatever it was written for, so it should not rot unnoticed.
        """
        import re
        endpoints = _all_endpoints()
        # "static" is Flask's built-in file server, not a route in this source.
        classified = (C.PUBLIC | C.INGEST | C.UNIT_KEY | set(C.ROUTE_CLEARANCE)) - {"static"}
        stale = sorted(classified - endpoints)
        self.assertEqual(stale, [], f"policy names routes that do not exist: {stale}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
