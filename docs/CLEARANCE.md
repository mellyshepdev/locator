# Clearance — levels 1 to 10

Every principal that touches the Locator carries a clearance level. 10 is the
owner; 1 is a guest. The level is decided in FreeIPA, carried by a Keycloak
access token, and enforced by `clearance.py` inside the Flask app.

## Why the app enforces it, not the proxy

Before this, the only gate was CSS in `templates/dashboard.html`:

```css
html:not(.auth-ok) body > * { visibility: hidden; }
```

That hides the DOM until Keycloak resolves, but every route stayed open to
anything that wasn't a browser. `curl https://locator.…/api/registry` returned
the whole mesh — units, internal IPs, SSH targets, compose files — to anyone,
signed in or not. Traefik's `locator-api` router deliberately routes `/api/*`
around the UI router, so a proxy-level gate would have to exempt the same paths
that leak the most.

So the check lives in the app, next to the data, where it can also decide
*which rows* and *which fields* a given level gets back.

## The levels

| Level | Name       | Gets                                                        |
|------:|------------|-------------------------------------------------------------|
| 10    | root       | `/api/exec` — arbitrary commands on the mesh                |
| 9     | infra      | deploys, YAML/compose writes, migrations, DNS sync          |
| 8     | operator   | start/stop containers, wake, shutdown, deregister           |
| 7     | engineer   | read compose/YAML/policy, see SSH targets                   |
| 6     | staff      | full mesh read — every service, every node, internal IPs    |
| 5     | partner    | full service list; internal addressing redacted             |
| 4     | contractor | own tenant + services shared with it                        |
| 3     | client     | own tenant only                                             |
| 2     | customer   | own tenant, heavy redaction                                 |
| 1     | guest      | liveness only                                               |
| 0     | —          | not a level; only satisfies routes listed as `PUBLIC`       |

Level 6 is the hinge: at 6 and above you see every row in the registry, and no
field is redacted. Below 6 both filters engage.

## The four layers

All four live in `clearance.py`.

1. **Per-endpoint minimum** — `ROUTE_CLEARANCE`, applied by a `before_request`
   hook. Keyed by Flask *endpoint name*, not path, so a trailing slash or a
   path parameter can't slip past it. **Fails closed**: a route that isn't in
   `PUBLIC`, `INGEST`, or `ROUTE_CLEARANCE` returns 403 to everyone, including
   root. `test_clearance.py` asserts every route in `locator.py` is classified,
   so adding a route without classifying it fails the tests rather than
   surprising you in production.

2. **Row-level filtering** — `filter_map()`. Below level 6, a principal sees
   only records whose `tenant`/`owner` matches theirs, plus anything explicitly
   marked `visibility: public`. Records with *no* owner are treated as internal,
   not public — otherwise switching enforcement on would expose the entire
   existing registry (none of which has owner metadata yet) to every level-2
   customer.

3. **Field redaction** — `redact()`. Sensitive keys are matched by glob, so
   `public_ip`, `vpn_ip` and `tailscale_ip` are all covered by one `*_ip` rule.
   `metadata` is a free-form bag written by whatever registered the service, so
   it can't be whitelisted field by field — below level 6 only
   `METADATA_SAFE_KEYS` survives and the rest is dropped.

4. **UI view visibility** — `VIEW_CLEARANCE` + `/api/whoami`. The dashboard
   hides toggle buttons the level can't reach and refuses deep links like
   `/?view=exec`. Cosmetic only; layers 1–3 are what actually enforce.

## How a level travels from FreeIPA to a decision

```
FreeIPA group        Keycloak                          token claim
─────────────        ────────                          ───────────
clearance-7      →   group /clearance-7
                 →   realm role clearance-7        →   realm_access.roles
tenant-acme      →   group /tenant-acme            →   groups: ["tenant-acme"]
                                                   →   aud: ["locator"]
```

`clearance.py` takes the **highest** `clearance-N` role it finds and the first
`tenant-*` group. A plain integer `clearance` claim is preferred if present,
but the role path needs no custom mapper, which is why it's the default.

Because the max wins, **demoting someone means removing their old group**, not
just adding a lower one.

## Token verification

`verify_token()` checks signature, issuer, audience, and expiry against the
realm's JWKS. Specifically:

- Algorithms are pinned to RS/PS. A token can't talk the verifier into `none`,
  and can't get an HMAC alg verified against the public key.
- Unknown `kid` forces one JWKS refetch (that's what key rotation looks like
  from here), rate-limited so a bogus `kid` can't be used to hammer the IdP.
- If the IdP is unreachable and a cached JWKS exists, the cache is served —
  a brief Keycloak outage shouldn't lock everyone out of the dashboard.
- `aud` falls back to `azp`, because Keycloak only puts a client in `aud` when
  a mapper puts it there. `keycloak-federation.sh` adds that mapper; the
  fallback means it works either way.

Machine agents (lokey, `locatorctl`, the unit agents) authenticate with the
pre-existing `X-Locator-Admin-Key` and are treated as level 10 — that key
already gated `/api/exec`, which is strictly more dangerous than anything else.

## Deploying it

### 1. Stand up FreeIPA

Needs a **dedicated host**. FreeIPA owns 389/636/88/464/53 and rewrites
`resolv.conf`; it does not co-tenant with Traefik or the unit agents. The FQDN
must resolve forward *and* reverse before first boot — the hostname is baked
into the Kerberos realm and the CA, and changing it later means reinstalling.

```bash
cd freeipa
cp .env.example .env && chmod 600 .env    # fill in the passwords
docker compose run --rm freeipa ipa-server-install -U \
  --realm=THEOFFICIALBLACKSHEEPCO.ONLINE \
  --domain=theofficialblacksheepco.online \
  --ds-password="$IPA_DM_PASSWORD" --admin-password="$IPA_ADMIN_PASSWORD" \
  --no-ntp --setup-dns --auto-forwarders
docker compose up -d
```

Back up `freeipa/data/`. It holds the CA private key; losing it means
re-enrolling every host.

### 2. Create the groups

```bash
./bootstrap-ipa.sh
```

Then assign people:

```bash
docker exec -it freeipa ipa group-add-member clearance-7 --users=jdoe
docker exec -it freeipa ipa group-add-member tenant-acme --users=jdoe
```

### 3. Federate into Keycloak

```bash
export KC_ADMIN_USER=admin KC_ADMIN_PASSWORD=… KEYCLOAK_BIND_PASSWORD=…
./keycloak-federation.sh
```

Run it twice if the first pass reports `group /clearance-N not present yet` —
the LDAP sync is asynchronous, and the second run binds the roles.

### 4. Verify before enforcing

This is the step that matters. Get a real token and look at it:

```bash
curl -s -d client_id=locator -d username=jdoe -d password=… -d grant_type=password \
  https://bsco-keycloak.fly.dev/realms/blacksheep/protocol/openid-connect/token \
  | python3 -c 'import sys,json,base64; t=json.load(sys.stdin)["access_token"].split(".")[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(t+"==")),indent=2))'
```

You want `realm_access.roles` containing `clearance-7` and `groups` containing
`tenant-acme`. Until you see that, **do not turn enforcement on** — every user
would resolve to level 0 and the dashboard would lock everyone out.

`/api/whoami` is the other half of the check. It's public and answers for
anonymous callers, so it works before enforcement is on:

```bash
curl -s https://locator.theofficialblacksheepco.online/api/whoami | jq
curl -s -H "Authorization: Bearer $TOKEN" \
  https://locator.theofficialblacksheepco.online/api/whoami | jq
```

### 5. Cut over

```bash
CLEARANCE_ENFORCE=true docker compose up -d locator
```

Watch for two things:

- **Heartbeats.** `CLEARANCE_ENFORCE_INGEST` stays `false` by default, so
  `/register` and the node/metrics/command routes keep accepting unattended
  agents exactly as before. Only flip it once every agent ships
  `LOCATOR_ADMIN_KEY`, or the mesh goes dark.
- **Row filtering.** No existing service record carries owner metadata, so
  below level 6 the registry will look nearly empty. That's layer 2 working as
  designed. Populate `metadata.tenant` on the services a customer should see:

```bash
curl -X POST https://locator.theofficialblacksheepco.online/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"acme-web","host":"unit4","metadata":{"tenant":"acme"}}'
```

Or mark something visible to everyone with `"visibility": "public"`.

### Rolling back

`CLEARANCE_ENFORCE=false` and redeploy. The gate stays installed but inert, and
every route behaves exactly as it did before. There's no data migration to undo.

## Adding a route later

Add it to `ROUTE_CLEARANCE` in `clearance.py` — or to `PUBLIC` / `INGEST` if
that's what it is. If you forget, the gate refuses it and
`test_clearance.py::TestPolicyCoverage` tells you which one.

## Tests

```bash
python -m pytest test_clearance.py -v
```

45 tests, no network and no IdP: a throwaway RSA keypair is pushed into the
JWKS cache, so signature/issuer/audience/expiry/algorithm checks all run for
real against Keycloak being down.
