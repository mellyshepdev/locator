# Wake-on-request

How a stopped container comes back because somebody visited a page.

Written 2026-08-30, when the whole path was rebuilt. Before that it had been
broken in four independent places at once, none of which failed loudly.

## The chain

```
visitor → Traefik (unit8) → upstream dead → 502
                          → errors middleware → locator /wake/<container>  (unit4, over the tailnet)
                          → locator queues a `start`
                          → lokey on the hosting unit polls, runs docker start
                          → visitor's page retries → real service answers
```

Locator never touches Docker on another unit. It queues; lokey executes. That
split is why wake works across units at all, and why Sablier was removed from
unit8 on 2026-08-21 — Sablier drives the *local* socket, and the things that
need waking do not all live locally.

Idle-stop and wake are two halves of one feature: `idle_stop` in `locator.yml`
takes a container down, `public_wake` in the same file brings it back. Keeping
both in one file is deliberate — see "Why the policy moved" below.

## Declaring it — `locator.yml`

```yaml
  searchsearcher-app:
    deployment_type: optional
    location_type: stationary
    units: "8"
    instances: 1
    public_wake: true
    wake_with: [searchsearcher-postgres]
    wake_triggers:
      domain:
        - search.theofficialblacksheepco.com
        - www.theofficialblacksheepco.com
      link:
        - welcome:search
```

| key | meaning |
| --- | --- |
| `public_wake` | **Strictly opt-in.** Lets an anonymous visitor wake this one container. Absent = not wakeable without CLIENT clearance. |
| `wake_with` | Dependencies started alongside it. Callers ask for one name; locator expands it. |
| `wake_triggers` | *What* causes the wake, keyed by kind. `domain:` = a hostname whose visit should wake it. `link:` = a named link in one of our own frontends. |

`locator.yml` is re-read on mtime change, so **adding a service is a YAML edit,
not a rebuild.** It is also editable from the dashboard's YAMLs tab.

New trigger kinds need no code change — the parser keeps whatever kinds it
finds, and `/api/wake/triggers` will match on any of them.

## Endpoints

### `GET /wake/<container>` — the wake page

Queues the start and returns a page that comes back when the service is up.
Accepts a comma-separated list (`/wake/agent-0,ollama`); the first name is the
primary. `wake_with` from policy is merged in automatically, so the URL does
not need the dependency list.

`?to=` sets an explicit redirect target, restricted to
`*.theofficialblacksheepco.{com,info,online,store}` and `*.prime-quality.online`.

**How the page checks back depends on who asked**, and this matters:

- **Served through an errors middleware** (the normal case): the HTML comes back
  as the body of the *sleeping service's own* response — the address bar still
  reads `https://forge.prime-quality.online/`. A relative `fetch("/services/…")`
  from there never reaches locator; it goes back to the router that is down. So
  the page simply **re-requests the original URL**. No cross-origin call, no
  CORS, no credentials — the retry is the real service answering for itself.
- **On locator's own origin** (the dashboard): polls `/services/<name>` and
  follows the redirect target, because there it is same-origin and the caller is
  already authenticated.

Capped at 48 retries (4 minutes), then it stops and says so.

### `GET /api/wake/triggers` — the trigger map

Ask which container a trigger should wake instead of hardcoding a name:

```
GET /api/wake/triggers?domain=https://www.theofficialblacksheepco.com/
  → {"container": "searchsearcher-app", "wake_url": "/wake/searchsearcher-app", ...}

GET /api/wake/triggers?link=client-portal:enter
  → {"container": "reech", "wake_with": ["reech-oauth"], ...}

GET /api/wake/triggers            → the whole map
```

A full URL is accepted for `domain` and reduced to its host. Any trigger kind
can be queried the same way. Unknown trigger → 404 with `"container": null`.

Only containers carrying `public_wake` are listed.

## Clearance

`wake_page` and `wake_triggers` are in `clearance.PUBLIC`, and this is the part
worth understanding before changing it.

They *must* answer pre-auth: the 502 reaches somebody holding no token, and the
login they would need is often behind the very service that is asleep. Gating
`wake_page` at CLIENT — which is how it sat until 2026-08-30 — meant every
anonymous visitor got `{"error":"insufficient clearance"}` and the entire
wake-on-request design was unreachable from a browser.

Public does **not** mean open. The gate moved from the route to the container:
`_may_wake()` allows CLIENT and above to wake anything, and an anonymous caller
only what `public_wake` opts in. What that grants is exactly one verb — queue a
`start` for a container already in the registry, deduped so a refresh cannot
pile up work. No registry data is returned by either endpoint.

`get_service` stays at CUSTOMER. It was never opened, because the re-request
strategy above removed the need to.

## Traefik side

Every wakeable hostname needs an `errors` middleware pointing at the shared
`locator-wake` service (`dynamic-config/locator-wake.yml`, which addresses
locator by tailnet IP because unit8 has no Docker DNS for a container on
another unit).

```yaml
http:
  middlewares:
    forge-wake:
      errors:
        status: ["502", "503", "504"]   # not 500 — a real app error should surface
        service: locator-wake
        query: "/wake/forge"
  routers:
    forge-prime:
      middlewares: [forge-wake]
```

**Define these in a file, never on container labels.** A docker-provider router
disappears together with its container, and a route that has vanished cannot
wake anything — Traefik returns 404, the errors middleware never fires, and
nothing is ever asked to start. `searchsearcher` had exactly this shape: its
router lived on the app container's labels, so with the container gone
`search.theofficialblacksheepco.com` served a bare 404 and no wake was possible.

## What wake can and cannot do

- The only verb it queues is `start`. Stopping is `/api/shutdown/<name>` at
  OPERATOR.
- It can only name containers **already in the registry**.
- It starts a **stopped** container. It cannot recreate a **removed** one —
  `docker start` has nothing to act on. If the container is gone, the fix is a
  deploy, not a wake.
- `?to=` cannot be turned into an open redirect; the allowlist is a regex over
  our own domains.

## Current wiring (2026-08-30)

`locator.yml` policy is declared for all of these. The column that matters is
the middleware one — policy alone wakes nothing if no route can return a 502.
No unit column: upstreams are resolved live (see "Edge upstreams" below), so
where a container is standing right now is a registry fact, not a file fact —
a static unit listed here was already wrong within days (forge moved off
unit8 on 2026-09-11).

| container | trigger | Traefik wake middleware | upstream | serving |
| --- | --- | --- | --- | --- |
| `forge` | `forge.prime-quality.online` | ✅ `forge.yml` | `forge@http` (dynamic) | ✅ |
| `forge-relay` | same host, `/pad` `/view` | ✅ `forge.yml` | `forge-relay@http` (dynamic) | ✅ |
| `welcome-hub` | `welcome.theofficialblacksheepco.com` | ✅ `welcome-hub.yml` | `welcome-hub@http` (dynamic) | ✅ |
| `ops-dashboard` (+`pgadmin_ui`, `inventory-server`, `inventory-api`, `inventory-inventory-1`) | `ops.theofficialblacksheepco.com` visit | ✅ page-driven, `ops-dashboard.yml` (2026-09-11) — own 502 path too | `ops-dashboard` local docker-net (stationary); `inventory-app@http` (dynamic) | ✅ |
| `agent-0` (+`ollama`) | `a0.theofficialblacksheepco.online` | ✅ `agent-zero.yml` | static file | — |
| `rasa` (+`ollama`) | `rasa.theofficialblacksheepco.online` | ✅ `rasa.yml` | static file | — |
| `searchsearcher-app` (+ its postgres) | `search.…com`, `www.…com` | ✅ `searchsearcher.yml` (2026-09-13) | static file | ✅ 200 |
| `reech` (+`reech-oauth`) | `portal.theofficialblacksheepco.com` visit | ✅ page-driven, `client-portal.yml` (2026-09-03) | static file | ✅ 302 |
| `reech-oauth` itself | `reech.prime-quality.online` | ❌ **still none** — its router is a container LABEL, so stopping it deletes the route and the host 404s with nothing to wake | static file | ✅ 302 |

### Edge upstreams — `/api/traefik`

An edge's Traefik polls locator's HTTP provider
(`--providers.http.endpoint=http://<locator tailnet>:50500/api/traefik`,
`pollInterval=30s`) and gets back `http.services` for every service declaring
`edge_port` in `locator.yml`:

```yaml
forge:
  edge_port: 8090     # the port the container publishes on its unit's tailnet IP
```

Locator resolves the service's current host out of the registry and emits
`http://<hosting unit's tailnet IP>:<edge_port>`. A file-provider router that
wants this uses the cross-provider reference `service: forge@http` — the file
still owns the router, middleware and TLS; only the upstream moves.

- **Migration-safe by construction**: a container moved by locator registers
  its new host, and every edge follows within one poll interval. Nobody edits
  a YAML on the edge.
- **Wake-safe when unresolvable**: the service is emitted even when the host
  cannot be resolved (dead `127.0.0.1:9` placeholder, or the policy `units:`
  hint as fallback). Dropping it would invalidate every router pointing at it
  and take the wake middleware down with the route.
- **The container side must publish on the tailnet** wherever it lands:
  `ports: ["${TAILNET_IP}:<edge_port>:<internal>"]`. lokey injects
  `TAILNET_IP` into `.env` on deploy (hard-stats.py), so the compose file
  itself never names a unit.
- **Locator itself is the bootstrap exception**: `locator-wake`,
  `locator-prime` and `locator-online` stay static — the provider endpoint is
  a literal address in the edge's static config, so locator's own upstream
  cannot be resolved by a service it might not be running to answer.
- One `edge_port` per service name. Multi-port stacks (odoo, puffbase,
  traccar) still need per-name stanzas or a richer key before they can join.

Three optional keys shape the emitted service:

```yaml
error-pages:
  edge_host: apache        # borrow apache's registry placement — a logical
                           # edge name with no container of its own
  edge_port: 8080
  edge_pass_host: false    # emitted as loadBalancer.passHostHeader
aegis-server:
  edge_port: 8090
  edge_healthcheck: /healthz   # emitted as loadBalancer.healthCheck,
                             # path only — interval/timeout are fixed 15s/5s
```

`edge_host` also covers one backend serving several routes that need
different load-balancer options — `error-pages` and `apache` share the same
upstream but only error-pages rewrites the Host header.

Both searchsearcher and reech were **not deployed at all** before this date — no
container and no image, only their data. They were built and started on unit8 on
2026-08-30. Nothing could have woken them, because there was nothing to start.

searchsearcher's index is **empty** (0 rows in `servers` and `searchable_items`),
so the search bar returns nothing until something ingests into it. That is a
separate piece of work from waking it.

### Still to wire

1. **File-defined routers + wake middleware for searchsearcher and reech.**
   DONE for searchsearcher (2026-09-13): `dynamic-config/searchsearcher.yml`
   owns the `search.…com` router + `searchsearcher-wake` errors middleware,
   upstream `http://searchsearcher-app:3000`. The compose rework that renamed
   the container to `searchsearcher` was walked back — `container_name` is
   `searchsearcher-app` again so lokey's exact-name `docker start` still lands;
   the planned oauth2-proxy front (searchsearcher-oauth) still needs its
   `SEARCHSEARCHER_OIDC_SECRET` before it can take over this route.
   reech's router remains on container labels — same trap still applies there.
2. **The frontends.** DONE for the welcome hub (→ forge, 2026-09-03) and the
   client portal (→ reech, 2026-09-03): both carry a script that calls
   `/__wake/triggers?domain=…` then `/__wake/<container>`, same-origin paths
   proxied to locator by `welcome-hub.yml` / `client-portal.yml` on unit8.
   Asking rather than hardcoding is the whole point of the trigger map.

   **A page-driven wake is the ONLY option when the visited host is healthy.**
   An `errors` middleware needs a 502/503/504 to fire, and a hub or portal that
   answers 200 never produces one, so it can never wake a sibling container.
   Use the middleware to wake the host being visited, the page to wake others.

   Still to do: the main site's search bar (→ searchsearcher-app).
3. **`locator-api-readblock.yml` blocks `PathPrefix(/wake)`** on both public
   locator hostnames, so a browser-initiated wake from a page still gets 403.
   That block predates wake having any auth of its own; now that the gate is
   per-container, GET needs an exception. Wake *through an errors middleware* is
   unaffected — that path goes over the tailnet, not through those hostnames.
4. **`wake.theofficialblacksheepco.com` is NXDOMAIN** — the frontends' old
   `WAKE_URL`. Either create the record or point the frontends at a live host.

### Operational notes

- unit8's disk is chronically tight and hit **100%** during these builds, which
  is what failed the first reech build (`no space left on device`). `docker
  builder prune -f` reclaimed 4.7GB. **Check `df -h /` before building there.**
- `/home/swoopg111/server` on unit8 is **not a git repository**. Traefik configs
  are versioned only by `.bak-<date>` copies beside them. Make one before editing.
- The live locator source is **unit4, branch `main`**. unit8 holds a diverged
  `clearance-levels` branch — do not edit that one and expect it to matter.

## History — the four breaks, 2026-08-30

Found while fixing "the forge won't come up on its own":

1. **`wake_page` gated at CLIENT.** Traefik's errors middleware forwards the
   visitor's own headers, which carry no admin key and no bearer token, so every
   anonymous wake 401'd. This affected `agent-zero.yml` and `rasa.yml` too — the
   whole feature, not just forge.
2. **The status poll could never have worked from a foreign host.** Relative
   `fetch("/services/…")` from a page served under the sleeping service's
   hostname goes back to the dead router. Independent of #1: fixing clearance
   alone would still have left the page spinning forever.
3. **`forge.yml` had no wake middleware at all**, and the welcome card passed no
   `container` prop, and it pointed at `forge.theofficialblacksheepco.online` —
   retired 2026-08-14, no cert.
4. **`wake.theofficialblacksheepco.com` does not resolve.** NXDOMAIN. The
   frontend's whole `WAKE_URL` path was dead for every service.

Also found: `searchsearcher` and `reech` were **not deployed at all** on unit8 —
no container, no image, only their data. Nothing could have woken them because
there was nothing to start.

### Why the policy moved into `locator.yml`

The mapping used to live in three places that had no way to disagree out loud: a
Traefik `query:` string, a frontend constant, and a card prop. They drifted —
a card pointing at a hostname retired months earlier, a dependency list repeated
in two files, a container renamed in one place only. Putting `public_wake`,
`wake_with` and `wake_triggers` in `locator.yml` gives one file that says what
the truth is, reloads without a restart, and can be *queried* by the pages that
need it via `/api/wake/triggers` — so a rename is one edit and every entry point
follows.

## Per-unit Glances web view (2026-09-12)

Clicking a `unitN` node in the dashboard's device modal shows an "Online Views"
section with a Glances link: `https://glances-<unit>.theofficialblacksheepco.com`.

The chain:

- Each unit runs **`glances-web.service`** (systemd) — `glances -w -B <unit
  tailnet IP> -p 61208 --disable-plugin docker`. It binds the tailnet address
  only, so nothing off-tailnet can reach it directly. The existing
  `glances.service` (`-s` on 127.0.0.1:61209, the `glances -c` API) is
  untouched — the web unit runs alongside it.
  - `docker` plugin is disabled because two *running* containers on unit8
    (`dashboard-server`, `upc-receiver`) reference pruned images, and the
    plugin's image lookup crashes before the web server binds — the same
    phantom-image bug family that broke lokey's enumeration. Re-enable it once
    those containers are rebuilt with real images.
- The edge publishes it via `networking/traefik/dynamic-config/glances.yml`:
  `glances-unitN.*` routers → `http://<tailnet>:61208`, behind the
  `glances-auth` basicAuth middleware. Upstream IPs are literal tailnet
  addresses on purpose — units are stationary, same convention as the
  locator-* and keycloak services.
- DNS A records (`glances-unit4|7|8` → the edge IP) live in the
  `theofficialblacksheepco.com` zone — the **primary is unit8's
  `mariadb-pdns-primary`** (`docker exec pdns pdnsutil add-record ...` runs
  there); unit9's pdns is a read-only replica. Adding a new unit's record on
  the replica fails with `--read-only=ON` — write on unit8.

**Auth note:** the gate is edge basicAuth, not Keycloak — every oauth2-proxy
gate needs its own Keycloak client and no working realm-admin credential was
available when this shipped. To upgrade: create a `glances-gate` client in the
blacksheep realm, add a `glances-gate` oauth2-proxy to `edge-gate`/
`oauth2-guards` compose (or one forwardAuth proxy + shared cookie-domain), and
swap `glances-auth` for it in `glances.yml`. The routers and DNS don't change.

**Enabling on another unit:** install the systemd unit (change `-B` to its own
tailnet IP), `systemctl enable --now glances-web`, add the router + service in
`glances.yml`, and the A record on unit8's pdns. If the distro package lacks
the built web bundle (Debian strips `outputs/static/public` — unit7 hits
this), run the official image instead; that's what unit7 does:

```bash
docker run -d --name glances-web --restart unless-stopped \
  -p <tailnet ip>:61208:61208 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /etc/os-release:/etc/os-release:ro \
  --pid host -e GLANCES_OPT="-w" \
  nicolargo/glances:latest-full
```
