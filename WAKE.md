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
