# Known Issues

## Login broken on / and /3d-mesh — Keycloak check-sso blocked by X-Frame-Options (found 2026-08-01)

**Symptom:** Users cannot log in to the Locator dashboard (`/`) or the 3D mesh
view (`/3d-mesh`). The page sits behind the black "AUTH UNAVAILABLE" overlay
and never reaches the Keycloak login screen.

**Confirmed via `/api/client-errors`** (the dashboard's own error reporter),
two live reports at 2026-08-01T07:36 UTC, both:

```
Keycloak init/check-sso failed: undefined
```

— one from `/`, one from `/3d-mesh`.

**Root cause:** `dashboard.html` and `mesh.html` both call
`kc.init({ onLoad: 'check-sso', ... })`. That mode silently loads Keycloak's
auth endpoint in a hidden iframe (`silentCheckSsoRedirectUri`) to check for an
existing session before deciding whether to show the login page. Keycloak's
`/realms/blacksheep/protocol/openid-connect/auth` response currently sends:

```
x-frame-options: SAMEORIGIN
```

confirmed live:
```
curl -sI "https://bsco-keycloak.fly.dev/realms/blacksheep/protocol/openid-connect/auth?client_id=locator&response_type=code&redirect_uri=https://tobsco-locator.fly.dev/&scope=openid"
```

`SAMEORIGIN` means the browser refuses to render that response inside a frame
on any origin other than `bsco-keycloak.fly.dev` itself. Since the locator
pages live on `tobsco-locator.fly.dev`, the hidden iframe never loads, the
`postMessage` handshake keycloak-js waits on never fires, and `kc.init()`'s
promise rejects with an opaque `undefined` error — exactly what's in the logs.
This is deterministic, not intermittent — it will fail for every visitor on
every browser, every time, on both pages that use `check-sso`.

**Why `register-device` "still works":** `register_device.html` has no
Keycloak gate at all (see `templates/register_device.html` — no `new
Keycloak(...)` anywhere). It was never behind SSO, so it was never affected.
That's the likely source of "I can log in to some pages but not others" — the
ungated page always loads; the two gated pages (`/` and `/3d-mesh`) are both
broken the same way.

**Fix options (not yet applied — needs a call on which):**
1. In the `blacksheep` Keycloak realm → *Realm settings → Security defenses →
   Headers*, relax `X-Frame-Options`/add a CSP `frame-ancestors` that
   includes `tobsco-locator.fly.dev` (and any other Black Sheep app origins
   using this same check-sso pattern). This is a shared Keycloak config change
   — affects every client in the realm, so worth confirming before touching it.
2. Stop using silent `check-sso` for these two pages; switch to
   `onLoad: 'login-required'` (full top-level redirect to the real Keycloak
   login page — not framed, so `X-Frame-Options` doesn't apply). Simpler,
   locator-only change, no Keycloak realm config needed, but users get bounced
   to a real login page instead of silently staying signed in across visits.

## Stray duplicate `locator.py` inside `templates/`

`templates/locator.py` (85,587 bytes) sits next to the actual HTML templates.
It's not the same file as the real `/root/projects/locator/locator.py`
(109,608 bytes) at the repo root — looks like an old/stale copy that landed in
the wrong directory. Flask only serves it if something explicitly
`render_template`s it (nothing does), so it's inert, just repo clutter/a
confusing leftover. Left in place per "never delete, only add" — flagging so
it doesn't get mistaken for the real app entrypoint.

## Registry has test/junk device entries

`/api/registry` currently includes entries like `Samsung Galaxy A03s`,
`Samsung Galaxy Tab A7`, `Linux armv81`, and `verify-fix-phone`, all
registered via `web-self-register` — several share the identical desktop
Firefox-on-Linux `user_agent` string despite being labeled as Android phones/
tablets. These look like leftover manual test registrations (someone clicked
the "Android" platform button from a desktop browser and typed in a fake
name), not a registration bug — `register_device.html`'s platform is
user-picked, not auto-detected from the UA. Noted here since they clutter the
registry; not touched.
