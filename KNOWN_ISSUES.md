# Known Issues

## [RESOLVED 2026-09-02] Login rejected before the form renders — realm bound to a broken `browser-mfa` flow

**Resolution:** the `blacksheep` realm's **Browser flow** binding pointed at a
custom flow named **`browser-mfa`**, while the built-in `browser` flow sat
unused ("Not in use" in the Flows list). `browser-mfa` failed credential
validation before rendering a form. Rebinding Browser flow → **`browser`**
(Authentication → Flows → ⋮ on the `browser` row → *Bind flow*) restored login
realm-wide. Verified immediately after: the login form renders again for both
`locator` and `bsco-agent-ops`.

`browser-mfa` was left in place, unbound, rather than deleted — the realm also
carries an unused `facial recognition flow`, so custom authenticators were
being built here and `browser-mfa` is presumably an unfinished one. Repair it
before binding it again.

**Diagnostic that isolated it, worth reusing:** replay the authorization
request by hand with valid PKCE and compare realms. `master` rendered a login
form while `blacksheep` returned 400 — that one comparison proved Keycloak,
the theme, and the clients were all healthy and put the fault on the
`blacksheep` browser flow alone. The admin console lives in `master`, so it
stayed reachable throughout and was the way back in.

---

### Original diagnosis (kept — the evidence chain was right, the named cause was not)

**Symptom:** The Keycloak login screen for the Locator "rejects any login before
I even get a chance to type anything in." No username/password form is ever
shown — the themed error page appears immediately with *"Invalid username or
password."*

**Not a repo problem.** Replaying the exact authorization request
`dashboard.html` sends (client `locator`, PKCE S256, redirect
`https://locator.prime-quality.online/`) against the live realm:

| request | result |
| --- | --- |
| `locator` + valid PKCE **S256** | **400 — "Invalid username or password."** |
| `locator` + PKCE `plain` | 302 → *"code challenge method is not matching the configured one"* |
| `locator` + bad `redirect_uri` | 400 — *"Invalid parameter: redirect_uri"* |
| `locator` + bogus `client_id` | 400 — *"Client not found."* |
| **`account`** (Keycloak's own built-in client) + S256 | **400 — "Invalid username or password."** |

Read in order, that rules almost everything out:

- The `locator` client **exists**, its redirect URI **is** whitelisted, and it
  correctly **requires S256** — so the S256 request is the *valid* one.
- The theme reports real errors verbatim in every other case, so it is not
  masking the true message.
- Keycloak accepts the parameters, enters the browser login flow, and the flow
  **fails credential validation without ever rendering a form**.
- **The stock `account` client fails identically**, which eliminates the
  `locator` client, the redirect URIs, `docker-compose.yml`, and the templates.
  The fault is **realm-wide**.

**Root cause (to confirm in the console):** the `blacksheep` realm's browser
authentication flow is running a *direct-grant*-style credential check.
Executions such as `Direct Grant Validate Username` / `Validate Password` read
credentials from request parameters instead of rendering a form; with no
credentials present they return `invalid_user_credentials` on the first hop,
which surfaces as "Invalid username or password."

**Fix (Keycloak admin console — cannot be done from this repo):**
`https://auth.theofficialblacksheepco.com/admin` → realm `blacksheep` →
*Authentication → Flows*

1. Check the **bindings** tab — *Browser flow* is likely bound to a direct-grant
   flow, or to a copied flow that was edited. It should be `browser`, or a copy
   whose first form step is **Username Password Form**.
2. If the binding is right, open the flow and confirm it contains a **Username
   Password Form** execution — not `Validate Username` / `Validate Password`.

---

### Collateral found while diagnosing the above

These did **not** cause the login failure and are tracked separately.

**1. `KC_ADMIN_*` env vars renamed to names nothing reads — `/api/admin/*` is dead.**
`docker-compose.yml` and `.env` were edited to `KC_admin-cli_CLIENT_ID` /
`kC_admin-cli_CLIENT_SECRET` (note the lowercase `kC`). Hyphens are not legal in
an environment variable name, and `kc_admin.py` reads `KC_ADMIN_CLIENT_ID` /
`KC_ADMIN_CLIENT_SECRET`. Confirmed end-to-end via `docker compose config`:

```
KC_admin-cli_CLIENT_SECRET: <EMPTY>
```

So `_svc_token()` trips `if not CLIENT_SECRET:` and every `/api/admin/*` call
returns *"KC_ADMIN_CLIENT_SECRET is not configured on the Locator."*
**Still open** — deliberately not auto-fixed, because the client *value* was
also swapped (`clearance-admin` → `admin-cli`) and that is a least-privilege
decision, not a typo. `clearance-admin` exists precisely so the Locator holds
only view-users / query-users / manage-users and never the realm master admin.
Putting a web-facing Flask app on `admin-cli` grants it far more of the realm
than it needs. Needs an owner decision on which client, then the names restored
to match `kc_admin.py`.

**2. `LOCATOR_CLIENT_ID` / `LOCATOR_CLIENT_SECRET` are dead config.**
Added to both `docker-compose.yml` and `.env`; read by nothing in the codebase.
`LOCATOR_CLIENT_SECRET` resolves to an 86-char value that is never consumed.

**3. [FIXED 2026-09-02] `mesh.html` still pointed at the dead fly.io Keycloak.**
`templates/mesh.html` initialised keycloak-js against
`https://bsco-keycloak.fly.dev`. `dashboard.html:88` had already been corrected
to `auth.theofficialblacksheepco.com`; mesh.html was missed. Now matches.

**4. [FIXED 2026-09-02] `KC_BASE` was never set.**
`kc_admin.py` falls back to its own default of `https://bsco-keycloak.fly.dev`,
so admin REST calls went to the dead fly host while tokens validated against the
`.com` issuer. `KC_BASE=${KC_BASE:-https://auth.theofficialblacksheepco.com}`
added to `docker-compose.yml` so the two name the same Keycloak.

**Verified safe:** `.env` is in `.gitignore:6` and untracked — the 3x-daily
`refresh` cron is not pushing these secrets to GitLab.

## [RESOLVED 2026-08-04] Login broken on / and /3d-mesh — Keycloak check-sso blocked by X-Frame-Options (found 2026-08-01)

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

**Resolution (2026-08-04):** Option 2 was applied at some point (onLoad is
now login-required in both templates — this doc just wasn't updated). That
fixed the X-Frame-Options failure, but a *new* iframe-based failure appeared
in its place: keycloak-js still runs its default session-status/3rd-party-
cookie check iframe (controlled by checkLoginIframe, defaults to true) even
under login-required. Since tobsco-locator.fly.dev and bsco-keycloak.fly.dev
are different origins and browsers increasingly block 3rd-party cookies, that
check iframe timed out for every visitor
('Timeout when waiting for 3rd party check iframe message' in
/api/client-errors). Fixed by adding checkLoginIframe: false to both kc.init()
calls in dashboard.html and mesh.html (commit 109232d, deployed to
tobsco-locator.fly.dev). Confirmed live via curl that both pages now serve
checkLoginIframe: false.

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
