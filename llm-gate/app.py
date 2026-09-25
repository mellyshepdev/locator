#!/usr/bin/env python3
"""llm-gate — fail-closed inference gate (unit2).

Owns the public LLM ports and forwards to the real backends on loopback:

    100.64.118.105:11434 -> 127.0.0.1:11435  (ollama container)
    0.0.0.0:8095         -> 127.0.0.1:8096   (llama-server.service)
    100.64.118.105:8082  -> 127.0.0.1:8083   (llama-cpp container)

Any request that would RUN inference (POST /api/generate, /api/chat,
/v1/chat/completions, /completion, embeddings, ...) must first hold an
ACKNOWLEDGED locator power drain — the room is made before the model is
asked. A drain that never acknowledges, failed stops, or an unreachable
locator all fail CLOSED: the request is refused with 503 and never
reaches the backend. Metadata paths (/api/tags, /v1/models, /api/ps,
health) pass through ungated.

Lease: each gated request refreshes last_used; after IDLE_LEASE_S of no
inference the drain is released via /api/power/restore. After a failed
drain, RETRY_BACKOFF_S must pass before another drain is attempted —
requests in the backoff window refuse fast rather than churn stop loops.

DRAIN_EXCLUDE carries known LLM consumers (agent-0, forge, site-chat,
perplexica, searxng, ...): a drain triggered BY an inference request must
never stop the container that made the request — that call would kill its
own caller mid-flight.
"""
import asyncio
import logging
import os
import time

from aiohttp import ClientError, ClientSession, ClientTimeout, web

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s llm-gate %(levelname)s %(message)s")
log = logging.getLogger("llm-gate")

LOCATOR_URL = os.environ.get(
    "LOCATOR_URL", "http://100.99.131.20:50500").rstrip("/")
LOCATOR_HOST = os.environ.get("LOCATOR_HOST_HEADER", "")
POWER_TOKEN = os.environ.get("POWER_TOKEN", "")
DRAIN_UNITS = [u.strip() for u in
               os.environ.get("DRAIN_UNITS", "unit2,unit7").split(",")
               if u.strip()]
DRAIN_EXCLUDE = [n.strip() for n in
                 os.environ.get("DRAIN_EXCLUDE", "").split(",") if n.strip()]
ACK_TIMEOUT_S = float(os.environ.get("ACK_TIMEOUT_S", "300"))
POLL_S = float(os.environ.get("POLL_S", "5"))
IDLE_LEASE_S = float(os.environ.get("IDLE_LEASE_S", "1800"))
RETRY_BACKOFF_S = float(os.environ.get("RETRY_BACKOFF_S", "60"))

# ROUTES: "bind:port->upstream|kind,bind:port->upstream|kind,..."
ROUTES = []
for spec in os.environ.get("ROUTES", "").split(","):
    spec = spec.strip()
    if not spec:
        continue
    left, _, right = spec.partition("->")
    upstream, _, kind = right.partition("|")
    host, _, port = left.rpartition(":")
    ROUTES.append({"host": host, "port": int(port),
                   "upstream": upstream.rstrip("/"), "kind": kind or "openai"})

# POST paths that actually spend model time. Everything else is metadata
# and passes through without a drain.
GATED = {
    "ollama": {"/api/generate", "/api/chat", "/api/embed", "/api/embeddings"},
    "openai": {"/v1/chat/completions", "/v1/completions", "/v1/embeddings",
               "/completion", "/completions", "/infill",
               "/embedding", "/embeddings"},
}

HOP = {"connection", "keep-alive", "proxy-authenticate",
       "proxy-authorization", "te", "trailers", "transfer-encoding",
       "upgrade", "host", "content-length"}

STATE = {"phase": "idle",       # idle | draining | ready | failed
         "drain_id": None,
         "last_used": 0.0,
         "fail_at": 0.0,
         "detail": ""}
STARTED = time.time()
SESSION: ClientSession


def _locator_headers():
    h = {"Content-Type": "application/json"}
    if LOCATOR_HOST:
        h["Host"] = LOCATOR_HOST
    if POWER_TOKEN:
        h["X-Power-Token"] = POWER_TOKEN
    return h


async def _restore(sid) -> bool:
    """POST the restore; True when the locator accepted it. Callers that
    clear state on success must NOT clear on False — a restore that never
    landed would leave containers stopped forever."""
    try:
        async with SESSION.post(
                f"{LOCATOR_URL}/api/power/restore",
                json={"drain_id": sid}, headers=_locator_headers(),
                timeout=ClientTimeout(total=15)) as r:
            log.info("restore %s -> %s", sid, r.status)
            return r.status == 200
    except Exception as exc:
        log.warning("restore %s failed: %s", sid, exc)
        return False


async def _drain_task():
    """POST the drain and poll it. Fail-closed: any outcome short of a
    clean acknowledgement leaves phase=failed and rolls back partial stops."""
    sid = None
    try:
        async with SESSION.post(
                f"{LOCATOR_URL}/api/power/drain",
                json={"units": DRAIN_UNITS, "exclude": DRAIN_EXCLUDE,
                      "reason": "llm-gate"},
                headers=_locator_headers(),
                timeout=ClientTimeout(total=15)) as r:
            data = await r.json()
            sid = data["drain_id"]
        STATE["drain_id"] = sid
        log.info("drain %s requested on %s (exclude=%d names)",
                 sid, DRAIN_UNITS, len(DRAIN_EXCLUDE))
        deadline = time.monotonic() + ACK_TIMEOUT_S
        while time.monotonic() < deadline:
            await asyncio.sleep(POLL_S)
            async with SESSION.get(
                    f"{LOCATOR_URL}/api/power/drain/{sid}",
                    headers=_locator_headers(),
                    timeout=ClientTimeout(total=15)) as r:
                if r.status == 404:
                    raise RuntimeError(
                        f"drain {sid} vanished (locator restart?)")
                st = await r.json()
            if st.get("acknowledged"):
                if st.get("failed"):
                    raise RuntimeError(
                        f"drain {sid} acknowledged with failed stops: "
                        f"{st['failed']}")
                STATE["phase"] = "ready"
                STATE["detail"] = f"drain {sid} holding {len(st.get('stopped', []))} stops"
                log.info("%s", STATE["detail"])
                return
        raise RuntimeError(
            f"drain {sid} not acknowledged within {ACK_TIMEOUT_S}s")
    except Exception as exc:
        STATE["phase"] = "failed"
        STATE["fail_at"] = time.monotonic()
        STATE["detail"] = str(exc)[:300]
        log.warning("drain failed closed: %s", STATE["detail"])
        if sid:
            await _restore(sid)   # roll back whatever did stop


async def ensure_drained():
    """True once an acknowledged drain is held; False when refusing."""
    STATE["last_used"] = time.monotonic()
    deadline = time.monotonic() + ACK_TIMEOUT_S + 15
    while time.monotonic() < deadline:
        ph = STATE["phase"]
        if ph == "ready":
            return True
        if ph == "failed":
            return False
        if ph == "idle":
            if time.monotonic() - STATE["fail_at"] < RETRY_BACKOFF_S:
                return False
            STATE["phase"] = "draining"
            STATE["detail"] = ""
            asyncio.ensure_future(_drain_task())
        await asyncio.sleep(2)
    return False


async def _reaper():
    """Release the drain after IDLE_LEASE_S of no gated traffic."""
    while True:
        await asyncio.sleep(30)
        if (STATE["phase"] == "ready"
                and time.monotonic() - STATE["last_used"] > IDLE_LEASE_S):
            sid = STATE["drain_id"]
            log.info("idle lease expired, restoring %s", sid)
            if await _restore(sid) and STATE["drain_id"] == sid:
                STATE.update(phase="idle", drain_id=None, detail="")


async def _proxy(request):
    route = request.app["route"]
    path = request.rel_url.path
    if (request.method == "POST"
            and path in GATED.get(route["kind"], set())):
        if not await ensure_drained():
            return web.json_response(
                {"error": "llm-gate refused: power drain not satisfied",
                 "detail": STATE["detail"]}, status=503)
    url = route["upstream"] + str(request.rel_url)
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in HOP}
    headers["Host"] = route["upstream"].split("://", 1)[-1]
    body = request.content.iter_any() if request.can_read_body else None
    try:
        async with SESSION.request(request.method, url,
                                   headers=headers, data=body) as resp:
            out = {k: v for k, v in resp.headers.items()
                   if k.lower() not in HOP}
            sr = web.StreamResponse(status=resp.status,
                                    reason=resp.reason, headers=out)
            await sr.prepare(request)
            async for chunk in resp.content.iter_any():
                await sr.write(chunk)
            await sr.write_eof()
            return sr
    except (ClientError, asyncio.TimeoutError) as exc:
        return web.json_response(
            {"error": f"llm-gate upstream error: {exc}"}, status=502)
    except (ConnectionResetError, asyncio.CancelledError):
        raise
    except Exception as exc:
        log.warning("proxy stream failed: %s", exc)
        raise


async def _status(request):
    return web.json_response({
        "phase": STATE["phase"], "drain_id": STATE["drain_id"],
        "detail": STATE["detail"], "last_used_age_s":
            round(time.monotonic() - STATE["last_used"], 1)
            if STATE["last_used"] else None,
        "drain_units": DRAIN_UNITS, "exclude": DRAIN_EXCLUDE,
        "idle_lease_s": IDLE_LEASE_S,
        "routes": ROUTES, "uptime_s": round(time.time() - STARTED, 1)})


def _make_app(route):
    app = web.Application()
    app["route"] = route
    app.router.add_get("/llm-gate/status", _status)
    app.router.add_route("*", "/{tail:.*}", _proxy)
    return app


async def _on_shutdown(_app):
    sid = STATE.get("drain_id")
    if sid and STATE["phase"] in ("ready", "draining"):
        await _restore(sid)


async def main():
    global SESSION
    SESSION = ClientSession(timeout=ClientTimeout(
        total=None, sock_connect=10, sock_read=3600))
    for route in ROUTES:
        app = _make_app(route)
        app.on_shutdown.append(_on_shutdown)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, route["host"], route["port"]).start()
        log.info("listening %s:%s -> %s (%s)",
                 route["host"], route["port"], route["upstream"],
                 route["kind"])
    asyncio.ensure_future(_reaper())
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
