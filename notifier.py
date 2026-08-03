"""
Provider-agnostic alert notifier for the Locator.

Each provider is independently optional — if its env vars aren't set, that
provider's function is a silent no-op (logged once, not on every call) rather
than an error. This lets code call notify_all() unconditionally without
caring which providers are actually configured yet.

Current providers:
  Slack   — POST to an incoming webhook. Live as soon as SLACK_WEBHOOK_URL
            is set as a Fly secret.
  Matrix  — POST a message to a room via the Client-Server API, using a bot
            access token. Inert until MATRIX_HOMESERVER_URL/MATRIX_ACCESS_TOKEN/
            MATRIX_ROOM_ID are set — expected to stay inert for a while,
            since Synapse/Element reportedly need to be rebuilt after the
            unit1/2/4 outage (separate project, not handled here).

Matrix "call" scope (per explicit product decision): ring/invite only — this
sends an m.call.invite event so the target rings, but does NOT establish
real two-way audio. The standard Python Matrix client (matrix-nio) has
call-signaling support but no WebRTC media stack; actual two-way audio was
explicitly deferred to a separate follow-up spike, not built here.
"""
import os
import time
import uuid

import requests

# SLACK_WEBHOOK_URL is the preferred name; ALERT_WEBHOOK_URL is locator.py's
# existing (previously-unused) generic webhook slot — accepted as a fallback
# so an already-configured value there doesn't need duplicating.
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "") or os.environ.get("ALERT_WEBHOOK_URL", "")

MATRIX_HOMESERVER_URL = os.environ.get("MATRIX_HOMESERVER_URL", "")
MATRIX_ACCESS_TOKEN   = os.environ.get("MATRIX_ACCESS_TOKEN", "")
MATRIX_ROOM_ID        = os.environ.get("MATRIX_ROOM_ID", "")

_warned = set()


def _warn_once(key, message):
    if key not in _warned:
        _warned.add(key)
        print(f"⚠️  notifier: {message}")


def notify_slack(text):
    if not SLACK_WEBHOOK_URL:
        _warn_once("slack", "SLACK_WEBHOOK_URL not set — Slack alerts are a no-op")
        return False
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        print(f"⚠️  notifier: Slack post failed: {e}")
        return False


def _matrix_configured():
    return bool(MATRIX_HOMESERVER_URL and MATRIX_ACCESS_TOKEN and MATRIX_ROOM_ID)


def notify_matrix_message(text):
    if not _matrix_configured():
        _warn_once("matrix_msg", "MATRIX_* env vars not set — Matrix alerts are a no-op (Synapse likely needs rebuilding after the unit1/2/4 outage)")
        return False
    try:
        txn_id = uuid.uuid4().hex
        url = (
            f"{MATRIX_HOMESERVER_URL.rstrip('/')}/_matrix/client/v3/rooms/"
            f"{MATRIX_ROOM_ID}/send/m.room.message/{txn_id}"
        )
        resp = requests.put(
            url,
            headers={"Authorization": f"Bearer {MATRIX_ACCESS_TOKEN}"},
            json={"msgtype": "m.text", "body": text},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"⚠️  notifier: Matrix message failed: {e}")
        return False


def notify_matrix_call(reason=""):
    """
    Ring/invite only — sends an m.call.invite so the room/device rings.
    Does not guarantee real two-way audio (see module docstring). Best-effort:
    if this doesn't actually ring anything usable once Matrix is rebuilt,
    that's the expected state of an intentionally-deferred feature, not a bug
    to chase here.
    """
    if not _matrix_configured():
        _warn_once("matrix_call", "MATRIX_* env vars not set — Matrix call-invite is a no-op")
        return False
    try:
        call_id = uuid.uuid4().hex
        txn_id = uuid.uuid4().hex
        url = (
            f"{MATRIX_HOMESERVER_URL.rstrip('/')}/_matrix/client/v3/rooms/"
            f"{MATRIX_ROOM_ID}/send/m.call.invite/{txn_id}"
        )
        resp = requests.put(
            url,
            headers={"Authorization": f"Bearer {MATRIX_ACCESS_TOKEN}"},
            json={
                "call_id": call_id,
                "version": "1",
                "lifetime": 30000,
                # No real SDP offer — this is a ring/invite signal only, not a
                # working WebRTC session. Real audio is out of scope here.
                "offer": {"type": "offer", "sdp": ""},
                "party_id": "locator-alert-bot",
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"⚠️  notifier: Matrix call-invite failed: {e}")
        return False


def notify_all(text, urgent=False):
    """Fire every configured provider; each is independently best-effort."""
    notify_slack(text)
    notify_matrix_message(text)
    if urgent:
        notify_matrix_call(reason=text)
