"""
eBay Marketplace Account Deletion Notification Handler
"""
import hashlib
import json
import logging
import os

from flask import Flask, request, jsonify, Response

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger("ebay")

VERIFICATION_TOKEN = os.environ.get("EBAY_VERIFICATION_TOKEN", "")
ENDPOINT_URL = os.environ.get(
    "EBAY_ENDPOINT_URL",
    "https://ebay.theofficialblacksheepco.info/ebay/account-deletion",
)

app = Flask(__name__)


@app.route("/ebay/account-deletion", methods=["GET"])
def challenge():
    """
    eBay endpoint ownership challenge.
    SHA256(challengeCode + verificationToken + endpointURL) → lowercase hex.
    """
    challenge_code = request.args.get("challenge_code", "")
    if not challenge_code:
        logger.warning("[ebay] Challenge request missing challenge_code")
        return jsonify({"error": "Missing challenge_code"}), 400

    if not VERIFICATION_TOKEN or not ENDPOINT_URL:
        logger.error("[ebay] EBAY_VERIFICATION_TOKEN or EBAY_ENDPOINT_URL not set")
        return jsonify({"error": "Server misconfigured"}), 500

    # No separators between the three values — exact eBay spec
    digest = hashlib.sha256(
        (challenge_code + VERIFICATION_TOKEN + ENDPOINT_URL).encode()
    ).hexdigest()

    logger.info(f"[ebay] challenge_code      = {challenge_code}")
    logger.info(f"[ebay] verification_token  = {VERIFICATION_TOKEN}")
    logger.info(f"[ebay] endpoint_url        = {ENDPOINT_URL}")
    logger.info(f"[ebay] challengeResponse   = {digest}")

    response = Response(
        json.dumps({"challengeResponse": digest}),
        status=200,
        mimetype="application/json",
    )
    return response


@app.route("/ebay/account-deletion", methods=["POST"])
def account_deletion():
    """
    eBay Marketplace Account Deletion notification delivery.
    Acknowledges with 200 and logs the event.
    """
    body = request.get_json(silent=True) or {}
    topic = body.get("metadata", {}).get("topic", "unknown")
    notif_id = body.get("notification", {}).get("notificationId", "-")
    user_id = body.get("notification", {}).get("data", {}).get("userId", "-")

    logger.info(f"[ebay] Notification received: topic={topic} id={notif_id} userId={user_id}")

    return jsonify({"status": "OK"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
