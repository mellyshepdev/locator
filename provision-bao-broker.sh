#!/usr/bin/env bash
# Give the Locator its own OpenBao identity, so it can act as the fleet's
# secrets broker.
#
# RUN THIS ON unit4 (where OpenBao and the locator both live):
#     ssh unit4
#     bash ~/projects/locator/provision-bao-broker.sh
#
# It reads the root token from UNSEAL-KEEP-SAFE.json, creates a least-privilege
# policy, mints a renewable periodic token for the locator, and writes that
# token to a file the locator container mounts read-only.
#
# The root token is never echoed, never exported into a child environment that
# outlives the script, and never leaves this box.
set -euo pipefail

BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
UNSEAL_FILE="${UNSEAL_FILE:-$HOME/server/security/openbao/UNSEAL-KEEP-SAFE.json}"
TOKEN_OUT="${TOKEN_OUT:-$HOME/projects/locator/secrets/bao.token}"
POLICY_NAME="locator-broker"
# 30 days, renewed by the locator on a timer. A periodic token does not expire
# while it is being renewed, but it DOES die silently if renewal stops — which
# is why /api/secrets/status reports the remaining TTL.
TOKEN_PERIOD="720h"

command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }
[ -r "$UNSEAL_FILE" ] || { echo "ERROR: cannot read $UNSEAL_FILE" >&2; exit 1; }

# Accept either shape the init output is commonly saved in.
ROOT_TOKEN="$(jq -r '.root_token // .root // empty' "$UNSEAL_FILE")"
[ -n "$ROOT_TOKEN" ] || {
  echo "ERROR: no root_token field in $UNSEAL_FILE" >&2; exit 1; }

bao_api() {  # bao_api METHOD PATH [JSON]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS --max-time 15 -X "$method" \
      -H "X-Vault-Token: $ROOT_TOKEN" -H "Content-Type: application/json" \
      -d "$body" "$BAO_ADDR/v1/$path"
  else
    curl -sS --max-time 15 -X "$method" \
      -H "X-Vault-Token: $ROOT_TOKEN" "$BAO_ADDR/v1/$path"
  fi
}

echo "▸ checking OpenBao at $BAO_ADDR"
health="$(curl -sS --max-time 10 "$BAO_ADDR/v1/sys/health")"
if [ "$(jq -r '.sealed' <<<"$health")" != "false" ]; then
  echo "ERROR: OpenBao is sealed — unseal it first." >&2; exit 1
fi
echo "  ok — version $(jq -r '.version' <<<"$health"), unsealed"

# ── policy ────────────────────────────────────────────────────────────────
# Read anywhere under secret/, but WRITE only under secret/compose/* — the
# path the sweeper quarantines into. A bug in the sweeper can therefore create
# and overwrite its own quarantine entries and nothing else; it cannot clobber
# secret/reech or anything a human curated.
read -r -d '' POLICY <<'HCL' || true
path "secret/data/*" {
  capabilities = ["read"]
}

path "secret/metadata/*" {
  capabilities = ["read", "list"]
}

path "secret/data/compose/*" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/compose/*" {
  capabilities = ["read", "list"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
HCL

echo "▸ writing policy '$POLICY_NAME'"
resp="$(bao_api PUT "sys/policies/acl/$POLICY_NAME" \
  "$(jq -n --arg p "$POLICY" '{policy: $p}')")"
if [ -n "$resp" ] && [ "$(jq -r '.errors // empty | length' <<<"$resp")" != "" ]; then
  echo "ERROR writing policy: $resp" >&2; exit 1
fi
echo "  ok"

# ── token ─────────────────────────────────────────────────────────────────
echo "▸ minting a periodic token for the locator"
tok_resp="$(bao_api POST "auth/token/create" "$(jq -n \
  --arg pol "$POLICY_NAME" --arg per "$TOKEN_PERIOD" \
  '{policies: [$pol], period: $per, display_name: "locator-broker",
    renewable: true, no_parent: true}')")"
NEW_TOKEN="$(jq -r '.auth.client_token // empty' <<<"$tok_resp")"
[ -n "$NEW_TOKEN" ] || { echo "ERROR minting token: $tok_resp" >&2; exit 1; }

mkdir -p "$(dirname "$TOKEN_OUT")"
umask 077
printf '%s' "$NEW_TOKEN" > "$TOKEN_OUT"
chmod 600 "$TOKEN_OUT"
echo "  ok — token written to $TOKEN_OUT (mode 600)"

# ── verify with the NEW token, not the root one ───────────────────────────
echo "▸ verifying the broker token"
check="$(curl -sS --max-time 10 -H "X-Vault-Token: $NEW_TOKEN" \
  "$BAO_ADDR/v1/auth/token/lookup-self")"
echo "  policies: $(jq -rc '.data.policies' <<<"$check")"
echo "  ttl:      $(jq -r '.data.ttl' <<<"$check")s  renewable: $(jq -r '.data.renewable' <<<"$check")"

echo "▸ verifying write access to the quarantine path"
probe="$(curl -sS --max-time 10 -X POST -H "X-Vault-Token: $NEW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"probe":"ok"}}' "$BAO_ADDR/v1/secret/data/compose/_provision_probe")"
if [ "$(jq -r '.errors // empty | length' <<<"$probe")" != "" ] && \
   [ "$(jq -r '.errors[0] // empty' <<<"$probe")" != "" ]; then
  echo "ERROR: broker token cannot write to secret/compose/*: $probe" >&2; exit 1
fi
curl -sS --max-time 10 -X DELETE -H "X-Vault-Token: $ROOT_TOKEN" \
  "$BAO_ADDR/v1/secret/metadata/compose/_provision_probe" >/dev/null
echo "  ok — write + cleanup succeeded"

unset ROOT_TOKEN NEW_TOKEN

cat <<EOF

✅ Done. Next:
   1. Add to ~/projects/locator/docker-compose.yml (already staged in git if you
      pulled this change):
        volumes:  - ./secrets:/app/secrets:ro
        environment: BAO_ADDR / BAO_TOKEN_FILE
   2. docker compose up -d --build locator
   3. curl -s http://127.0.0.1:50500/api/secrets/status | jq
      -> expects {"reachable":true,"sealed":false,"configured":true,"token_ok":true}
EOF
