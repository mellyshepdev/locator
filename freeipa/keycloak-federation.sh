#!/usr/bin/env bash
#
# Federate FreeIPA into Keycloak and make clearance land in the access token.
#
# Run against the Keycloak that already fronts the Locator (realm "blacksheep",
# client "locator"). Idempotent — re-running reconciles rather than duplicating.
#
# What it builds, end to end:
#
#   FreeIPA (LDAP)            Keycloak                         token
#   ──────────────            ────────                         ─────
#   uid=jdoe               →  federated user jdoe
#   memberOf clearance-7   →  group /clearance-7
#                          →  realm role clearance-7        →  realm_access.roles
#   memberOf tenant-acme   →  group /tenant-acme            →  groups: ["tenant-acme"]
#                                                           →  aud: ["locator"]
#
# clearance.py then reads the highest clearance-N role and the first tenant-*
# group. No script mappers, so this works on a stock Keycloak build.

set -euo pipefail

KC_URL="${KC_URL:-https://bsco-keycloak.fly.dev}"
REALM="${KC_REALM:-blacksheep}"
CLIENT_ID="${KC_CLIENT_ID:-locator}"
KCADM="${KCADM:-kcadm.sh}"

IPA_HOST="${IPA_HOST:-ipa.theofficialblacksheepco.online}"
IPA_BASE_DN="${IPA_BASE_DN:-dc=theofficialblacksheepco,dc=online}"

: "${KC_ADMIN_USER:?set KC_ADMIN_USER}"
: "${KC_ADMIN_PASSWORD:?set KC_ADMIN_PASSWORD}"
: "${KEYCLOAK_BIND_PASSWORD:?set KEYCLOAK_BIND_PASSWORD (same value bootstrap-ipa.sh used)}"

echo "==> logging in to $KC_URL as $KC_ADMIN_USER"
$KCADM config credentials --server "$KC_URL" --realm master \
    --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD"

# ── 1. LDAP user federation ────────────────────────────────────────────────
# ldaps on 636, not StartTLS on 389: FreeIPA presents its own CA, and a
# plaintext bind would put the service-account password on the wire between
# Keycloak (fly.dev) and the IPA host.
echo "==> user federation provider"
FED_ID=$($KCADM get components -r "$REALM" \
    --query "name=freeipa" --fields id --format csv --noquotes 2>/dev/null | head -1 || true)

FED_PAYLOAD=$(cat <<JSON
{
  "name": "freeipa",
  "providerId": "ldap",
  "providerType": "org.keycloak.storage.UserStorageProvider",
  "config": {
    "enabled": ["true"],
    "priority": ["0"],
    "vendor": ["rhds"],
    "connectionUrl": ["ldaps://${IPA_HOST}:636"],
    "usersDn": ["cn=users,cn=accounts,${IPA_BASE_DN}"],
    "bindDn": ["uid=keycloak-bind,cn=users,cn=accounts,${IPA_BASE_DN}"],
    "bindCredential": ["${KEYCLOAK_BIND_PASSWORD}"],
    "authType": ["simple"],
    "usernameLDAPAttribute": ["uid"],
    "rdnLDAPAttribute": ["uid"],
    "uuidLDAPAttribute": ["ipaUniqueID"],
    "userObjectClasses": ["inetOrgPerson, organizationalPerson"],
    "searchScope": ["1"],
    "editMode": ["READ_ONLY"],
    "importEnabled": ["true"],
    "syncRegistrations": ["false"],
    "trustEmail": ["true"],
    "useTruststoreSpi": ["always"],
    "connectionPooling": ["true"],
    "pagination": ["true"],
    "batchSizeForSync": ["1000"],
    "fullSyncPeriod": ["86400"],
    "changedSyncPeriod": ["600"],
    "cachePolicy": ["DEFAULT"]
  }
}
JSON
)

if [[ -n "$FED_ID" ]]; then
    echo "    updating existing provider $FED_ID"
    echo "$FED_PAYLOAD" | $KCADM update "components/$FED_ID" -r "$REALM" -f -
else
    FED_ID=$(echo "$FED_PAYLOAD" | $KCADM create components -r "$REALM" -f - --id)
    echo "    created provider $FED_ID"
fi

# ── 2. group mapper ────────────────────────────────────────────────────────
# memberOf rather than a member-attribute search: FreeIPA maintains memberOf
# server-side, and the search strategy re-reads every group on every login.
echo "==> group-ldap-mapper"
GRP_MAPPER_ID=$($KCADM get components -r "$REALM" \
    --query "parent=$FED_ID" --query "name=ipa-groups" \
    --fields id --format csv --noquotes 2>/dev/null | head -1 || true)

GRP_PAYLOAD=$(cat <<JSON
{
  "name": "ipa-groups",
  "providerId": "group-ldap-mapper",
  "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
  "parentId": "${FED_ID}",
  "config": {
    "groups.dn": ["cn=groups,cn=accounts,${IPA_BASE_DN}"],
    "group.name.ldap.attribute": ["cn"],
    "group.object.classes": ["groupOfNames"],
    "preserve.group.inheritance": ["false"],
    "membership.ldap.attribute": ["member"],
    "membership.attribute.type": ["DN"],
    "membership.user.ldap.attribute": ["uid"],
    "mode": ["READ_ONLY"],
    "user.roles.retrieve.strategy": ["GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE"],
    "memberof.ldap.attribute": ["memberOf"],
    "groups.path": ["/"],
    "drop.non.existing.groups.during.sync": ["false"]
  }
}
JSON
)

if [[ -n "$GRP_MAPPER_ID" ]]; then
    echo "$GRP_PAYLOAD" | $KCADM update "components/$GRP_MAPPER_ID" -r "$REALM" -f -
    echo "    updated"
else
    echo "$GRP_PAYLOAD" | $KCADM create components -r "$REALM" -f - >/dev/null
    echo "    created"
fi

# ── 3. sync, so the groups exist before roles are bound to them ────────────
echo "==> triggering full LDAP sync (this can take a minute)"
$KCADM create "user-storage/$FED_ID/sync?action=triggerFullSync" -r "$REALM" >/dev/null || \
    echo "    sync call returned non-zero — check the Keycloak log before continuing"

# ── 4. realm roles + bind each to its group ────────────────────────────────
echo "==> clearance realm roles"
for lvl in 10 9 8 7 6 5 4 3 2 1; do
    role="clearance-$lvl"
    if $KCADM get "roles/$role" -r "$REALM" >/dev/null 2>&1; then
        echo "    exists:  $role"
    else
        $KCADM create roles -r "$REALM" -s "name=$role" \
            -s "description=Locator clearance level $lvl" >/dev/null
        echo "    created: $role"
    fi
    # Bind the role to the same-named group so LDAP membership alone decides
    # the level — nobody has to remember to also grant a role by hand.
    if $KCADM add-roles -r "$REALM" --gname "$role" --rolename "$role" >/dev/null 2>&1; then
        echo "      bound to group /$role"
    else
        echo "      NOTE: group /$role not present yet — re-run after the sync finishes"
    fi
done

# ── 5. protocol mappers on the locator client ──────────────────────────────
echo "==> protocol mappers on client '$CLIENT_ID'"
CLIENT_UUID=$($KCADM get clients -r "$REALM" \
    --query "clientId=$CLIENT_ID" --fields id --format csv --noquotes | head -1)
[[ -n "$CLIENT_UUID" ]] || { echo "client '$CLIENT_ID' not found in realm '$REALM'" >&2; exit 1; }

add_mapper() {
    local name="$1" payload="$2"
    local existing
    existing=$($KCADM get "clients/$CLIENT_UUID/protocol-mappers/models" -r "$REALM" \
        --fields name,id --format csv --noquotes 2>/dev/null | grep "^$name," | cut -d, -f2 || true)
    if [[ -n "$existing" ]]; then
        echo "$payload" | $KCADM update "clients/$CLIENT_UUID/protocol-mappers/models/$existing" -r "$REALM" -f -
        echo "    updated: $name"
    else
        echo "$payload" | $KCADM create "clients/$CLIENT_UUID/protocol-mappers/models" -r "$REALM" -f - >/dev/null
        echo "    created: $name"
    fi
}

# groups claim — carries tenant-* membership for row-level filtering.
add_mapper "groups" "$(cat <<'JSON'
{
  "name": "groups",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-group-membership-mapper",
  "config": {
    "claim.name": "groups",
    "full.path": "false",
    "access.token.claim": "true",
    "id.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}
JSON
)"

# audience — clearance.py verifies aud, and Keycloak omits the client from its
# own tokens unless something puts it there.
add_mapper "locator-audience" "$(cat <<JSON
{
  "name": "locator-audience",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "config": {
    "included.client.audience": "${CLIENT_ID}",
    "access.token.claim": "true",
    "id.token.claim": "false"
  }
}
JSON
)"

# Optional: a literal integer `clearance` claim. clearance.py prefers this and
# falls back to the roles above, so it is a nicety, not a requirement — set
# CLEARANCE_USER_ATTRIBUTE=1 only if you also add a matching user-attribute
# mapper on the LDAP provider.
if [[ "${CLEARANCE_USER_ATTRIBUTE:-0}" == "1" ]]; then
    add_mapper "clearance" "$(cat <<'JSON'
{
  "name": "clearance",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "user.attribute": "clearance",
    "claim.name": "clearance",
    "jsonType.label": "int",
    "access.token.claim": "true",
    "id.token.claim": "true"
  }
}
JSON
)"
fi

echo
echo "==> done."
echo "    Verify with a real login, then decode the token:"
echo "      curl -s -d client_id=$CLIENT_ID -d username=<user> -d password=<pw> \\"
echo "        -d grant_type=password \\"
echo "        $KC_URL/realms/$REALM/protocol/openid-connect/token \\"
echo "        | python3 -c 'import sys,json,base64; t=json.load(sys.stdin)[\"access_token\"].split(\".\")[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(t+\"==\")),indent=2))'"
echo
echo "    Expect realm_access.roles to contain clearance-<n> and groups to"
echo "    contain tenant-<name>. Only then set CLEARANCE_ENFORCE=true."
