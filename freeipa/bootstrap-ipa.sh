#!/usr/bin/env bash
#
# Create the clearance and tenant structure in FreeIPA.
#
# The scheme is deliberately group-only — no LDAP schema extension. A custom
# attribute would be tidier to read, but extending FreeIPA's schema is a
# one-way door on a replicated directory, and getting an integer attribute
# through Keycloak into a token needs a script mapper (which most Keycloak
# builds ship disabled). Group membership travels the whole chain on stock
# mappers, so that is what this uses:
#
#   FreeIPA group  ->  Keycloak group  ->  Keycloak realm role  ->  token
#   clearance-7        clearance-7         clearance-7             realm_access.roles
#   tenant-acme        tenant-acme         (none)                  groups claim
#
# clearance.py reads the highest clearance-N role it finds, and the first
# tenant-* group. Idempotent: safe to re-run.

set -euo pipefail

: "${IPA_ADMIN_PASSWORD:?set IPA_ADMIN_PASSWORD (see freeipa/.env)}"
IPA_EXEC="${IPA_EXEC:-docker exec -i freeipa}"

echo "==> authenticating as admin"
$IPA_EXEC bash -c "echo '$IPA_ADMIN_PASSWORD' | kinit admin" >/dev/null

ipa_cmd() { $IPA_EXEC ipa "$@"; }

# Idempotence helper: FreeIPA exits non-zero on "already exists", which is not
# an error for our purposes but is indistinguishable from a real failure by
# exit code alone. Match on the message instead.
ensure() {
    local desc="$1"; shift
    local out
    if out=$(ipa_cmd "$@" 2>&1); then
        echo "    created: $desc"
    elif grep -qi "already exists" <<<"$out"; then
        echo "    exists:  $desc"
    else
        echo "    FAILED:  $desc" >&2
        echo "$out" >&2
        return 1
    fi
}

echo "==> clearance groups 10..1"
declare -A LEVELS=(
    [10]="root — owner; shell and arbitrary exec on the mesh"
    [9]="infra — deploys, YAML writes, migrations, DNS"
    [8]="operator — start/stop containers, trigger deploys"
    [7]="engineer — read compose/YAML, see SSH targets"
    [6]="staff — full mesh read incl. internal addressing"
    [5]="partner — full service list, addressing redacted"
    [4]="contractor — own tenant plus shared services"
    [3]="client — own tenant only"
    [2]="customer — own tenant, heavy redaction"
    [1]="guest — liveness only"
)
for lvl in 10 9 8 7 6 5 4 3 2 1; do
    ensure "clearance-$lvl" group-add "clearance-$lvl" --desc="${LEVELS[$lvl]}"
done

echo "==> tenant groups"
# One per customer/client org. Row-level filtering keys off these: a principal
# in tenant-acme sees only services whose owner/tenant metadata says "acme".
# Add real ones here, or with: ipa group-add tenant-<name> --desc="..."
for tenant in ${IPA_TENANTS:-acme globex}; do
    ensure "tenant-$tenant" group-add "tenant-$tenant" --desc="Tenant: $tenant"
done

echo "==> service account for Keycloak's LDAP bind"
# Read-only. Keycloak never writes back to FreeIPA in this design — FreeIPA is
# the source of truth for who exists and what level they hold.
if ! ipa_cmd user-show keycloak-bind >/dev/null 2>&1; then
    ipa_cmd user-add keycloak-bind \
        --first=Keycloak --last=Bind \
        --shell=/sbin/nologin \
        --password <<< "${KEYCLOAK_BIND_PASSWORD:?set KEYCLOAK_BIND_PASSWORD}
${KEYCLOAK_BIND_PASSWORD}"
    echo "    created: keycloak-bind"
    # FreeIPA forces a password change on first bind for new users, which would
    # break an unattended LDAP bind on the very first connect. Expire it far out.
    ipa_cmd user-mod keycloak-bind --setattr=krbPasswordExpiration=20380101000000Z >/dev/null
else
    echo "    exists:  keycloak-bind"
fi

echo
echo "==> done. Assign a level to someone with:"
echo "     ipa group-add-member clearance-7 --users=jdoe"
echo "     ipa group-add-member tenant-acme --users=jdoe"
echo
echo "    A user in two clearance groups gets the HIGHER level (clearance.py"
echo "    takes the max), so demote by removing the old group, not just adding"
echo "    a lower one."
