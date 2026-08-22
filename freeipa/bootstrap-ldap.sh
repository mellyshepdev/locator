#!/usr/bin/env bash
#
# Create the clearance and tenant groups directly over LDAP.
#
# bootstrap-ipa.sh uses the `ipa` CLI, which needs client enrolment — the one
# step that will not complete while FreeIPA runs with bridge networking (SPNEGO
# fails). The directory itself is fully up, and an IPA group is just an LDAP
# entry whose server-side plugins (ipa-uuid, DNA) generate ipaUniqueID and
# gidNumber on add, exactly as they do when the CLI performs the same write.
#
# Auth notes, both learned the hard way:
#   * GSSAPI, not a simple bind — the Directory Manager password could not be
#     passed through the ssh -> docker exec -> bash chain without mangling.
#   * The URI must be the FQDN. Against ldap://localhost the SASL bind asks for
#     ldap/localhost@REALM, which is not in the Kerberos database.
#
# gidNumber: -1 is the DNA plugin's magic value — posixGroup requires the
# attribute, and -1 tells 389-ds to allocate the next real GID from the
# "Posix IDs" range rather than taking the literal. Omitting it fails with
# 'missing attribute "gidNumber" required by object class "posixGroup"'.
#
# Success is confirmed by re-querying the directory, never by parsing ldapadd's
# output: it prints "adding new entry" *before* attempting, so that string is
# present on failures too.

set -uo pipefail

cd /mnt/omv_storage/swoopg111/server/security/freeipa
set -a; . ./.env; set +a

BASE="dc=theofficialblacksheepco,dc=online"
GROUPS_DN="cn=groups,cn=accounts,${BASE}"
URI="ldap://ipa.theofficialblacksheepco.online"

# Build one LDIF for every group, then a single authenticated add.
build_ldif() {
    while IFS='|' read -r cn desc; do
        [ -z "$cn" ] && continue
        cat <<LDIF
dn: cn=${cn},${GROUPS_DN}
objectClass: top
objectClass: groupofnames
objectClass: nestedgroup
objectClass: ipausergroup
objectClass: ipaobject
objectClass: posixgroup
cn: ${cn}
description: ${desc}
gidNumber: -1

LDIF
    done
}

GROUPS_SPEC="clearance-10|root - owner; shell and arbitrary exec on the mesh
clearance-9|infra - deploys, YAML writes, migrations, DNS
clearance-8|operator - start/stop containers, trigger deploys
clearance-7|engineer - read compose/YAML, see SSH targets
clearance-6|staff - full mesh read incl. internal addressing
clearance-5|partner - full service list, addressing redacted
clearance-4|contractor - own tenant plus shared services
clearance-3|client - own tenant only
clearance-2|customer - own tenant, heavy redaction
clearance-1|guest - liveness only"

for t in ${IPA_TENANTS:-acme globex}; do
    GROUPS_SPEC="${GROUPS_SPEC}
tenant-${t}|Tenant: ${t}"
done

LDIF_TEXT=$(build_ldif <<<"$GROUPS_SPEC")

echo "==> adding $(grep -c '^dn:' <<<"$LDIF_TEXT") groups"
printf '%s' "$LDIF_TEXT" | docker exec -i \
    -e PW="$IPA_ADMIN_PASSWORD" -e KRB5CCNAME=FILE:/tmp/bootstrap_cc freeipa bash -c '
      echo "$PW" | kinit admin >/dev/null 2>&1 || { echo "kinit failed"; exit 1; }
      cat > /tmp/groups.ldif
      # -c continues past entries that already exist, so this is re-runnable.
      ldapadd -c -Y GSSAPI -H '"$URI"' -f /tmp/groups.ldif 2>&1 \
        | grep -viE "^SASL|^adding new entry" | grep -vE "^$"
      rm -f /tmp/groups.ldif
    ' | sed 's/^/    /'

echo
echo "==> verifying against the directory"
docker exec -e PW="$IPA_ADMIN_PASSWORD" -e KRB5CCNAME=FILE:/tmp/bootstrap_cc freeipa bash -c '
  echo "$PW" | kinit admin >/dev/null 2>&1
  ldapsearch -Y GSSAPI -LLL -H '"$URI"' -b "'"$GROUPS_DN"'" \
    "(|(cn=clearance-*)(cn=tenant-*))" cn gidNumber 2>/dev/null \
    | grep -E "^cn:|^gidNumber:"
' | paste - - | sed 's/^/    /'
