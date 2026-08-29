#!/usr/bin/env bash
set -uo pipefail
cd /mnt/omv_storage/swoopg111/server/security/freeipa
set -a; . ./.env; set +a
# Kerberos rather than a simple bind: kinit works, and it keeps the password
# out of argv entirely.
docker exec -e PW="$IPA_ADMIN_PASSWORD" freeipa bash -c '
  echo "$PW" | kinit admin >/dev/null 2>&1 || { echo "kinit failed"; exit 1; }
  ldapsearch -Y GSSAPI -H ldap://localhost \
    -b "cn=groups,cn=accounts,dc=theofficialblacksheepco,dc=online" \
    "(|(cn=clearance-*)(cn=tenant-*))" cn gidNumber 2>/dev/null \
    | grep -E "^cn: |^gidNumber: |^# numEntries"
'
