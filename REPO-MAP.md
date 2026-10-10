# REPO-MAP — fleet source → deployment inventory

Generated from `repomap` DB run **3** (2026-10-06 14:18:32, by manual/devin).
initial fleet repo-map build

History: every refresh inserts a new run — `psql repomap -c "select * from runs"` —
`repo_state` rows per run preserve prior versions of this map.
Refresh: `~/projects/repo-map/repomap.sh` → then `python3 ~/projects/repo-map/gen_md.py`.


## Deployed services — repo ↔ live container

| host | repo | last push | deploys to | live containers | drift |
|------|------|-----------|------------|-----------------|-------|
| gitlab | blackshepherddeveloper-group/blackshepherddeveloper-project | 2026-09-20 | unit4 | main-website@unit4:Up; website-backend@unit4:Up | repo 2026-09-20 · api.theofficialblacksheepco.com, app.prime-quality |
| gitlab | blackshepherddeveloper-group/keycloak | 2026-09-08 | unit4 | keycloak@unit4:Up | repo 2026-09-08 · auth.theofficialblacksheepco.online, login.theoffi |
| gitlab | blackshepherddeveloper-group/locator | 2026-10-01 | unit4 | locator@unit4:Up | repo 2026-10-01 · -ipa.theofficialblacksheepco.online, a0.theofficia |
| gitlab | blackshepherddeveloper-group/searchsearcher | 2026-09-10 | unit4 | searchsearcher-oauth@unit4:Up; searchsearcher-postgres@unit4 | repo 2026-09-10 · auth.theofficialblacksheepco.com, auth.theofficial |
| gitlab | blackshepherddeveloper-group/site-chat | 2026-09-30 | unit4 | site-chat@unit4:Up | repo 2026-09-30 · auth.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper/blackshepherddeveloper-project | 2026-10-01 | unit4 | main-website@unit4:Up; website-backend@unit4:Up | repo 2026-10-01 · api.theofficialblacksheepco.com, app.prime-quality |
| gitlab | blackshepherddeveloper/calendar | 2026-06-25 | unit8,unit9 | apache@unit8:Up; nasa@unit9:Exited | repo 2026-06-25 · calendar.theofficialblacksheepco.online, nasa.theo |
| gitlab | blackshepherddeveloper/ceph-cluster | 2026-09-30 | unit4 | ceph-mounter@unit4:Up | repo 2026-09-30 |
| gitlab | blackshepherddeveloper/compose-stacks | 2026-10-03 | unit2,unit4,unit9 | fluent-bit@unit9:Up; inventory-web@unit4:Created; lago-api@u | repo 2026-10-03 · a0.theofficialblacksheepco.online, app.prime-quali |
| gitlab | blackshepherddeveloper/edge-apache | 2026-09-29 | unit8 | apache@unit8:Up | repo 2026-09-29 · nasa.theofficialblacksheepco.online, sheldon.theof |
| gitlab | blackshepherddeveloper/edge-networking | 2026-09-29 | unit2,unit9 | haproxy@unit9:Up; traefik@unit2:Up; varnish@unit9:Up | repo 2026-09-29 · auth.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper/edge-unit9 | 2026-09-30 | unit9 | haproxy@unit9:Up; varnish@unit9:Up | repo 2026-09-30 · mail.theofficialblacksheepco.com, matrix.prime-qua |
| gitlab | blackshepherddeveloper/inventory | 2026-10-01 | unit4 | inventory-web@unit4:Created | repo 2026-10-01 · auth.theofficialblacksheepco.com, inventory.theoff |
| gitlab | blackshepherddeveloper/keycloak-u2 | 2026-09-28 | unit4 | keycloak@unit4:Up | repo 2026-09-28 · auth.theofficialblacksheepco.com, pg-node1-vpn.pri |
| gitlab | blackshepherddeveloper/ops-dashboard | 2026-09-30 | unit4 | ops-dashboard@unit4:Up; ops-pgdb@unit4:Up | repo 2026-09-30 · app.prime-quality.online, dash.theofficialblackshe |
| gitlab | blackshepherddeveloper/petal-stone | 2026-09-30 | unit4 | petal-stone-web@unit4:Up | repo 2026-09-30 |
| gitlab | blackshepherddeveloper/unit2-networking | 2026-09-30 | unit2,unit9 | haproxy@unit9:Up; traefik@unit2:Up; varnish@unit9:Up | repo 2026-09-30 · auth.theofficialblacksheepco.com, locator-nw.prime |
| gitlab | blackshepherddeveloper/unit4-puffbase | 2026-09-30 | unit4 | puffbase@unit4:Up; puffbase-crew@unit4:Up; puffbase-runner@u | repo 2026-09-30 · auth.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper/unit7-apache | 2026-09-28 | unit8 | apache@unit8:Up | repo 2026-09-28 · element.theofficialblacksheepco.online |
| gitlab | blackshepherddeveloper/unit7-traefik | 2026-09-29 | unit2 | traefik@unit2:Up | repo 2026-09-29 |
| gitlab | blackshepherddeveloper/welcome | 2026-10-02 | unit4 | hub-backend@unit4:Up; hub-postgres@unit4:Up | repo 2026-10-02 · a0.theofficialblacksheepco.online, anatomy.theoffi |
| gitlab | blackshepherddeveloper/welcome-hub-deploy | 2026-09-29 | unit4 | welcome-hub@unit4:Up | repo 2026-09-29 · welcome.theofficialblacksheepco.com |
| gitlab | gbonds1/live-logger | 2026-09-30 | unit4,unit9 | fluent-bit@unit9:Up; live-logger-api@unit4:Up; live-logger-c | repo 2026-09-30 · logs.prime-quality.online |
| gitlab | gbonds1/lokey | 2026-09-30 | unit4 | lokey@unit4:Up | repo 2026-09-30 · -locator-vpn.prime-quality.online, locator-nw.prim |
| gitlab | gbonds1/pro-pieces | 2026-10-02 | unit4 | pro-pieces@unit4:Up | repo 2026-10-02 · pro-pieces.prime-quality.online, www.theofficialbl |
| github | mellyshepdev/blackshepherddeveloper-project | 2026-09-14 | unit4 | main-website@unit4:Up; website-backend@unit4:Up | repo 2026-09-14 · api.theofficialblacksheepco.com, auth.theofficialb |
| github | mellyshepdev/locator | 2026-10-01 | unit4 | locator@unit4:Up | repo 2026-10-01 · -ipa.theofficialblacksheepco.online, a0.theofficia |
| github | mellyshepdev/searchsearcher | 2026-09-30 | unit4 | searchsearcher-app@unit4:Exited; searchsearcher-oauth@unit4: | repo 2026-09-30 · auth.theofficialblacksheepco.com, scanner.theoffic |
| github | mellyshepdev/ser.ops | 2026-09-30 | unit4 | ser-ops@unit4:Up | repo 2026-09-30 · locator.prime-quality.online, locator.theofficialb |

## Deploy source (no live container matched)

| host | repo | last push | deploys to | live containers | drift |
|------|------|-----------|------------|-----------------|-------|
| gitlab | blackshepherddeveloper-group/inventory-api | 2026-09-16 | - | - | repo 2026-09-16 / no live match · catalog.theofficialblacksheepco.com, display.theof |
| gitlab | blackshepherddeveloper-group/matomo | 2026-09-30 | - | - | repo 2026-09-30 / no live match · matomo.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper-group/searxng-deploy | 2026-09-16 | - | - | repo 2026-09-16 / no live match |
| gitlab | blackshepherddeveloper-group/services-page | 2026-07-04 | - | - | repo 2026-07-04 / no live match · services.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper-group/vane-deploy | 2026-09-16 | - | - | repo 2026-09-16 / no live match |
| gitlab | blackshepherddeveloper/anatomy-dashboard | 2026-07-03 | - | - | repo 2026-07-03 / no live match · anatomy.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper/avatars | 2026-09-30 | - | - | repo 2026-09-30 / no live match · auth.theofficialblacksheepco.com, avatars.prime-qu |
| gitlab | blackshepherddeveloper/barcode_scanner | 2026-10-01 | - | - | repo 2026-10-01 / no live match · .scanner.theofficialblacksheepco.com, scanner-api. |
| gitlab | blackshepherddeveloper/blsh-term | 2026-09-30 | - | - | repo 2026-09-30 / no live match · -terminal.theofficialblacksheepco.online, auth.the |
| gitlab | blackshepherddeveloper/bsco-inventory | 2026-09-30 | - | - | repo 2026-09-30 / no live match · OG.theofficialblacksheepco.com, www.theofficialbla |
| gitlab | blackshepherddeveloper/chat-stack | 2026-09-30 | - | - | repo 2026-09-30 / no live match · chatwoot.theofficialblacksheepco.online, mail.theo |
| gitlab | blackshepherddeveloper/db-directory | 2026-09-22 | - | - | repo 2026-09-22 / no live match |
| gitlab | blackshepherddeveloper/ebay-mail-poller | 2026-09-29 | - | - | repo 2026-09-29 / no live match |
| gitlab | blackshepherddeveloper/firefly | 2026-09-30 | - | - | repo 2026-09-30 / no live match |
| gitlab | blackshepherddeveloper/forge-relay | 2026-09-28 | - | - | repo 2026-09-28 / no live match · forge.prime-quality.online |
| gitlab | blackshepherddeveloper/freeipa | 2026-08-28 | - | - | repo 2026-08-28 / no live match · ipa.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper/lokey-native | 2026-08-23 | - | - | repo 2026-08-23 / no live match · -locator.prime-quality.online, locator-vpn.prime-q |
| gitlab | blackshepherddeveloper/matrix-relay | 2026-09-30 | - | - | repo 2026-09-30 / no live match · chatwoot.theofficialblacksheepco.online, matrix.th |
| gitlab | blackshepherddeveloper/nasa-project | 2026-09-30 | - | - | repo 2026-09-30 / no live match · nasa.theofficialblacksheepco.online |
| gitlab | blackshepherddeveloper/ollama | 2026-08-21 | - | - | repo 2026-08-21 / no live match |
| gitlab | blackshepherddeveloper/puffbase | 2026-09-30 | - | - | repo 2026-09-30 / no live match · puff.dashboard.prime-quality.online, puffbase.prim |
| gitlab | blackshepherddeveloper/sheldon-site | 2026-10-01 | - | - | repo 2026-10-01 / no live match · auth.theofficialblacksheepco.com, avatars.prime-qu |
| gitlab | blackshepherddeveloper/sheldon-the-sheep | 2026-09-30 | - | - | repo 2026-09-30 / no live match · sheldonthesheep.theofficialblacksheepco.online |
| gitlab | blackshepherddeveloper/teken404 | 2026-09-22 | - | - | repo 2026-09-22 / no live match |
| gitlab | blackshepherddeveloper/the-beast | 2026-05-11 | - | - | repo 2026-05-11 / no live match · a0.theofficialblacksheepco.com, a1.theofficialblac |
| gitlab | blackshepherddeveloper/unit2-samba | 2026-09-29 | - | - | repo 2026-09-29 / no live match |
| gitlab | gbonds1/authenticator | 2026-09-27 | - | - | repo 2026-09-27 / no live match · auth.theofficialblacksheepco.com, face.prime-quali |
| gitlab | gbonds1/card-creator | 2026-10-01 | - | - | repo 2026-10-01 / no live match · forge.prime-quality.online, forge.theofficialblack |
| gitlab | gbonds1/mailserver | 2026-09-30 | - | - | repo 2026-09-30 / no live match · mail.theofficialblacksheepco.com |
| gitlab | gbonds1/reech | 2026-09-30 | - | - | repo 2026-09-30 / no live match · auth.theofficialblacksheepco.com, matrix.theoffici |
| github | mellyshepdev/Art_of_Forgery | 2026-09-05 | - | - | repo 2026-09-05 / no live match · forge.prime-quality.online, forge.theofficialblack |
| github | mellyshepdev/Puffbase | 2026-09-30 | - | - | repo 2026-09-30 / no live match · puff.dashboard.prime-quality.online, puffbase.prim |
| github | mellyshepdev/chunker1-app | 2026-08-05 | - | - | repo 2026-08-05 / no live match |
| github | mellyshepdev/tech-estate | 2026-09-23 | - | - | repo 2026-09-23 / no live match |

## App/other repos (no deploy signals)

| host | repo | last push | deploys to | live containers | drift |
|------|------|-----------|------------|-----------------|-------|
| gitlab | blackshepherddeveloper-group/bsco-inventory-api | 2026-10-01 | - | - | repo 2026-10-01 / no live match · auth.theofficialblacksheepco.com, catalog.theoffic |
| gitlab | blackshepherddeveloper-group/business-card | 2026-07-16 | - | - | repo 2026-07-16 / no live match |
| gitlab | blackshepherddeveloper-group/chatwoot-config | 2026-07-04 | - | - | repo 2026-07-04 / no live match |
| gitlab | blackshepherddeveloper-group/historic-hub | 2026-09-30 | - | - | repo 2026-09-30 / no live match |
| gitlab | blackshepherddeveloper-group/live-logger | 2026-06-20 | - | - | repo 2026-06-20 / no live match |
| gitlab | blackshepherddeveloper-group/ogscan-android | 2026-09-30 | - | - | repo 2026-09-30 / no live match |
| gitlab | blackshepherddeveloper-group/teken404 | 2026-06-19 | - | - | repo 2026-06-19 / no live match |
| gitlab | blackshepherddeveloper-group/work-order | 2026-07-16 | - | - | repo 2026-07-16 / no live match |
| gitlab | blackshepherddeveloper/BS_Store | 2026-09-22 | - | - | repo 2026-09-22 / no live match · auth.theofficialblacksheepco.com, avatars.prime-qu |
| gitlab | blackshepherddeveloper/ai-assessment | 2026-07-15 | - | - | repo 2026-07-15 / no live match |
| gitlab | blackshepherddeveloper/azure | 2026-08-10 | - | - | repo 2026-08-10 / no live match |
| gitlab | blackshepherddeveloper/black-sheep-wallstreet | 2026-10-01 | - | - | repo 2026-10-01 / no live match |
| gitlab | blackshepherddeveloper/bsco-agent-ops | 2026-09-30 | - | - | repo 2026-09-30 / no live match · auth.theofficialblacksheepco.com |
| gitlab | blackshepherddeveloper/cad-building-creator | 2026-07-15 | - | - | repo 2026-07-15 / no live match |
| gitlab | blackshepherddeveloper/claude-code-memory | 2026-08-09 | - | - | repo 2026-08-09 / no live match |
| gitlab | blackshepherddeveloper/client-portal | 2026-09-30 | - | - | repo 2026-09-30 / no live match · auth.theofficialblacksheepco.com, avatars.prime-qu |
| gitlab | blackshepherddeveloper/depot-theme | 2026-09-28 | - | - | repo 2026-09-28 / no live match |
| gitlab | blackshepherddeveloper/dog-tycoon | 2026-03-14 | - | - | repo 2026-03-14 / no live match |
| gitlab | blackshepherddeveloper/live-logger | 2026-08-08 | - | - | repo 2026-08-08 / no live match |
| gitlab | blackshepherddeveloper/lokey-android | 2026-09-28 | - | - | repo 2026-09-28 / no live match |
| gitlab | blackshepherddeveloper/main-website-ops | 2026-09-30 | - | - | repo 2026-09-30 / no live match |
| gitlab | blackshepherddeveloper/ops-site | 2026-09-27 | - | - | repo 2026-09-27 / no live match · auth.theofficialblacksheepco.com, calendar.theoffi |
| gitlab | blackshepherddeveloper/pdns-fly | 2026-08-01 | - | - | repo 2026-08-01 / no live match |
| gitlab | blackshepherddeveloper/refresh | 2026-09-15 | - | - | repo 2026-09-15 / no live match |
| gitlab | blackshepherddeveloper/seek-eternity | 2026-09-27 | - | - | repo 2026-09-27 / no live match |
| gitlab | blackshepherddeveloper/sheldon-characters | 2026-06-26 | - | - | repo 2026-06-26 / no live match |
| gitlab | blackshepherddeveloper/sheldons-universe-card-game | 2026-09-22 | - | - | repo 2026-09-22 / no live match |
| gitlab | blackshepherddeveloper/stepped-out-fighter | 2026-06-25 | - | - | repo 2026-06-25 / no live match |
| gitlab | blackshepherddeveloper/store | 2026-09-30 | - | - | repo 2026-09-30 / no live match |
| gitlab | blackshepherddeveloper/traefik-dynamic | 2026-09-29 | - | - | repo 2026-09-29 / no live match · api.theofficialblacksheepco.com, app.prime-quality |
| gitlab | blackshepherddeveloper/unit2-traefik-dynamic | 2026-09-27 | - | - | repo 2026-09-27 / no live match · api.theofficialblacksheepco.com, auth.theofficialb |
| gitlab | blackshepherddeveloper/unit7-scripts | 2026-09-28 | - | - | repo 2026-09-28 / no live match · locator.theofficialblacksheepco.online |
| gitlab | blackshepherddeveloper/unit7-traefik-dynamic | 2026-10-01 | - | - | repo 2026-10-01 / no live match · api-lago.prime-quality.online, api.theofficialblac |
| gitlab | blackshepherddeveloper/vana-mois | 2026-09-22 | - | - | repo 2026-09-22 / no live match |
| gitlab | blackshepherddeveloper/vaultwarden | 2026-07-19 | - | - | repo 2026-07-19 / no live match |
| gitlab | gbonds1/Secure-Cyberstructures | 2026-09-25 | - | - | repo 2026-09-25 / no live match |
| gitlab | gbonds1/anatomy | 2026-05-11 | - | - | repo 2026-05-11 / no live match |
| gitlab | gbonds1/atomic.cal | 2026-04-27 | - | - | repo 2026-04-27 / no live match |
| gitlab | gbonds1/diesel.tech | 2026-08-28 | - | - | repo 2026-08-28 / no live match |
| gitlab | gbonds1/forge-companion | 2026-09-28 | - | - | repo 2026-09-28 / no live match |
| gitlab | gbonds1/ogscan | 2026-04-15 | - | - | repo 2026-04-15 / no live match |
| gitlab | gbonds1/professional-agent | 2026-09-17 | - | - | repo 2026-09-17 / no live match |
| gitlab | gbonds1/reech-android | 2026-09-25 | - | - | repo 2026-09-25 / no live match |
| gitlab | gbonds1/the-beastwatcher | 2026-06-11 | - | - | repo 2026-06-11 / no live match |
| github | mellyshepdev/TheBEAST | 2026-02-26 | - | - | repo 2026-02-26 / no live match |
| github | mellyshepdev/authenticator | 2026-09-11 | - | - | repo 2026-09-11 / no live match |
| github | mellyshepdev/barcode_scanner- | 2026-03-25 | - | - | repo 2026-03-25 / no live match |
| github | mellyshepdev/blsh-term | 2026-09-11 | - | - | repo 2026-09-11 / no live match |
| github | mellyshepdev/card-creator | 2026-09-11 | - | - | repo 2026-09-11 / no live match |
| github | mellyshepdev/cash-tamp | 2026-03-25 | - | - | repo 2026-03-25 / no live match |
| github | mellyshepdev/diesel.tech | 2026-07-26 | - | - | repo 2026-07-26 / no live match · login.theofficialblacksheepco.com |
| github | mellyshepdev/lokey | 2026-09-11 | - | - | repo 2026-09-11 / no live match |
| github | mellyshepdev/lokey-android | 2026-07-28 | - | - | repo 2026-07-28 / no live match |
| github | mellyshepdev/nasa-project | 2026-09-11 | - | - | repo 2026-09-11 / no live match |
| github | mellyshepdev/professional-agent | 2026-09-25 | - | - | repo 2026-09-25 / no live match |
| github | mellyshepdev/reech-app | 2026-09-15 | - | - | repo 2026-09-15 / no live match |
| github | mellyshepdev/refresh | 2026-09-11 | - | - | repo 2026-09-11 / no live match |
| github | mellyshepdev/welcome | 2026-09-11 | - | - | repo 2026-09-11 / no live match |

## puffbase gitea depot mirrors (auto-maintained)

| host | repo | last push | deploys to | live containers | drift |
|------|------|-----------|------------|-----------------|-------|
| gitea-depot | puffadmin/black-sheep-wallstreet | - | - | - | - |
| gitea-depot | puffadmin/blsh-term | - | - | - | - |
| gitea-depot | puffadmin/card-creator | - | - | - | - |
| gitea-depot | puffadmin/locator | 2026-10-01 | - | - | - |
| gitea-depot | puffadmin/lokey | 2026-09-30 | - | - | - |
| gitea-depot | puffadmin/nasa-project | - | - | - | - |
| gitea-depot | puffadmin/pro-pieces | - | - | - | - |
| gitea-depot | puffadmin/professional-agent | 2026-09-25 | - | - | - |
| gitea-depot | puffadmin/puffbase | 2026-09-30 | - | - | - |
| gitea-depot | puffadmin/ser.ops | 2026-09-20 | - | - | - |
| gitea-depot | puffadmin/smoke-test | - | - | - | - |
| gitea-depot | puffadmin/tech-estate | - | - | - | - |
