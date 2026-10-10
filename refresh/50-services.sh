# Phase 5 — services that follow the code just pulled.
# Deliberately NOT here: restarting lokey (it is the process running this
# script) and rebuilding locator (it is the process running the sweep).
for vname in varnish wt-varnish; do
    if docker_running "$vname"; then
        log "Purging $vname cache"
        retry_cmd docker exec "$vname" varnishadm "ban req.url ~ ." >/dev/null 2>&1 || warn "$vname purge failed"
    fi
done
for HUB in "$HOME/Software/hub" "$HOME/projects/black-sheep-hub"; do
    [[ -f "$HUB/docker-compose.yml" ]] || continue
    if docker_running hub-frontend; then
        log "Rebuilding hub-frontend"
        retry_cmd docker compose -f "$HUB/docker-compose.yml" up -d --build frontend >/dev/null 2>&1 \
            || warn "hub-frontend rebuild failed"
    fi
done
log "services done"
