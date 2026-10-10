# Phase 7 — reclaim space. Containers and volumes are NEVER pruned, and the
# image prune has no `-a`: that would delete the images of deliberately
# stopped containers (idle-stopped, Sablier-scaled), some of them locally
# built and in no registry.
log "System cleanup"
if command -v docker &>/dev/null; then
    docker image prune -f >/dev/null 2>&1 || warn "docker image prune failed"
    docker builder prune -af >/dev/null 2>&1 || warn "docker builder prune failed"
fi
command -v npm  &>/dev/null && { npm cache clean --force >/dev/null 2>&1 || warn "npm cache clean failed"; }
command -v pip3 &>/dev/null && { pip3 cache purge >/dev/null 2>&1 || true; }
command -v go   &>/dev/null && { go clean -cache >/dev/null 2>&1 || warn "go cache clean failed"; }
if [[ -d "$HOME/Downloads" ]]; then
    find "$HOME/Downloads" -maxdepth 1 -mmin +60 \( -iname "*.part" -o -iname "*.crdownload" -o -iname "*.download" -o -iname "*.partial" \) -delete 2>/dev/null || true
fi
case "$OS_TYPE" in
    linux)
        if sudo -n true 2>/dev/null; then
            command -v apt-get &>/dev/null && sudo -n apt-get autoremove -y -q >/dev/null 2>&1 || true
            if command -v journalctl &>/dev/null; then
                sudo -n journalctl --vacuum-time=2d  >/dev/null 2>&1 || true
                sudo -n journalctl --vacuum-size=200M >/dev/null 2>&1 || true
            fi
            if command -v snap &>/dev/null; then
                OLD_SNAPS="$(snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' || true)"
                while read -r s r; do
                    [[ -z "$s" || -z "$r" ]] && continue
                    sudo -n snap remove "$s" --revision="$r" >/dev/null 2>&1 || warn "snap remove $s rev $r failed"
                done <<< "$OLD_SNAPS"
            fi
        fi
        rm -rf "$HOME"/.cache/* 2>/dev/null || true ;;
    macos)
        command -v brew &>/dev/null && brew cleanup --prune=all -s >/dev/null 2>&1 || true
        rm -rf "$HOME"/Library/Caches/* "$HOME"/Library/Logs/* 2>/dev/null || true ;;
    windows)
        rm -rf "${TEMP:-/nonexistent}"/* "${TMP:-/nonexistent}"/* 2>/dev/null || true ;;
esac
df -h "$HOME" 2>/dev/null | tail -1 | awk '{print "    disk after cleanup: " $5 " used, " $4 " free"}'
