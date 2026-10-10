# Phase 6 — OS packages.
case "$OS_TYPE" in
    linux)
        if command -v apt-get &>/dev/null && sudo -n true 2>/dev/null; then
            log "Updating system packages (apt)"
            retry_cmd sudo -n apt-get update -q >/dev/null && \
                sudo -n env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q >/dev/null || warn "apt upgrade failed"
        else
            skip "apt upgrade (no passwordless sudo or non-apt system)"
        fi ;;
    macos)
        if command -v brew &>/dev/null; then
            log "Updating Homebrew packages"
            retry_cmd brew update >/dev/null && brew upgrade >/dev/null || warn "brew upgrade failed"
        else
            skip "brew not installed"
        fi ;;
    windows)
        command -v winget &>/dev/null && { log "winget upgrade"; winget upgrade --all --include-unknown || warn "winget upgrade failed"; } ;;
esac
