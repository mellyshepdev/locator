# Phase 2 — commit every dirty repo. Nothing is pushed here: every unit
# commits first, so the push phase sees the whole fleet's work at once.
STAMP="$(date '+%Y-%m-%d %H:%M')"
n_repos=0; n_committed=0
while read -r dir; do
    [[ -z "$dir" ]] && continue
    n_repos=$((n_repos + 1))
    if repo_busy "$dir"; then skip "$dir — merge/rebase in progress or detached HEAD"; continue; fi
    [[ -z "$(git -C "$dir" status --porcelain 2>/dev/null)" ]] && continue
    git -C "$dir" add -A 2>/dev/null
    if out=$(git -C "$dir" -c user.name="${GIT_AUTHOR_NAME:-refresh}" -c user.email="${GIT_AUTHOR_EMAIL:-refresh@__UNIT__}" \
             commit -q -m "auto(refresh): __UNIT__ $STAMP" --no-verify 2>&1); then
        n_committed=$((n_committed + 1))
        echo "    committed $dir ($(git -C "$dir" log -1 --format=%h))"
    else
        warn "commit failed in $dir: $(echo "$out" | tr '\n' ' ' | cut -c1-200)"
    fi
done < <(find_repos)
log "commit: $n_committed of $n_repos repo(s) had changes"
