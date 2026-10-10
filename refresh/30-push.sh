# Phase 3 — push every repo that is ahead of its upstream. Never forced: a
# repo that is also behind is reported as diverged and left for a human.
n_pushed=0
while read -r dir; do
    [[ -z "$dir" ]] && continue
    repo_busy "$dir" && continue
    git -C "$dir" rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1 || { skip "$dir — no upstream branch"; continue; }
    retry_cmd git -C "$dir" fetch -q origin 2>/dev/null || { warn "fetch failed for $dir"; continue; }
    counts=$(git -C "$dir" rev-list --left-right --count '@{u}...HEAD' 2>/dev/null) || continue
    behind=${counts%%[[:space:]]*}; ahead=${counts##*[[:space:]]}
    [[ "$ahead" -eq 0 ]] && continue
    if [[ "$behind" -gt 0 ]]; then
        warn "$dir has diverged ($ahead local / $behind upstream) — not pushing, needs manual reconciliation"
        continue
    fi
    if out=$(git -C "$dir" push -q origin HEAD 2>&1); then
        n_pushed=$((n_pushed + 1)); echo "    pushed $ahead commit(s) from $dir"
    else
        warn "push failed for $dir: $(echo "$out" | tr '\n' ' ' | cut -c1-300)"
    fi
done < <(find_repos)
log "push: $n_pushed repo(s) pushed"
