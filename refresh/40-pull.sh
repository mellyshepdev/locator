# Phase 4 — fast-forward every repo to upstream. Runs only after every unit
# has pushed, so each unit pulls the whole fleet's commits from this sweep.
n_pulled=0
while read -r dir; do
    [[ -z "$dir" ]] && continue
    repo_busy "$dir" && continue
    git -C "$dir" rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1 || continue
    retry_cmd git -C "$dir" fetch -q origin 2>/dev/null || { warn "fetch failed for $dir"; continue; }
    counts=$(git -C "$dir" rev-list --left-right --count '@{u}...HEAD' 2>/dev/null) || continue
    behind=${counts%%[[:space:]]*}; ahead=${counts##*[[:space:]]}
    [[ "$behind" -eq 0 ]] && continue
    if [[ "$ahead" -gt 0 ]]; then
        warn "$dir has diverged ($ahead local / $behind upstream) — refusing a non-fast-forward pull"
        continue
    fi
    if out=$(git -C "$dir" merge -q --ff-only '@{u}' 2>&1); then
        n_pulled=$((n_pulled + 1)); echo "    pulled $behind commit(s) into $dir"
    else
        warn "pull failed for $dir: $(echo "$out" | tr '\n' ' ' | cut -c1-300)"
    fi
done < <(find_repos)
log "pull: $n_pulled repo(s) updated"
