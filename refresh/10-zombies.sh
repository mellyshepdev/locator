# Phase 1 — reap zombie processes.
# Summarised per PARENT, not per zombie: lokey's own hard-stats.py has leaked
# hundreds of git children before (143 on unit4, 336 on unit8), and a line
# each drowned every other diagnostic in the run log. One SIGCHLD per parent.
if [[ "$OS_TYPE" == "linux" || "$OS_TYPE" == "macos" ]]; then
    ZOMBIES=$(ps -eo pid,ppid,stat,comm 2>/dev/null | awk '$3 ~ /^Z/ {print $1, $2, $4}' || true)
    if [[ -n "$ZOMBIES" ]]; then
        log "Zombie processes detected ($(printf '%s\n' "$ZOMBIES" | wc -l | tr -d ' '))"
        printf '%s\n' "$ZOMBIES" | awk '{print $2, $3}' | sort | uniq -c | sort -rn | head -10 \
            | while read -r count ppid comm; do
                  echo "    $count zombie $comm -> parent PID $ppid ($(ps -o comm= -p "$ppid" 2>/dev/null || echo unknown))"
              done
        printf '%s\n' "$ZOMBIES" | awk '{print $2}' | sort -u | while read -r ppid; do
            [[ -n "$ppid" ]] && kill -SIGCHLD "$ppid" 2>/dev/null || true
        done
        sleep 2
        LEFT=$(ps -eo stat 2>/dev/null | grep -c '^Z' || true)
        echo "    zombies remaining after SIGCHLD: $LEFT"
    else
        log "No zombie processes"
    fi
else
    skip "zombie reaping on $OS_TYPE"
fi
