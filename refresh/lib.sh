# Shared preamble for every fleet-refresh phase.
#
# Locator owns the refresh now: it sends lib.sh + one phase script to each
# unit's lokey as a single exec, so no unit keeps a copy of refresh on disk.
# Each phase runs on EVERY unit before the next phase starts anywhere — all
# commits land fleet-wide, then all pushes, then all pulls — so a pull on one
# unit never races a push that another unit has not made yet.
#
# Not `set -e`: one repo failing must not abort the phase for every repo after
# it. Failures are reported with warn() and the phase keeps going.
set -uo pipefail

log()  { echo "==> $*"; }
skip() { echo "    (skipped: $*)"; }
warn() { echo "    warning: $*" >&2; WARNINGS=$((WARNINGS + 1)); }
WARNINGS=0

case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux*)               OS_TYPE="linux" ;;
    Darwin*)              OS_TYPE="macos" ;;
    CYGWIN*|MINGW*|MSYS*) OS_TYPE="windows" ;;
    *)                    OS_TYPE="unknown" ;;
esac
# Native lokey on macOS runs with launchd's bare PATH; brew/docker live here.
PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:$HOME/.local/bin"

# Handshake: locator substitutes a per-command nonce. A phase result without
# this line is treated as "lokey did not really run our script", whatever the
# exit code says.
echo "ACK __NONCE__ unit=__UNIT__ user=$(id -un) home=$HOME os=$OS_TYPE"

retry_cmd() {
    local n=1 delay=1
    while [[ $n -le 3 ]]; do
        "$@" && return 0
        n=$((n + 1)); [[ $n -le 3 ]] && sleep "$delay" && delay=$((delay * 2))
    done
    return 1
}

docker_running() {
    command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"
}

# Every git checkout with an origin under the usual project roots. Discovery
# instead of a hardcoded list: the old list silently missed every repo nobody
# remembered to add (client-portal among them). Opt a repo out with
# `touch <repo>/.git/norefresh` (inside .git, so marking it does not itself
# dirty the working tree) or a committed `.norefresh` file.
find_repos() {
    local root
    for root in "$HOME/projects" "$HOME/home-server/projects" "$HOME/Software" \
                "$HOME/business" "$HOME/scripts" "$HOME/lokey" "$HOME/server"; do
        [[ -d "$root" ]] || continue
        find "$root" -maxdepth 4 \( -name node_modules -o -name .cache \) -prune \
             -o -name .git -type d -print -prune 2>/dev/null
    done | sed 's#/\.git$##' | sort -u | while read -r d; do
        [[ -f "$d/.norefresh" || -f "$d/.git/norefresh" ]] && continue
        git -C "$d" remote get-url origin >/dev/null 2>&1 || continue
        echo "$d"
    done
}

# A repo mid-merge/rebase or on a detached HEAD belongs to whoever is working
# in it; committing over that would bury their state.
repo_busy() {
    local g; g=$(git -C "$1" rev-parse --git-dir 2>/dev/null) || return 0
    [[ "$g" != /* ]] && g="$1/$g"
    [[ -e "$g/MERGE_HEAD" || -d "$g/rebase-merge" || -d "$g/rebase-apply" || -e "$g/CHERRY_PICK_HEAD" ]] && return 0
    git -C "$1" symbolic-ref -q HEAD >/dev/null || return 0
    return 1
}
