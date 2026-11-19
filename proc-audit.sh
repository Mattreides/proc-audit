#!/usr/bin/env bash
#
# proc-audit.sh — flag running processes whose executable isn't legitimately
# accounted for, and for each finding dump its network sockets.
#
# Distinguishes three cases so a routine `pacman -Syu` doesn't cry wolf:
#
#   RED   — genuinely suspicious: an unowned binary in an unexpected location,
#           OR a DELETED binary whose real path is NOT back on disk as a
#           package-owned file (the classic drop-execute-unlink in-memory
#           implant pattern). THIS is your investigate-now shortlist.
#
#   STALE — running on a (deleted) binary, BUT the same path exists again on
#           disk and is owned by an installed package. Benign: the process
#           predates a package update (pacman unlinks the old binary and writes
#           a new one; already-running processes keep the old in-memory copy,
#           so /proc/<pid>/exe reads "... (deleted)"). Fix = log out / reboot.
#           An optional pacman -Qkk checksum note is shown but NEVER changes the
#           STALE verdict — checksum output is too format-variable to gate on.
#
#   INFO  — unowned by pacman but in a legitimately-unpackaged location
#           (snap, flatpak, /opt, ~/.cargo, AppImage, ...).
#
# Design note: an earlier version folded `pacman -Qkk` into the
# STALE-vs-RED decision. -Qkk emits warnings for packages lacking stored
# checksums (the common case), which was misread as "tampered", cascading
# every benign post-update orphan into RED. Classification now depends only on
# file existence + package ownership, which is robust.
#
# Run with sudo so it can read every /proc/<pid>/exe and every socket.

set -uo pipefail

usage() {
    cat <<EOF
Usage: ${0##*/} [--checksums]

Read-only audit of running processes on Arch-based systems. Flags executables
that no installed package owns, or that were deleted while running, and shows
each finding's network sockets.

  --checksums   also run an advisory 'pacman -Qkk' integrity check on the
                package that owns each STALE binary (slower; never changes
                a verdict)
  -h, --help    show this help and exit

Run with sudo to see every process and socket.
EOF
}

DO_QKK=0
[[ $# -le 1 ]] || { usage >&2; exit 2; }
case "${1:-}" in
    "")          ;;
    --checksums) DO_QKK=1 ;;   # opt-in, advisory only
    -h|--help)   usage; exit 0 ;;
    *)           usage >&2; exit 2 ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "NOTE: not root — you'll only see your own processes/sockets. Re-run: sudo $0" >&2
    echo >&2
fi

command -v pacman >/dev/null 2>&1 || { echo "pacman not found — targets Arch/Manjaro." >&2; exit 1; }
command -v cmp    >/dev/null 2>&1 || { echo "cmp not found — install diffutils." >&2; exit 1; }
have_ss=0; command -v ss >/dev/null 2>&1 && have_ss=1

# Process names, command lines and paths are chosen by whoever started the
# process. Replace control characters before printing so a hostile name
# can't inject terminal escape sequences into this report.
printable() { printf '%s' "$1" | LC_ALL=C tr '[:cntrl:]' '?'; }

is_expected_path() {
    case "$1" in
        /snap/*|/var/lib/snapd/*) return 0 ;;
        /var/lib/flatpak/*|*/.local/share/flatpak/*) return 0 ;;
        /opt/*) return 0 ;;
        *.AppImage|*/appimage*/*) return 0 ;;
        /home/*/.cargo/*|/home/*/.rustup/*) return 0 ;;
        /home/*/.local/bin/*) return 0 ;;
        /home/*/.nvm/*|/home/*/.npm-global/*) return 0 ;;
        /home/*/.local/share/uv/python/*|/root/.local/share/uv/python/*) return 0 ;;
        /home/*/.pyenv/versions/*) return 0 ;;
        *) return 1 ;;
    esac
}

# --- Foreign mount namespaces (snap/flatpak/containers) ---
# /proc/<pid>/exe is resolved inside the process's own mount ns, so a snap's
# /usr/bin/dash is the base snap's dash, not a host file. Pacman can't own it.
HOST_MNTNS=$(readlink /proc/1/ns/mnt 2>/dev/null)
in_foreign_ns() {
    local ns; ns=$(readlink "/proc/$1/ns/mnt" 2>/dev/null) || return 1
    [[ -n "$HOST_MNTNS" && "$ns" != "$HOST_MNTNS" ]]
}
ns_kind() {
    local cg; cg=$(cat "/proc/$1/cgroup" 2>/dev/null)
    case "$cg" in
        *snap.*)                                   echo snap ;;
        *app-flatpak-*)                            echo flatpak ;;
        *docker*|*libpod*|*containerd*|*lxc*|*machine.slice*) echo container ;;
        *)                                         echo unknown ;;
    esac
}

# --- STALE gate: exists on disk AND owned by a package. That's it. ---
ondisk_and_owned() {
    local path="$1"
    [[ -e "$path" ]] || return 1
    pacman -Qo "$path" &>/dev/null
}

# --- OPTIONAL advisory checksum note. Never gates classification. ---
declare -A QKK_CACHE
qkk_note() {
    [[ $DO_QKK -eq 1 ]] || { echo ""; return; }
    local path="$1" owner out
    owner=$(pacman -Qoq "$path" 2>/dev/null) || { echo ""; return; }
    [[ -z "$owner" ]] && { echo ""; return; }
    if [[ -z "${QKK_CACHE[$owner]+set}" ]]; then
        out=$(pacman -Qkk "$owner" 2>&1)
        # Only a POSITIVE altered-file count is treated as noteworthy. Warnings
        # about missing checksum data are ignored (they're normal, not tamper).
        # Here-string, not `echo | grep -q`: under pipefail an early grep exit
        # can SIGPIPE echo and turn a match into a failure.
        if grep -qE '[1-9][0-9]* (altered|modified) files?' <<<"$out"; then
            QKK_CACHE[$owner]=" [!! pacman -Qkk reports ALTERED files in pkg '$owner' — verify]"
        else
            QKK_CACHE[$owner]=""
        fi
    fi
    echo "${QKK_CACHE[$owner]}"
}

red=0; stale=0; info=0
RED_BUF=""; STALE_BUF=""; INFO_BUF=""
append() { case "$1" in RED) RED_BUF+="$2"$'\n';; STALE) STALE_BUF+="$2"$'\n';; INFO) INFO_BUF+="$2"$'\n';; esac; }

SS_ALL=""
[[ $have_ss -eq 1 ]] && SS_ALL=$(ss -Htunap 2>/dev/null)
sockets_for_pid() {
    local pid="$1"
    [[ $have_ss -eq 1 ]] || { echo "        (install iproute2 for socket detail)"; return; }
    printf '%s\n' "$SS_ALL" | awk -v p="pid=$pid," -v p2="pid=$pid)" \
        'index($0,p)||index($0,p2){print "        " $0}'
}

echo "=== Unowned/stale executable audit — $(date -Is) ==="
echo "Scanning $(ls -d /proc/[0-9]* 2>/dev/null | wc -l) processes..."
[[ $DO_QKK -eq 1 ]] && echo "(--checksums: also running advisory pacman -Qkk per package)"
echo

while read -r pid; do
    raw=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    [[ -z "$raw" ]] && continue

    is_deleted=0; real="$raw"
    if [[ "$raw" == *" (deleted)" ]]; then is_deleted=1; real="${raw% (deleted)}"; fi

    # Fast benign path: current exe present and package-owned.
    if [[ $is_deleted -eq 0 ]] && pacman -Qo "$real" &>/dev/null; then
        continue
    fi

    comm=$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/ *$//')
    puser=$(stat -c '%U' "/proc/$pid" 2>/dev/null)

    tag=""; note=""
    if in_foreign_ns "$pid"; then
        kind=$(ns_kind "$pid")
        nsfile="/proc/$pid/root$real"
        if [[ $kind == unknown ]]; then
            tag="RED"; note=" [foreign mount ns, unrecognized sandbox — INVESTIGATE]"
        elif [[ $is_deleted -eq 1 ]]; then
            if [[ -e "$nsfile" ]]; then tag="STALE"; note=" [$kind: deleted, path back on disk in its ns — restart to clear]"
            else tag="RED"; note=" [$kind: DELETED, nothing at path in its ns — INVESTIGATE]"; fi
        elif cmp -s "/proc/$pid/exe" "$nsfile"; then
            tag="INFO"; note=" [$kind ns; matches on-disk file in its ns]"
        else
            tag="RED"; note=" [$kind ns; in-memory exe does NOT match $nsfile — INVESTIGATE]"
        fi
    elif [[ $is_deleted -eq 1 ]]; then
        if ondisk_and_owned "$real"; then
            tag="STALE"; note=" [deleted, but clean package file back on disk — restart to clear]$(qkk_note "$real")"
        else
            tag="RED"; note=" [DELETED and no package-owned file at this path — INVESTIGATE]"
        fi
    else
        if is_expected_path "$real"; then tag="INFO"
        else tag="RED"; note=" [unowned binary in unexpected location]"; fi
    fi

    case "$tag" in RED) ((red++));; STALE) ((stale++));; INFO) ((info++));; esac

    block="[$tag] pid=$pid user=$puser comm=$(printable "$comm")"$'\n'
    block+="        exe:     $(printable "$real$note")"$'\n'
    block+="        cmdline: $(printable "${cmdline:-<none>}")"$'\n'
    socks=$(sockets_for_pid "$pid")
    [[ -n "$socks" ]] && block+="        sockets:"$'\n'"$socks"$'\n' || block+="        sockets: none"$'\n'
    append "$tag" "$block"
done < <(ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | sort -n)

[[ -n "$RED_BUF"   ]] && { echo "########## RED — investigate ##########"; echo "$RED_BUF"; }
[[ -n "$STALE_BUF" ]] && { echo "########## STALE — benign, restart to clear ##########"; echo "$STALE_BUF"; }
[[ -n "$INFO_BUF"  ]] && { echo "########## INFO — legitimately unpackaged ##########"; echo "$INFO_BUF"; }

echo "=== Summary ==="
echo "RED   (investigate now):            $red"
echo "STALE (benign — restart to clear):  $stale"
echo "INFO  (unpackaged but expected):    $info"
echo
if [[ $red -eq 0 ]]; then
    echo "==> No RED findings. Nothing suspicious."
    [[ $stale -gt 0 ]] && echo "    The $stale STALE entries are pre-update binaries; log out / reboot to clear."
    [[ $DO_QKK -eq 0 ]] && echo "    For an extra integrity pass: sudo $0 --checksums"
else
    echo "Run down each RED with:"
    echo "    ls -l /proc/<pid>/exe ; sudo lsof -p <pid>"
    echo "Recover the in-memory image of a deleted binary (private temp dir, not a fixed /tmp name):"
    echo "    d=\$(mktemp -d) && sudo cp /proc/<pid>/exe \"\$d/pid<pid>.bin\" && echo \"\$d\""
fi
exit 0   # a completed audit succeeds; don't leak the last [[ ]] test's status
