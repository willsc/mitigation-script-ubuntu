#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# copyfail-verify.sh
#
# Apply (idempotently) and VERIFY the CVE-2026-31431 mitigation on an
# Ubuntu desktop, then actively try to bypass it. Audits sudoers for rules
# that would let a non-root user reverse the mitigation.
#
# Modules covered: algif_aead, authencesn
#
# Phases:
#   1. Apply mitigation     — write /etc/modprobe.d/cve-2026-31431.conf,
#                             try to unload if currently loaded.
#   2. Verify blacklist     — confirm the file is on disk, owned by root,
#                             not world-writable, and contains both
#                             `blacklist` and `install … /bin/false` lines.
#   3. Active load tests    — try `modprobe`, `modprobe -f`, `insmod` on
#                             the on-disk .ko. Each should FAIL.
#   4. Sudoers audit        — scan /etc/sudoers and /etc/sudoers.d/* for
#                             any rule that would let a non-root user:
#                               - run modprobe / insmod / rmmod
#                               - edit /etc/modprobe.d/*
#                               - run a shell or editor as root with NOPASSWD
#                             Also flags ALL=(ALL) NOPASSWD: ALL.
#   5. Summary              — pass/fail per check, exit 1 if any FAIL.
#
# Run as root (or via sudo). Read-only by default except phase 1. Use
# --no-apply to skip phase 1 if you've already applied the blacklist.
# initramfs is intentionally left untouched; rebuild it separately if
# you want the blacklist baked into early boot.
#
# Recurring enforcement:
#   --install-cron   Copies this script to /usr/local/sbin and registers
#                    a daily cron entry in /etc/cron.d/copyfail-verify
#                    that re-applies and verifies the mitigation. Output
#                    is appended to /var/log/copyfail-verify.log.
#   --uninstall-cron Removes the cron entry (leaves the script and log
#                    in place for audit).
# ─────────────────────────────────────────────────────────────────────────────

set -u
set -o pipefail

# ─── styling ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'
    B=$'\033[0;34m'; BO=$'\033[1m';   RS=$'\033[0m'
else
    R=''; G=''; Y=''; B=''; BO=''; RS=''
fi

info()  { printf "%s→%s %s\n"  "$B"  "$RS" "$*"; }
good()  { printf "%s✓%s %s\n"  "$G"  "$RS" "$*"; }
warn()  { printf "%s⚠%s %s\n"  "$Y"  "$RS" "$*"; }
fail()  { printf "%s✗%s %s\n"  "$R"  "$RS" "$*"; }
hdr()   { printf "\n%s%s═══ %s ═══%s\n" "$BO" "$B" "$*" "$RS"; }

# ─── flags ───────────────────────────────────────────────────────────────────
APPLY=1
INSTALL_CRON=0
UNINSTALL_CRON=0
TARGET_MODULES=(algif_aead authencesn)
BLACKLIST_FILE=/etc/modprobe.d/cve-2026-31431.conf
CRON_FILE=/etc/cron.d/copyfail-verify
INSTALL_PATH=/usr/local/sbin/copyfail-verify.sh
LOG_FILE=/var/log/copyfail-verify.log

usage() {
    cat <<EOF
Usage: $0 [--no-apply] [--install-cron] [--uninstall-cron] [-h|--help]

  --no-apply         Skip phase 1 (assume mitigation already applied).
  --install-cron     Copy this script to $INSTALL_PATH and register a
                     daily cron job at $CRON_FILE that re-applies and
                     verifies the mitigation. Logs to $LOG_FILE.
  --uninstall-cron   Remove the cron job (keeps script + log).
  -h, --help         This message.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-apply)        APPLY=0; shift ;;
        --install-cron)    INSTALL_CRON=1; shift ;;
        --uninstall-cron)  UNINSTALL_CRON=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) printf "Unknown arg: %s\n" "$1"; usage; exit 2 ;;
    esac
done

if [[ $INSTALL_CRON -eq 1 && $UNINSTALL_CRON -eq 1 ]]; then
    printf "Cannot use --install-cron and --uninstall-cron together.\n"
    exit 2
fi

# ─── preflight ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "Must run as root (sudo $0)"
    exit 2
fi

if ! command -v modprobe >/dev/null 2>&1; then
    fail "modprobe not found — is this even Linux?"
    exit 2
fi

# trackers
declare -i FAIL_COUNT=0
declare -i WARN_COUNT=0
record_fail() { FAIL_COUNT+=1; fail "$*"; }
record_warn() { WARN_COUNT+=1; warn "$*"; }

KREL="$(uname -r)"

# ─── cron install / uninstall ────────────────────────────────────────────────
install_cron() {
    hdr "Installing cron enforcement"

    # Copy script to a stable system path (resolve current path first)
    local src
    src=$(readlink -f "$0")
    if [[ "$src" != "$INSTALL_PATH" ]]; then
        info "Copying $src → $INSTALL_PATH"
        install -o root -g root -m 0755 "$src" "$INSTALL_PATH"
        good "Installed at $INSTALL_PATH"
    else
        good "Already at $INSTALL_PATH"
    fi

    # Make sure the log file exists with sane perms (root-only)
    touch "$LOG_FILE"
    chown root:root "$LOG_FILE"
    chmod 0600      "$LOG_FILE"
    good "Log file: $LOG_FILE (root:root 0600)"

    # Write the cron entry. flock prevents overlapping runs; the small
    # minute offset (23:03) avoids the top-of-hour herd.
    info "Writing $CRON_FILE"
    cat > "$CRON_FILE" <<EOF
# /etc/cron.d/copyfail-verify
# Daily enforcement of the CVE-2026-31431 (Copyfail) blacklist.
# Re-applies the blacklist and verifies it; exit code logged.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

23 3 * * * root /usr/bin/flock -n /var/lock/copyfail-verify.lock $INSTALL_PATH >> $LOG_FILE 2>&1
EOF
    chown root:root "$CRON_FILE"
    chmod 0644      "$CRON_FILE"
    good "Wrote $CRON_FILE (runs daily at 03:23)"

    # cron picks up /etc/cron.d/* automatically; nudge if the daemon is
    # systemd-cron or similar that watches the file.
    if systemctl is-active --quiet cron 2>/dev/null; then
        good "cron daemon is running"
    elif systemctl is-active --quiet cronie 2>/dev/null; then
        good "cronie daemon is running"
    else
        record_warn "No active cron daemon detected — install 'cron' (apt install cron)"
    fi
}

uninstall_cron() {
    hdr "Removing cron enforcement"
    if [[ -f "$CRON_FILE" ]]; then
        rm -f "$CRON_FILE"
        good "Removed $CRON_FILE"
    else
        info "No $CRON_FILE present — nothing to remove"
    fi
    info "Leaving $INSTALL_PATH and $LOG_FILE in place for audit"
    info "(remove manually with: rm $INSTALL_PATH $LOG_FILE)"
}

# Handle uninstall-and-exit before doing any phases
if [[ $UNINSTALL_CRON -eq 1 ]]; then
    uninstall_cron
    exit 0
fi

# Install cron now if requested; we then fall through to a normal run so the
# operator gets immediate verification on top of the scheduled enforcement.
if [[ $INSTALL_CRON -eq 1 ]]; then
    install_cron
fi

# ─── phase 1: apply mitigation ───────────────────────────────────────────────
if [[ $APPLY -eq 1 ]]; then
    hdr "Phase 1 — apply mitigation"

    info "Writing $BLACKLIST_FILE"
    cat > "$BLACKLIST_FILE" <<'EOF'
# CVE-2026-31431 (Copyfail) — block AF_ALG AEAD path
# Two-layer block: `blacklist` stops auto-load, `install … /bin/false`
# stops explicit modprobe.
blacklist algif_aead
blacklist authencesn
install algif_aead /bin/false
install authencesn /bin/false
EOF
    chown root:root "$BLACKLIST_FILE"
    chmod 0644      "$BLACKLIST_FILE"
    good "Wrote and locked permissions on $BLACKLIST_FILE"
    info "Skipping initramfs rebuild (out of scope)"

    # Try to unload now (best-effort; will fail if in use)
    for m in "${TARGET_MODULES[@]}"; do
        if lsmod | awk '{print $1}' | grep -qx "$m"; then
            info "Module $m is loaded — trying rmmod"
            if rmmod "$m" 2>/dev/null; then
                good "Unloaded $m"
            else
                record_warn "$m is in use; reboot required to fully evict it"
            fi
        fi
    done
else
    hdr "Phase 1 — skipped (--no-apply)"
fi

# ─── phase 2: verify blacklist file ──────────────────────────────────────────
hdr "Phase 2 — verify blacklist file"

if [[ ! -f $BLACKLIST_FILE ]]; then
    record_fail "Missing: $BLACKLIST_FILE"
else
    good "Present: $BLACKLIST_FILE"

    # ownership
    owner=$(stat -c '%U:%G' "$BLACKLIST_FILE")
    if [[ "$owner" == "root:root" ]]; then
        good "Owned by root:root"
    else
        record_fail "Wrong owner ($owner) on $BLACKLIST_FILE"
    fi

    # mode — must not be world-writable
    mode=$(stat -c '%a' "$BLACKLIST_FILE")
    if [[ "$mode" =~ [2367]$ ]]; then
        record_fail "World-writable mode $mode on $BLACKLIST_FILE"
    else
        good "Mode $mode (not world-writable)"
    fi

    # content — must contain both blacklist + install lines for each module
    for m in "${TARGET_MODULES[@]}"; do
        if grep -qE "^[[:space:]]*blacklist[[:space:]]+$m\b" "$BLACKLIST_FILE"; then
            good "blacklist line present for $m"
        else
            record_fail "blacklist line missing for $m"
        fi
        if grep -qE "^[[:space:]]*install[[:space:]]+${m}[[:space:]]+/bin/false\b" "$BLACKLIST_FILE"; then
            good "install … /bin/false line present for $m"
        else
            record_fail "install … /bin/false line missing for $m"
        fi
    done
fi

# Also check that modprobe agrees the module is blacklisted
for m in "${TARGET_MODULES[@]}"; do
    # `modprobe --showconfig` reflects merged config from all of /etc/modprobe.d
    # and /lib/modprobe.d. If anything overrides our file, this is where we
    # see it.
    config=$(modprobe --showconfig 2>/dev/null || true)
    if echo "$config" | grep -qE "^[[:space:]]*blacklist[[:space:]]+$m\b"; then
        good "modprobe sees $m as blacklisted"
    else
        record_fail "modprobe does NOT see $m as blacklisted (override somewhere?)"
    fi
    if echo "$config" | grep -qE "^[[:space:]]*install[[:space:]]+${m}[[:space:]]+/bin/false\b"; then
        good "modprobe sees install→/bin/false for $m"
    else
        record_warn "modprobe does not show install→/bin/false for $m"
    fi
done

# ─── phase 3: active load attempts ───────────────────────────────────────────
hdr "Phase 3 — try to load the modules anyway"

# helper: report whether module is currently loaded
is_loaded() {
    lsmod | awk '{print $1}' | grep -qx "$1"
}

for m in "${TARGET_MODULES[@]}"; do
    info "── target: $m"

    # 3a. plain modprobe — should fail because of install→/bin/false
    if modprobe "$m" 2>/dev/null; then
        record_fail "modprobe $m SUCCEEDED — mitigation broken"
    else
        good "modprobe $m blocked"
    fi

    # 3b. modprobe -f (force) — `install` directive still wins, this should
    # also fail. A success here is a kernel-level surprise worth flagging.
    if modprobe -f "$m" 2>/dev/null; then
        record_fail "modprobe -f $m SUCCEEDED — mitigation broken"
    else
        good "modprobe -f $m blocked"
    fi

    # 3c. direct insmod of the on-disk .ko — this BYPASSES modprobe entirely
    # and is the real test of whether the blacklist holds against a
    # determined attacker with root.
    ko_path=$(find "/lib/modules/$KREL" -name "${m}.ko*" -print -quit 2>/dev/null || true)
    if [[ -z "$ko_path" ]]; then
        good "$m has no on-disk .ko under /lib/modules/$KREL — insmod path is closed"
    else
        info "found $ko_path — attempting direct insmod"
        # Decompress if needed (insmod doesn't always handle .zst/.xz)
        tmp_ko=""
        case "$ko_path" in
            *.ko)     load_path="$ko_path" ;;
            *.ko.zst) tmp_ko=$(mktemp --suffix=.ko); zstd -d -q -o "$tmp_ko" "$ko_path" 2>/dev/null && load_path="$tmp_ko" || load_path="" ;;
            *.ko.xz)  tmp_ko=$(mktemp --suffix=.ko); xz -d -c "$ko_path" > "$tmp_ko" 2>/dev/null && load_path="$tmp_ko" || load_path="" ;;
            *)        load_path="$ko_path" ;;
        esac

        if [[ -n "$load_path" ]] && insmod "$load_path" 2>/dev/null; then
            record_fail "insmod $ko_path SUCCEEDED — blacklist does NOT cover insmod"
            # try to undo damage
            rmmod "$m" 2>/dev/null && info "(unloaded $m again)"
        else
            good "insmod of $m blocked or unloadable"
        fi
        [[ -n "$tmp_ko" && -f "$tmp_ko" ]] && rm -f "$tmp_ko"
    fi

    # 3d. final state check — module had better not be loaded right now
    if is_loaded "$m"; then
        record_fail "$m is currently LOADED in the running kernel"
    else
        good "$m is NOT loaded"
    fi
done

# Note on insmod: the kernel itself does NOT honor /etc/modprobe.d/ when you
# call insmod directly on a .ko file. The only way insmod fails here is if
# (a) the .ko is absent (e.g. uninstalled by linux-modules upgrade), or
# (b) the kernel is locked down (Secure Boot + lockdown=integrity), or
# (c) module signature enforcement rejects it.
# If insmod succeeded above, that's expected on a stock Ubuntu desktop and
# the mitigation against root is "remove the .ko file" or "enable lockdown".
if [[ $FAIL_COUNT -gt 0 ]]; then
    cat <<EOF

  ${Y}Note:${RS} If insmod succeeded, that's expected on a stock Ubuntu desktop
  without Secure Boot lockdown. /etc/modprobe.d/* only constrains modprobe,
  not direct insmod by root. Defences against root reloading the module:
    1. Enable Secure Boot + kernel lockdown (integrity mode).
    2. Delete the .ko files: find /lib/modules -name 'algif_aead.ko*' -delete
       (will be reinstated by next linux-modules upgrade).
    3. Upgrade to a patched kernel — the real fix.
EOF
fi

# ─── phase 4: sudoers audit ──────────────────────────────────────────────────
hdr "Phase 4 — sudoers audit (can a user reverse this?)"

# Collect all sudoers files. Use visudo -c style logic but just read them.
SUDOERS_FILES=(/etc/sudoers)
if [[ -d /etc/sudoers.d ]]; then
    while IFS= read -r -d '' f; do
        # skip backups & README
        case "$(basename "$f")" in
            *~|*.bak|*.dpkg-*|*.swp|README) continue ;;
        esac
        SUDOERS_FILES+=("$f")
    done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)
fi

info "Scanning ${#SUDOERS_FILES[@]} sudoers file(s):"
for f in "${SUDOERS_FILES[@]}"; do
    printf "    - %s\n" "$f"
done
echo

# Patterns that would let a non-root user reverse the mitigation, ordered by
# danger. Each entry: regex|description.
declare -a RISKY_PATTERNS=(
    '\bALL[[:space:]]*=[[:space:]]*\(.*\)[[:space:]]*NOPASSWD:[[:space:]]*ALL\b|NOPASSWD:ALL grants full root — trivially reverses any mitigation'
    '\b/sbin/insmod\b|/usr/sbin/insmod\b|\binsmod\b|insmod allowed — can load .ko bypassing modprobe'
    '\b/sbin/modprobe\b|/usr/sbin/modprobe\b|\bmodprobe\b|modprobe allowed — could override blacklist with -f or by removing the file first'
    '\b/sbin/rmmod\b|/usr/sbin/rmmod\b|\brmmod\b|rmmod allowed — can unload modules'
    '/etc/modprobe\.d|Write access to /etc/modprobe.d — can delete or override the blacklist'
    '\b/bin/(ba)?sh\b|\b/usr/bin/(ba)?sh\b|Shell allowed via sudo — full root'
    '\b(vi|vim|nvim|nano|emacs|less|more|man|awk|find|sed)\b.*NOPASSWD|Editor/pager via NOPASSWD — shell-escape to root'
    '\b/bin/(cp|mv|rm|tee|dd)\b.*NOPASSWD|/usr/bin/(cp|mv|rm|tee|dd)\b.*NOPASSWD|Privileged file ops via NOPASSWD — can rewrite /etc/modprobe.d'
)

scan_sudoers_file() {
    local f="$1"
    [[ -r "$f" ]] || { record_warn "Cannot read $f"; return; }

    # Strip comments and blank lines for pattern matching, but keep line
    # numbers via grep -n on the raw file.
    local hits=0
    for entry in "${RISKY_PATTERNS[@]}"; do
        local pat="${entry%|*}"
        local desc="${entry##*|}"
        # Only match non-comment lines (don't start with #)
        local matches
        matches=$(grep -nE "$pat" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' || true)
        if [[ -n "$matches" ]]; then
            record_warn "$f: $desc"
            while IFS= read -r line; do
                printf "        %s\n" "$line"
            done <<< "$matches"
            hits+=1
        fi
    done

    [[ $hits -eq 0 ]] && good "$f: clean"
}

for f in "${SUDOERS_FILES[@]}"; do
    scan_sudoers_file "$f"
done

# Bonus check: is /etc/modprobe.d itself writable by a non-root user, or
# are any files in it owned by non-root? An attacker who can write here can
# drop a higher-precedence rule that overrides ours.
hdr "Phase 4b — /etc/modprobe.d directory permissions"
dir_mode=$(stat -c '%a' /etc/modprobe.d)
dir_owner=$(stat -c '%U:%G' /etc/modprobe.d)
if [[ "$dir_owner" == "root:root" ]] && [[ ! "$dir_mode" =~ [2367]$ ]]; then
    good "/etc/modprobe.d is $dir_owner mode $dir_mode"
else
    record_fail "/etc/modprobe.d has weak perms: $dir_owner mode $dir_mode"
fi

# Any non-root-owned files inside?
weird=$(find /etc/modprobe.d -maxdepth 1 -type f ! -user root -o ! -group root 2>/dev/null | head -20)
if [[ -n "$weird" ]]; then
    record_fail "Non-root-owned files in /etc/modprobe.d:"
    while IFS= read -r line; do printf "        %s\n" "$line"; done <<< "$weird"
else
    good "All files in /etc/modprobe.d are root-owned"
fi

# Same check for /run/modprobe.d (higher precedence than /etc/modprobe.d)
if [[ -d /run/modprobe.d ]]; then
    info "/run/modprobe.d exists — files there OVERRIDE /etc/modprobe.d"
    ls -la /run/modprobe.d/ 2>/dev/null | sed 's/^/        /'
    # Anything in there for our modules?
    for m in "${TARGET_MODULES[@]}"; do
        if grep -rE "$m" /run/modprobe.d/ 2>/dev/null | grep -v blacklist >/dev/null; then
            record_fail "/run/modprobe.d contains a non-blacklist rule for $m — could override mitigation"
        fi
    done
fi

# ─── summary ─────────────────────────────────────────────────────────────────
hdr "Summary"
if [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -eq 0 ]]; then
    good "All checks passed. Mitigation is in place and not trivially reversible."
    exit 0
elif [[ $FAIL_COUNT -eq 0 ]]; then
    warn "$WARN_COUNT warning(s). Review above — mitigation holds but there are caveats."
    exit 0
else
    fail "$FAIL_COUNT failure(s), $WARN_COUNT warning(s). Mitigation has gaps — see above."
    exit 1
fi
