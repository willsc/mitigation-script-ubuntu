#!/usr/bin/env bash
#
# copyfail-fix.sh
#
# Fully patches an Ubuntu host against CVE-2026-31431 ("Copy Fail").
#
# This script is exhaustive — it does not assume a particular Ubuntu release
# or kernel flavour. It detects every installed kernel meta-package on the
# host (generic, generic-hwe-XX.XX, lowlatency, lowlatency-hwe-*, virtual,
# oem-*, aws, azure, gcp, kvm, raspi, etc.) and upgrades them all.
#
# Priority order — full fix first, mitigation second:
#   1. Inventory every installed Linux kernel meta-package on the host.
#   2. apt-get update.
#   3. Upgrade EVERY kernel meta-package + image/headers/modules/
#      modules-extra/tools/cloud-tools siblings to the latest patched
#      version. This is the actual fix.
#   4. Rebuild any DKMS-managed third-party kernel modules (ZFS,
#      VirtualBox, NVIDIA, etc.) against the new kernel so the host is
#      fully bootable on the patched ABI.
#   5. Upgrade `kmod` as defence-in-depth (Canonical's mitigation rule).
#   6. Write our own /etc/modprobe.d/cve-2026-31431.conf blacklisting
#      both algif_aead and authencesn — independent of Canonical's package.
#   7. Try to unload algif_aead from memory if currently loaded.
#   8. Verify each installed kernel image's changelog references the CVE,
#      and flag whether a reboot is required.
#   9. Report Ubuntu Pro Livepatch status if available.
#
# Usage:
#   sudo ./copyfail-fix.sh              # apply the full fix
#   sudo ./copyfail-fix.sh --check      # report only, no changes
#        ./copyfail-fix.sh --help

set -euo pipefail

CVE="CVE-2026-31431"
CHECK_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=1 ;;
        -h|--help)
            awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
            exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

# ---------- output helpers ----------
if [[ -t 1 ]]; then
    B=$'\033[1;34m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; R=$'\033[1;31m'; X=$'\033[0m'
else
    B=""; G=""; Y=""; R=""; X=""
fi
info() { printf '%s[*]%s %s\n' "$B" "$X" "$*"; }
good() { printf '%s[+]%s %s\n' "$G" "$X" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$X" "$*"; }
fail() { printf '%s[-]%s %s\n' "$R" "$X" "$*" >&2; }
hr()   { printf '%s%s%s\n' "$B" "----------------------------------------------------------------" "$X"; }

# ---------- pre-flight ----------
if [[ $EUID -ne 0 && $CHECK_ONLY -eq 0 ]]; then
    fail "Must run as root unless using --check. Try: sudo $0"
    exit 1
fi

if [[ ! -r /etc/os-release ]] || ! grep -q '^ID=ubuntu' /etc/os-release; then
    fail "This script is for Ubuntu only."
    exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
hr
info "Host: Ubuntu ${VERSION_ID} (${VERSION_CODENAME:-?}) — ${PRETTY_NAME}"

# Ubuntu 26.04 (Resolute) and later are not affected.
MAJOR="${VERSION_ID%%.*}"
if [[ "${MAJOR}" =~ ^[0-9]+$ ]] && (( MAJOR >= 26 )); then
    good "Ubuntu ${VERSION_ID} ships kernels not affected by ${CVE}. Nothing to do."
    exit 0
fi

# WSL: kernel comes from Windows, not Ubuntu.
if grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; then
    warn "This appears to be WSL. The Linux kernel is provided by Windows."
    warn "Update via 'wsl --update' on the Windows host. Continuing anyway —"
    warn "the kmod mitigation will still be installed if the package is available."
fi

# Container: kernel changes must happen on host.
if [[ -f /.dockerenv ]] || grep -qaE '(docker|containerd|kubepods|/lxc/)' /proc/1/cgroup 2>/dev/null; then
    warn "This looks like a container. Kernel upgrades only take effect on the HOST."
    warn "Run this script on the host instead. Continuing for kmod mitigation only."
fi

RUNNING_KERNEL="$(uname -r)"
info "Running kernel: ${RUNNING_KERNEL}"

# Is algif_aead built into the kernel (=y) or a module (=m)?
ALGIF_BUILTIN=0
KCONFIG="/boot/config-${RUNNING_KERNEL}"
if [[ -r "$KCONFIG" ]]; then
    if grep -q '^CONFIG_CRYPTO_USER_API_AEAD=y' "$KCONFIG" 2>/dev/null; then
        ALGIF_BUILTIN=1
        warn "algif_aead is BUILT INTO the running kernel (=y)."
        warn "kmod blacklist will NOT block it — only a kernel upgrade fixes this host."
    fi
fi

# ---------- detect installed kernel meta-packages ----------
# Meta-packages have names like:
#   linux-image-generic, linux-image-generic-hwe-22.04, linux-image-oem-22.04,
#   linux-image-lowlatency, linux-image-lowlatency-hwe-22.04, linux-image-virtual,
#   linux-image-aws, linux-image-azure, linux-image-gcp, linux-image-kvm, etc.
# Versioned image packages (the actual kernels) start with linux-image-N.N…
detect_image_metas() {
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\n' 'linux-image-*' 2>/dev/null \
        | awk -F'\t' '$1 ~ /^ii/ {print $2}' \
        | sed 's/:.*//' \
        | grep -v -E '^linux-image-[0-9]' \
        | sort -u
}

mapfile -t IMAGE_METAS < <(detect_image_metas)

# Build the full upgrade list: each image meta + its sibling linux-FOO,
# linux-headers-FOO, linux-modules-FOO, linux-modules-extra-FOO,
# linux-tools-FOO, linux-cloud-tools-FOO.
KERNEL_PKGS=()
for img in "${IMAGE_METAS[@]+"${IMAGE_METAS[@]}"}"; do
    KERNEL_PKGS+=("$img")
    suffix="${img#linux-image-}"
    for prefix in "linux" "linux-headers" "linux-modules" "linux-modules-extra" "linux-tools" "linux-cloud-tools"; do
        sibling="${prefix}-${suffix}"
        if dpkg-query -W -f='${db:Status-Abbrev}' "$sibling" 2>/dev/null | grep -q '^ii'; then
            KERNEL_PKGS+=("$sibling")
        fi
    done
done

echo
if [[ ${#IMAGE_METAS[@]} -eq 0 ]]; then
    warn "No installed kernel meta-packages detected."
    warn "Possible causes: pinned versioned kernel, snap-based kernel, container."
    warn "Falling back to apt list --upgradable filter at upgrade time."
else
    info "Installed kernel meta-packages on this host:"
    for p in "${IMAGE_METAS[@]}"; do echo "    - $p"; done
fi

# ---------- helper: changelog check ----------
# Ubuntu security update changelogs name the CVE explicitly. We grep for it.
# This requires network access; first calls take a few seconds.
check_changelog() {
    local pkg="$1"
    apt-get changelog "$pkg" 2>/dev/null | grep -q "$CVE"
}

# ---------- apt update ----------
echo
if [[ $CHECK_ONLY -eq 0 ]]; then
    info "Refreshing apt cache..."
    apt-get update -qq 2>/dev/null || warn "apt-get update non-zero; continuing with cached data"
fi

# ---------- inventory installed kernel IMAGES (versioned) and patch state ----------
echo
info "Installed kernel images and patch state:"
mapfile -t INSTALLED_IMAGES < <(
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' 'linux-image-*' 2>/dev/null \
        | awk -F'\t' '$1 ~ /^ii/ && $2 ~ /^linux-image-[0-9]/ {print $2"\t"$3}'
)

UNPATCHED=()
for line in "${INSTALLED_IMAGES[@]+"${INSTALLED_IMAGES[@]}"}"; do
    pkg="${line%%$'\t'*}"
    ver="${line##*$'\t'}"
    printf '  %-46s %-30s ' "$pkg" "$ver"
    if check_changelog "$pkg"; then
        printf '%s[patched]%s\n' "$G" "$X"
    else
        printf '%s[no %s ref]%s\n' "$Y" "$CVE" "$X"
        UNPATCHED+=("$pkg")
    fi
done

# Running kernel patch state
RUNNING_PKG="linux-image-${RUNNING_KERNEL}"
echo
RUNNING_PATCHED=0
if check_changelog "$RUNNING_PKG"; then
    good "Running kernel ${RUNNING_PKG} references the ${CVE} fix."
    RUNNING_PATCHED=1
else
    warn "Running kernel ${RUNNING_PKG} does NOT reference the ${CVE} fix."
fi

# kmod / explicit blacklist file
echo
if [[ -f /etc/modprobe.d/disable-algif_aead.conf ]]; then
    good "Canonical kmod mitigation present: /etc/modprobe.d/disable-algif_aead.conf"
else
    warn "Canonical kmod mitigation file not present."
fi
if [[ -f /etc/modprobe.d/cve-2026-31431.conf ]]; then
    good "Explicit blacklist present:        /etc/modprobe.d/cve-2026-31431.conf"
else
    warn "Explicit blacklist not present (will be written by upgrade)."
fi

# Algif loaded?
if grep -qE '^algif_aead ' /proc/modules; then
    warn "algif_aead module is currently LOADED (active exposure)."
fi

# ---------- short-circuit for --check ----------
if [[ $CHECK_ONLY -eq 1 ]]; then
    echo
    hr
    if [[ ${#UNPATCHED[@]} -eq 0 && $RUNNING_PATCHED -eq 1 ]]; then
        good "Check result: host appears patched against ${CVE}."
    else
        warn "Check result: action needed."
        warn "Re-run without --check to apply the full fix."
    fi
    hr
    exit 0
fi

# ---------- apply the fix ----------
echo
hr
info "Applying full fix (kernel upgrade is the priority, kmod is defence-in-depth)"
hr

# STEP 1: kernel upgrade — the actual fix
echo
info "[1/5] Upgrading all kernel meta-packages and siblings..."
if [[ ${#KERNEL_PKGS[@]} -gt 0 ]]; then
    echo "      Targets: ${KERNEL_PKGS[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "${KERNEL_PKGS[@]}" || \
        warn "Some kernel package upgrades failed; check apt output above."
else
    warn "No detected kernel metas; falling back to upgrading any upgradable linux-* packages."
fi

# Safety net: anything else linux-* still upgradable?
mapfile -t REMAINING < <(
    apt list --upgradable 2>/dev/null \
        | awk -F/ '/^linux-/{print $1}' \
        | sort -u
)
if [[ ${#REMAINING[@]} -gt 0 ]]; then
    info "      Pulling additional pending linux-* upgrades: ${REMAINING[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "${REMAINING[@]}" || true
fi

# STEP 2: rebuild DKMS-managed third-party kernel modules against any newly
# installed kernel ABI. Apt's package hooks normally do this automatically,
# but failures during the hook can be silent. Re-running dkms autoinstall
# is idempotent and surfaces any rebuild errors.
echo
info "[2/5] Rebuilding DKMS-managed third-party kernel modules (if any)..."
if command -v dkms >/dev/null 2>&1; then
    DKMS_STATUS=$(dkms status 2>/dev/null || true)
    if [[ -z "$DKMS_STATUS" ]]; then
        good "No DKMS modules registered on this host."
    else
        echo "      Registered DKMS modules:"
        echo "$DKMS_STATUS" | sed 's/^/        /'
        # Find the newest installed kernel image and rebuild against its version.
        NEWEST_KVER=$(
            dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\n' 'linux-image-*' 2>/dev/null \
                | awk -F'\t' '$1 ~ /^ii/ && $2 ~ /^linux-image-[0-9]/ {print $2}' \
                | sed 's/^linux-image-//' \
                | sort -V \
                | tail -1
        )
        if [[ -n "$NEWEST_KVER" ]]; then
            info "      Running: dkms autoinstall --kernelver $NEWEST_KVER"
            if dkms autoinstall --kernelver "$NEWEST_KVER" 2>&1 | sed 's/^/        /'; then
                good "DKMS rebuild completed."
            else
                warn "DKMS reported errors. Check 'dkms status' and"
                warn "/var/lib/dkms/<module>/<version>/build/make.log for details."
                warn "The kernel may still boot, but third-party modules may be missing."
            fi
        fi
    fi
else
    good "DKMS not installed on this host (nothing to rebuild)."
fi

# STEP 3: kmod upgrade — Canonical's drop-in mitigation
echo
info "[3/5] Upgrading kmod (Canonical's algif_aead block)..."
DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade kmod || \
    warn "kmod upgrade non-zero; continuing"

# STEP 4: write our own explicit blacklist — defence-in-depth, independent
# of whether Canonical's kmod patch is installed. Covers both algif_aead
# and authencesn (the broken AEAD template the researcher's PoC chains).
echo
BLACKLIST_FILE="/etc/modprobe.d/cve-2026-31431.conf"
info "[4/5] Writing explicit blacklist: ${BLACKLIST_FILE}"
cat > "${BLACKLIST_FILE}" <<'EOF'
# CVE-2026-31431 ("Copy Fail") — defence-in-depth
# Block the AF_ALG AEAD interface and the authencesn template that the
# published exploit chains. Safe on stock Ubuntu — does not affect
# dm-crypt/LUKS, kTLS, IPsec, OpenSSL, GnuTLS, NSS, or SSH.
#
# Remove this file (and reboot) once a confirmed patched kernel is running.
blacklist algif_aead
blacklist authencesn
install algif_aead /bin/false
install authencesn /bin/false
EOF
chmod 0644 "${BLACKLIST_FILE}"
good "Blacklist written."

# Refresh initramfs so the blacklist applies on next boot even if either
# module is auto-loaded early. Failure here is non-fatal.
if command -v update-initramfs >/dev/null 2>&1; then
    info "      Refreshing initramfs to bake in the blacklist..."
    update-initramfs -u 2>/dev/null || warn "update-initramfs returned non-zero; continuing."
fi

# STEP 5: try to unload modules now
echo
info "[5/5] Unloading algif_aead and authencesn if currently in memory..."
for mod in algif_aead authencesn; do
    if grep -qE "^${mod} " /proc/modules; then
        if rmmod "$mod" 2>/dev/null; then
            good "$mod unloaded."
        else
            warn "rmmod $mod failed (in use). Reboot will clear it."
        fi
    else
        good "$mod is not loaded."
    fi
done

# ---------- post-fix verification ----------
echo
hr
info "Post-fix verification"
hr

# Re-inventory installed kernel images
mapfile -t INSTALLED_IMAGES_POST < <(
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' 'linux-image-*' 2>/dev/null \
        | awk -F'\t' '$1 ~ /^ii/ && $2 ~ /^linux-image-[0-9]/ {print $2"\t"$3}'
)

POST_UNPATCHED=0
for line in "${INSTALLED_IMAGES_POST[@]+"${INSTALLED_IMAGES_POST[@]}"}"; do
    pkg="${line%%$'\t'*}"
    ver="${line##*$'\t'}"
    printf '  %-46s %-30s ' "$pkg" "$ver"
    if check_changelog "$pkg"; then
        printf '%s[patched]%s\n' "$G" "$X"
    else
        printf '%s[no %s ref]%s\n' "$Y" "$CVE" "$X"
        POST_UNPATCHED=$((POST_UNPATCHED+1))
    fi
done

# Latest installed kernel
LATEST_LINE=$(
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' 'linux-image-*' 2>/dev/null \
        | awk -F'\t' '$1 ~ /^ii/ && $2 ~ /^linux-image-[0-9]/ {print $2"\t"$3}' \
        | sort -V -k2 \
        | tail -1
)

if [[ -n "$LATEST_LINE" ]]; then
    LATEST_PKG="${LATEST_LINE%%$'\t'*}"
    LATEST_VER="${LATEST_PKG#linux-image-}"
    echo
    info "Latest installed kernel: ${LATEST_PKG}"
    if check_changelog "$LATEST_PKG"; then
        good "Latest installed kernel references the ${CVE} fix."
    else
        warn "Could not confirm fix in ${LATEST_PKG}."
        warn "If the patched kernel is not yet in your archive, re-run this script later."
        warn "If on Ubuntu Pro, Livepatch may already be applying the fix in memory."
    fi

    if [[ "$LATEST_VER" != "$RUNNING_KERNEL" ]]; then
        echo
        hr
        warn "  REBOOT REQUIRED to activate the patched kernel."
        warn "  Latest installed:  ${LATEST_VER}"
        warn "  Currently running: ${RUNNING_KERNEL}"
        warn "  Run:    sudo reboot"
        hr
    else
        good "Running kernel matches the latest installed."
    fi
fi

# Blacklist files (post)
echo
if [[ -f /etc/modprobe.d/disable-algif_aead.conf ]]; then
    good "Canonical kmod mitigation in place: /etc/modprobe.d/disable-algif_aead.conf"
fi
if [[ -f /etc/modprobe.d/cve-2026-31431.conf ]]; then
    good "Explicit blacklist in place:        /etc/modprobe.d/cve-2026-31431.conf"
fi

# If algif_aead is built-in, kmod blacklist is ineffective
if [[ $ALGIF_BUILTIN -eq 1 ]]; then
    warn "Reminder: algif_aead is built-in on the running kernel."
    warn "Only the kernel upgrade + reboot will close this exposure."
fi

# Livepatch status (Ubuntu Pro)
if command -v canonical-livepatch >/dev/null 2>&1; then
    echo
    info "Ubuntu Pro Livepatch status:"
    canonical-livepatch status 2>/dev/null || true
elif command -v pro >/dev/null 2>&1; then
    echo
    info "Ubuntu Pro status:"
    pro status --format=json 2>/dev/null | grep -E '(livepatch|kernel)' || true
fi

echo
hr
good "Full fix sequence complete."
hr
