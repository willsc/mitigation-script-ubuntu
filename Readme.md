# copyfail-fix.sh

A bash script that fully patches an Ubuntu host against **CVE-2026-31431** ("Copy Fail"), a Linux kernel local privilege escalation vulnerability in the `algif_aead` crypto module that allows any unprivileged local user to gain root.

The script prioritises the actual fix (kernel upgrade) over mitigations, but applies both belt-and-braces.

## Background

CVE-2026-31431, disclosed on 29 April 2026, is a logic bug in the kernel's `authencesn` AEAD template that lets an unprivileged user trigger a controlled 4-byte write into the page cache of any readable file. By corrupting the in-memory copy of a setuid binary like `su`, the attacker escalates to root. The bug exists in every Linux kernel from 4.14 (2017) to the patched releases (mainline 6.18.22 / 6.19.12 / 7.0).

On Ubuntu, the fix is:

1. **Kernel upgrade** to a patched version (the actual fix), and
2. **Mitigation** by blocking the `algif_aead` module from loading (defence-in-depth, applies without reboot).

This script handles both, plus the supporting work — DKMS module rebuilds, initramfs refresh, and verification.

## Requirements

- Ubuntu (any version; releases ≥26.04 are not affected and the script exits clean on those)
- `sudo` / root for the apply mode (`--check` works as a regular user)
- Network access to the Ubuntu archive (for `apt-get update`, `apt-get install`, and changelog fetches)

## Usage

```bash
chmod +x copyfail-fix.sh

# Read-only status check — safe to run any time
sudo ./copyfail-fix.sh --check

# Apply the full fix
sudo ./copyfail-fix.sh

# Help
./copyfail-fix.sh --help
```

A typical workflow on a desktop or server:

```bash
sudo ./copyfail-fix.sh --check    # see what's missing
sudo ./copyfail-fix.sh            # apply the fix
sudo reboot                       # if the script tells you to
sudo ./copyfail-fix.sh --check    # confirm patched after reboot
```

## What it does (in priority order)

1. **Inventory** every installed Linux kernel meta-package (`linux-image-generic`, `linux-image-generic-hwe-22.04`, `linux-image-oem-22.04`, `linux-image-aws`, etc.).
2. **`apt-get update`** to refresh the package cache.
3. **Upgrade** every detected kernel meta plus its installed siblings: `linux-${suffix}`, `linux-headers-${suffix}`, `linux-modules-${suffix}`, `linux-modules-extra-${suffix}`, `linux-tools-${suffix}`, `linux-cloud-tools-${suffix}`. This is the actual fix.
4. **Rebuild DKMS** third-party modules (ZFS, VirtualBox, NVIDIA, etc.) against the newly installed kernel ABI, surfacing any rebuild failures before reboot.
5. **Upgrade `kmod`** to pick up Canonical's `/etc/modprobe.d/disable-algif_aead.conf` mitigation drop-in.
6. **Write `/etc/modprobe.d/cve-2026-31431.conf`** — an explicit blacklist of `algif_aead` and `authencesn`, independent of Canonical's package, with `install … /bin/false` rules that actually block loading (not just `blacklist`, which can be overridden).
7. **Refresh initramfs** so the blacklist applies on next boot.
8. **Unload** `algif_aead` and `authencesn` from running memory if currently loaded.
9. **Verify** by checking each installed kernel's changelog for `CVE-2026-31431` and flagging whether a reboot is required.
10. **Report Livepatch status** if Ubuntu Pro Livepatch is active.

## Coverage matrix

| Ubuntu release          | Kernel lines handled                                    |
|-------------------------|---------------------------------------------------------|
| 16.04 / 18.04 ESM       | GA + HWE (requires Ubuntu Pro for security updates)     |
| 20.04 LTS               | GA (5.4) and HWE (5.15)                                 |
| 22.04 LTS (incl. desktop) | GA (5.15) and HWE (6.8)                                |
| 24.04 LTS (incl. desktop) | GA (6.8) and any rolling HWE                           |
| 25.04 / 25.10 interim   | Whatever's installed                                    |
| 26.04 (Resolute)        | Not affected — script exits clean                       |

Kernel flavours auto-detected: `generic`, `generic-hwe-XX.XX`, `lowlatency`, `lowlatency-hwe-XX.XX`, `virtual`, `oem-XX.XX*`, `aws`, `azure`, `gcp`, `kvm`, `raspi`. The detection works by inventory rather than hard-coding, so any flavour following Ubuntu's `linux-image-*` naming convention is picked up.

## Files the script writes

| Path                                          | Purpose                                          |
|-----------------------------------------------|--------------------------------------------------|
| `/etc/modprobe.d/cve-2026-31431.conf`         | Explicit blacklist of `algif_aead` + `authencesn` |
| (Canonical package may write `/etc/modprobe.d/disable-algif_aead.conf` separately when `kmod` is upgraded.) |   |

The script does **not** modify GRUB, kernel command line arguments, or systemd units.

## After running: how to verify

```bash
# Confirm the running kernel is the patched one
uname -r

# Confirm the changelog of the running kernel references the CVE
apt changelog "linux-image-$(uname -r)" | grep -i CVE-2026-31431

# Confirm the blacklist is in place
ls -l /etc/modprobe.d/cve-2026-31431.conf
ls -l /etc/modprobe.d/disable-algif_aead.conf 2>/dev/null   # may not exist on older kmod

# Confirm the modules are not loaded
lsmod | grep -E '^(algif_aead|authencesn) '   # should be empty

# Confirm no leftover algif sockets
sudo lsof | grep AF_ALG                       # should be empty
```

A clean output on all of the above means you're patched.

## Removing the blacklist (after a confirmed patched kernel)

The `cve-2026-31431.conf` blacklist is safe to leave in place indefinitely — it only blocks an obscure crypto interface that almost no application uses. But if you want to remove it after several boots on a confirmed patched kernel:

```bash
sudo rm /etc/modprobe.d/cve-2026-31431.conf
sudo update-initramfs -u
sudo reboot
```

Canonical's `/etc/modprobe.d/disable-algif_aead.conf` will be removed by a future `kmod` package update once Canonical decides to rescind the mitigation; do not delete it manually.

## Troubleshooting

**The script says no kernel meta-package was detected.** You may be running a manually pinned versioned kernel, a snap-based kernel (Ubuntu Core), or a custom kernel. The script will still try to upgrade any pending `linux-*` packages and apply the blacklist, but the kernel upgrade portion may be a no-op. Run `apt list --installed 'linux-image-*'` and check whether you have a meta or only versioned packages.

**DKMS rebuild errors for NVIDIA.** Check `/var/lib/dkms/nvidia/<version>/build/make.log`. The most common cause is an old `nvidia-dkms-XXX` package that doesn't support the new kernel. Fix with `sudo apt install nvidia-dkms-XXX` for a newer driver. **Do not reboot** into the new kernel until DKMS is clean, or you may lose your graphical session — boot the previous kernel from GRUB's advanced menu if you do.

**The host is in WSL.** The script will warn and skip the kernel upgrade — your kernel is provided by Windows, not Ubuntu. Update via `wsl --update` from PowerShell on the Windows host. The blacklist file is still written, which is harmless.

**The host is in a container.** Kernel changes happen on the host, not the container. The script warns and continues; only the blacklist file is meaningful inside a container, and even that's overridden by the host kernel's actual module loading rules.

**`apt-get changelog` is slow or fails.** The changelog endpoint requires network. On air-gapped hosts the script can't verify CVE references but will still apply the upgrade and blacklist. The verification step will show "no CVE-2026-31431 ref" — check the kernel version against [Ubuntu's CVE tracker](https://ubuntu.com/security/CVE-2026-31431) manually.

**`rmmod` fails.** The module is in use by a running process. The script logs this and continues — a reboot will clear it, and the blacklist prevents reload.

**`update-initramfs` fails.** Usually disk space (`/boot` full) or a broken initramfs hook. The script logs and continues. Fix with `sudo apt autoremove --purge` to clear old kernels, then re-run.

## Caveats

- The script relies on Ubuntu's archive for patched kernels. If your release is past EOL and not on Ubuntu Pro/ESM, you will not receive kernel updates — only the blacklist mitigation will apply.
- Ubuntu Pro Livepatch may patch the running kernel in memory without changing the on-disk image. The script reports Livepatch status when available; if Livepatch is active, the changelog check on the on-disk kernel may still say "no CVE ref" but the host is patched in memory.
- The blacklist may break applications that explicitly use `AF_ALG` for AEAD ciphers — typically only OpenSSL with the `afalg` engine enabled, or hardware crypto offload via `AF_ALG`. Standard dm-crypt/LUKS, kTLS, IPsec, OpenSSL (default), GnuTLS, NSS, and SSH are unaffected.
- The script does not touch firmware (`linux-firmware`). If you want firmware updates too, run `sudo apt full-upgrade` separately.
- The script is idempotent: re-running it on an already-patched host is safe and reports clean status.

## License

Public domain / no warranty. Review the script before running it on production hosts.
