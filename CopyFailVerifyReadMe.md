# copyfail-verify

Apply, verify, and continuously enforce the CVE-2026-31431 (Copyfail)
blacklist for `algif_aead` and `authencesn` on Ubuntu desktop.

This is the verification companion to `copyfail-fix.sh`. Where `copyfail-fix.sh`
upgrades the kernel and writes the blacklist as part of a one-shot remediation,
this script focuses on **proving the mitigation actually holds** — by trying
to bypass it the way a determined operator would — and on **keeping it in
place over time** via an optional daily cron.

## Background

CVE-2026-31431 is a flaw in the kernel AF_ALG AEAD path. The mitigation —
pending a kernel upgrade — is to block the two modules that expose the
vulnerable code path: `algif_aead` (the AF_ALG socket family for AEAD ciphers)
and `authencesn` (the AEAD template chained through it in the published
exploit). The blacklist file uses two layers:

```
blacklist algif_aead
blacklist authencesn
install algif_aead /bin/false
install authencesn /bin/false
```

`blacklist` stops automatic loading. `install … /bin/false` makes any explicit
`modprobe` call invoke `/bin/false` instead of loading the module — `/bin/false`
always exits non-zero, so the load fails.

## Requirements

- Ubuntu (tested against 22.04 and 24.04 desktop)
- Bash 4+
- Root (run with `sudo`)
- A working cron daemon if you use `--install-cron`

## Quick start

```bash
chmod +x copyfail-verify.sh
sudo ./copyfail-verify.sh
```

That applies the blacklist, then runs all four verification phases. Exits 0
on full pass, 1 if any check fails.

If you've already applied the blacklist via `copyfail-fix.sh`:

```bash
sudo ./copyfail-verify.sh --no-apply
```

To install daily enforcement so the blacklist is automatically restored if
anyone deletes or modifies it:

```bash
sudo ./copyfail-verify.sh --install-cron
```

## Flags

| Flag | Behaviour |
|---|---|
| (none) | Apply blacklist, run all verification phases. |
| `--no-apply` | Skip phase 1. Useful for read-only audit. |
| `--install-cron` | Install to `/usr/local/sbin/`, register daily cron at `/etc/cron.d/copyfail-verify`. Then continues with a normal run. |
| `--uninstall-cron` | Remove the cron entry. Leaves the installed script and log in place. |
| `-h`, `--help` | Print usage and exit. |

## What the script checks

### Phase 1 — apply mitigation

Writes `/etc/modprobe.d/cve-2026-31431.conf` with the four directives above,
sets ownership to `root:root` mode `0644`, and tries to `rmmod` each target
module if it's currently loaded. **initramfs is intentionally not rebuilt** —
neither module is loaded during early boot, so the rebuild adds nothing for
this CVE. If you need it for other reasons, run `update-initramfs -u` separately.

### Phase 2 — verify blacklist file

Confirms the file exists, is owned by `root:root`, isn't world-writable, and
contains both `blacklist` and `install … /bin/false` lines for each module.
Then runs `modprobe --showconfig` to confirm the kernel's userspace tooling
actually agrees the modules are blacklisted — this catches the case where a
higher-precedence drop-in in `/run/modprobe.d/` or `/lib/modprobe.d/` is
overriding your file.

### Phase 3 — active load attempts

For each target module, tries three load paths:

1. `modprobe <module>` — should fail because of `install → /bin/false`.
2. `modprobe -f <module>` — same; the `install` directive still wins.
3. Direct `insmod` of the on-disk `.ko` — handles `.ko.zst` and `.ko.xz` by
   decompressing to a tempfile first.

Then asserts the module is not currently loaded.

### Phase 4 — sudoers audit

Scans `/etc/sudoers` and every file under `/etc/sudoers.d/` for rules that
would let a non-root user reverse the mitigation. Patterns flagged, in order
of severity:

- `ALL=(ALL) NOPASSWD: ALL` — full root, trivially reverses any mitigation
- `insmod` / `modprobe` / `rmmod` allowed via sudo
- Write access to `/etc/modprobe.d`
- Shell binaries (`bash`, `sh`) allowed via sudo
- Shell-escapable utilities (`vim`, `less`, `more`, `man`, `find`, `awk`,
  `sed`, `nano`, `emacs`, `nvim`) granted with `NOPASSWD`
- File-modification utilities (`cp`, `mv`, `rm`, `tee`, `dd`) granted with
  `NOPASSWD` — any of these can rewrite the blacklist file

Phase 4b additionally checks the permissions of `/etc/modprobe.d` itself, flags
any non-root-owned files inside it, and reports anything in `/run/modprobe.d/`
(which has higher precedence than `/etc/modprobe.d`).

## Cron enforcement

`--install-cron` copies the script to `/usr/local/sbin/copyfail-verify.sh`,
creates `/var/log/copyfail-verify.log` with `root:root 0600`, and writes
`/etc/cron.d/copyfail-verify`:

```
23 3 * * * root /usr/bin/flock -n /var/lock/copyfail-verify.lock /usr/local/sbin/copyfail-verify.sh >> /var/log/copyfail-verify.log 2>&1
```

Some design notes:

The cron runs in default (apply) mode, not `--no-apply`. If anyone deletes or
edits the blacklist file, the next run rewrites it from canonical content.
Verify-only would catch tampering but wouldn't fix it.

`flock -n` prevents overlapping runs if a previous invocation hangs.

`/etc/cron.d/` is used rather than `/etc/cron.daily/` because `cron.d` files
are atomic single-file drops that are easy to ship via configuration management
and remove cleanly. `cron.daily` is run via `anacron` on desktops, which may
never fire if the machine sleeps overnight.

The log is `0600` so the sudoers listings (which could be useful intel for a
local attacker) aren't world-readable.

## Files created

| Path | Purpose | Created by |
|---|---|---|
| `/etc/modprobe.d/cve-2026-31431.conf` | The blacklist itself | Phase 1 |
| `/usr/local/sbin/copyfail-verify.sh` | Stable copy for cron | `--install-cron` |
| `/etc/cron.d/copyfail-verify` | Daily enforcement schedule | `--install-cron` |
| `/var/log/copyfail-verify.log` | Cron run output | `--install-cron` |
| `/var/lock/copyfail-verify.lock` | flock lockfile | First cron run |

## Exit codes

- `0` — all checks passed (warnings allowed)
- `1` — at least one phase 2/3/4 check failed
- `2` — argument or preflight error (not running as root, etc.)

## Caveats

**`insmod` cannot be blocked by `/etc/modprobe.d/`.** The kernel itself doesn't
read `/etc/modprobe.d/` — only the `modprobe` userspace tool does. If a root
user runs `insmod` directly on a `.ko` file, that bypasses the blacklist
entirely and Phase 3 will report a failure. This is **expected on a stock
Ubuntu desktop** and not a bug in the blacklist. The three real defences
against root reloading the module:

1. Enable Secure Boot with kernel lockdown: `lockdown=integrity` on the kernel
   command line. With lockdown active, `insmod` of an unsigned or non-locally-
   trusted module is rejected by the kernel.
2. Delete the `.ko` files: `find /lib/modules -name 'algif_aead.ko*' -delete`
   (will be reinstated by the next `linux-modules-*` package upgrade).
3. **Upgrade to a patched kernel.** This is the only actual fix; everything
   else is a stopgap.

**The sudoers audit is heuristic.** It flags patterns that are *commonly*
exploitable, but it can't catch every possible bypass — for example, a custom
script run via `NOPASSWD` whose internals shell out to `bash`. Treat the
output as a starting point for review, not a definitive verdict.

**Userland AEAD callers will break.** Any program that uses `AF_ALG` AEAD —
typically OpenSSL with the `afalg` engine explicitly enabled, or specialised
hardware-crypto offload software — will see crypto failures while the
blacklist is in place. dm-crypt/LUKS, kTLS, IPsec, default OpenSSL, GnuTLS,
NSS, and SSH do **not** use this path.

## Troubleshooting

**"`/etc/modprobe.d` has weak perms" on Phase 4b.** Some custom hardening
profiles set the directory mode to `0700`. The script's check is for
world-writable bits specifically; tighter-than-default modes are fine. If
you see this on a stock Ubuntu install, something has changed the directory
permissions — investigate.

**Cron runs but nothing in the log.** Check that the cron daemon is actually
running: `systemctl status cron`. On minimal Ubuntu containers the `cron`
package isn't installed by default. Install it with `sudo apt install cron`
and enable: `sudo systemctl enable --now cron`.

**`modprobe --showconfig` doesn't agree with the on-disk file.** Something in
`/run/modprobe.d/` or `/lib/modprobe.d/` is overriding `/etc/modprobe.d/`.
Phase 4b lists `/run/modprobe.d/` contents; check `/lib/modprobe.d/` manually
with `ls -la /lib/modprobe.d/`. The precedence order is `/lib/modprobe.d/` <
`/etc/modprobe.d/` < `/run/modprobe.d/`, with later files winning.

**Phase 3 reports `insmod` succeeded.** See the caveats section. Expected
behaviour on a stock Ubuntu desktop without Secure Boot lockdown.

## Removing the mitigation

After upgrading to a patched kernel and confirming you've been running it for
several boots, you can remove the blacklist:

```bash
sudo ./copyfail-verify.sh --uninstall-cron   # if cron was installed
sudo rm /etc/modprobe.d/cve-2026-31431.conf
sudo rm /usr/local/sbin/copyfail-verify.sh   # optional
sudo rm /var/log/copyfail-verify.log         # optional
```

Reboot is not strictly required — but the modules won't be loadable until
you reboot or run `modprobe algif_aead` manually anyway, so there's no rush.
