# VYPER Local Console 1.0.0-rc1

Ubuntu/Debian x86_64 prototype package.

```bash
sha256sum -c checksums.txt
sudo ./install.sh
sudo vyper enroll
vyper open
```

The agent API and web console bind to loopback. The agent runs as root because
it performs tightly scoped storage operations; the static UI runs as the
unprivileged `vyper-ui` account. No arbitrary command API is exposed.

Package integrity is protected by SHA-256 only. Package signing is a future
production requirement.

On supported GRUB2 hosts, `sudo vyper system-disk prepare --dry-run` prepares
the no-USB, one-shot system-disk boot workflow. It does not erase data from the
running OS. Read `/opt/vyper/docs/SYSTEM_DISK_SANITIZATION.md`,
`BOOT_RECOVERY.md`, and `SECURE_BOOT.md` before non-dry-run use.
