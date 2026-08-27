# VYPER Local Console 1.0.0-rc1

Ubuntu/Debian x86_64 prototype package.

```bash
sha256sum -c checksums.txt
sudo ./install.sh
sudo vyper enroll
vyper open
```

The application-menu launcher and `vyper open` start an unprivileged Tauri
window containing the existing local dashboard. The agent API and compatibility
web console remain bound to loopback. The unprivileged agent delegates tightly
scoped storage operations to the separate root executor. The GUI has no command
bridge or direct device access.

Package integrity is protected by SHA-256 only. Package signing is a future
production requirement.

On supported GRUB2 hosts, `sudo vyper system-disk prepare --dry-run` prepares
the no-USB, one-shot system-disk boot workflow. It does not erase data from the
running OS. Read `/opt/vyper/docs/SYSTEM_DISK_SANITIZATION.md`,
`BOOT_RECOVERY.md`, and `SECURE_BOOT.md` before non-dry-run use.
